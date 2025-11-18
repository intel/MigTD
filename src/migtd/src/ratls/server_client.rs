// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use async_io::{AsyncRead, AsyncWrite};
use crypto::{
    ecdsa::EcdsaPk,
    hash::digest_sha384,
    tls::{SecureChannel, TlsConfig},
    x509::{
        AlgorithmIdentifier, AnyRef, BitStringRef, Certificate, CertificateBuilder, Decode, Encode,
        ExtendedKeyUsage, Extension, Extensions, Tag,
    },
    Error as CryptoError,
};

use super::*;
#[cfg(feature = "policy_v2")]
use crate::config::get_policy;
use crate::event_log::get_event_log;
use verify::*;

type Result<T> = core::result::Result<T, RatlsError>;

pub fn server<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new()?;
    let (certs, quote) = gen_cert(&signing_key)?;
    let certs = vec![certs];

    #[cfg(feature = "policy_v2")]
    let _ = &quote; // mark as intentionally unused

    // Server verifies certificate of client
    #[cfg(not(feature = "policy_v2"))]
    let config = TlsConfig::new(certs, signing_key, verify_client_cert, quote)?;
    #[cfg(feature = "policy_v2")]
    let config = TlsConfig::new(certs, signing_key, verify_client_cert, remote_policy)?;
    config.tls_server(stream).map_err(|e| e.into())
}

pub fn client<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
    #[cfg(feature = "vmcall-raw")] data: &mut Vec<u8>,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new()?;
    let (certs, quote) = gen_cert(&signing_key)?;
    let certs = vec![certs];

    #[cfg(feature = "policy_v2")]
    let _ = &quote; // mark as intentionally unused

    // Client verifies certificate of server
    #[cfg(not(feature = "policy_v2"))]
    let config = TlsConfig::new(certs, signing_key, verify_server_cert, quote)?;
    #[cfg(feature = "policy_v2")]
    let config = TlsConfig::new(certs, signing_key, verify_server_cert, remote_policy)?;
    config.tls_client(stream).map_err(|e| {
        #[cfg(feature = "vmcall-raw")]
        data.extend_from_slice(
            &format!(
                "Error: server_client client(): Failure in tls_client() error: {:?}\n",
                e
            )
            .into_bytes(),
        );
        e.into()
    })
}

fn gen_cert(signing_key: &EcdsaPk) -> Result<(Vec<u8>, Vec<u8>)> {
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(AnyRef::new(
            Tag::ObjectIdentifier,
            SECP384R1_OID.as_bytes(),
        )?),
    };
    let eku = vec![SERVER_AUTH, CLIENT_AUTH, MIGTD_EXTENDED_KEY_USAGE].to_der()?;

    let pub_key = signing_key.public_key()?;
    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };
    let key_usage = BitStringRef::from_bytes(&[0x80])?.to_der()?;
    let quote = gen_quote(&pub_key)?;
    let event_log = get_event_log().ok_or(RatlsError::InvalidEventlog)?;
    #[cfg(feature = "policy_v2")]
    let policy_hash = {
        let policy = get_policy().ok_or(RatlsError::InvalidPolicy)?;
        digest_sha384(policy)
    }?;

    let x509_builder = CertificateBuilder::new(sig_alg, algorithm, &pub_key)?
        // 1970-01-01T00:00:00Z
        .set_not_before(core::time::Duration::new(0, 0))?
        // 9999-12-31T23:59:59Z
        .set_not_after(core::time::Duration::new(253402300799, 0))?
        .add_extension(Extension::new(
            KEY_USAGE_EXTENSION,
            Some(true),
            Some(key_usage.as_slice()),
        )?)?
        .add_extension(Extension::new(
            EXTENDED_KEY_USAGE,
            Some(false),
            Some(eku.as_slice()),
        )?)?
        .add_extension(Extension::new(
            EXTNID_MIGTD_QUOTE_REPORT,
            Some(false),
            Some(quote.as_slice()),
        )?)?
        .add_extension(Extension::new(
            EXTNID_MIGTD_EVENT_LOG,
            Some(false),
            Some(event_log),
        )?)?;

    // If policy_v2 feature is enabled, add policy extension
    #[cfg(feature = "policy_v2")]
    let x509_builder = x509_builder.add_extension(Extension::new(
        EXTNID_MIGTD_POLICY_HASH,
        Some(false),
        Some(&policy_hash),
    )?)?;

    let mut x509_certificate = x509_builder.build();
    let tbs = x509_certificate.tbs_certificate.to_der()?;
    let signature = signing_key.sign(&tbs)?;
    x509_certificate.set_signature(&signature)?;

    Ok((x509_certificate.to_der().map_err(CryptoError::from)?, quote))
}

fn gen_quote(public_key: &[u8]) -> Result<Vec<u8>> {
    let hash = digest_sha384(public_key)?;

    // Generate the TD Report that contains the public key hash as nonce
    let mut additional_data = [0u8; 64];
    additional_data[..hash.len()].copy_from_slice(hash.as_ref());
    let td_report = tdx_tdcall::tdreport::tdcall_report(&additional_data)?;

    attestation::get_quote(td_report.as_bytes()).map_err(|_| RatlsError::GetQuote)
}

fn verify_server_cert(cert: &[u8], quote: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(true, cert, quote)
}

fn verify_client_cert(cert: &[u8], quote: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(false, cert, quote)
}

#[cfg(not(feature = "test_disable_ra_and_accept_all"))]
mod verify {
    use super::*;
    use crate::mig_policy;

    use alloc::string::ToString;
    use crypto::ecdsa::ecdsa_verify;
    use crypto::{Error as CryptoError, Result as CryptoResult};
    use policy::PolicyError;

    #[cfg(not(feature = "policy_v2"))]
    pub fn verify_peer_cert(
        is_client: bool,
        cert: &[u8],
        quote_local: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let verified_report_local = attestation::verify_quote(quote_local)
            .map_err(|_| CryptoError::TlsVerifyPeerCert(MUTUAL_ATTESTATION_ERROR.to_string()))?;
        let cert = Certificate::from_der(cert).map_err(|_| CryptoError::ParseCertificate)?;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(CryptoError::ParseCertificate)?;

        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions)?;
        // Parse out quote report and event log from certificate extensions
        let quote_report = find_extension(extensions, &EXTNID_MIGTD_QUOTE_REPORT)
            .ok_or(CryptoError::ParseCertificate)?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG)
            .ok_or(CryptoError::ParseCertificate)?;

        if let Ok(verified_report_peer) = attestation::verify_quote(quote_report) {
            verify_signature(&cert, verified_report_peer.as_slice())?;

            // MigTD-src acts as TLS client
            let policy_check_result = mig_policy::authenticate_policy(
                is_client,
                verified_report_local.as_slice(),
                verified_report_peer.as_slice(),
                event_log,
            );

            if let Err(e) = &policy_check_result {
                log::error!("Policy check failed, below is the detail information:\n");
                log::error!("{:x?}\n", e);
            }

            policy_check_result.map_err(|e| match e {
                PolicyError::InvalidPolicy => {
                    CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
                }
                _ => CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string()),
            })
        } else {
            Err(CryptoError::TlsVerifyPeerCert(
                MUTUAL_ATTESTATION_ERROR.to_string(),
            ))
        }
    }

    #[cfg(feature = "policy_v2")]
    pub fn verify_peer_cert(
        is_client: bool,
        cert: &[u8],
        policy: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| CryptoError::ParseCertificate)?;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(CryptoError::ParseCertificate)?;

        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions)?;
        // Parse out quote, event log and policy from certificate extensions
        let quote_report = find_extension(extensions, &EXTNID_MIGTD_QUOTE_REPORT)
            .ok_or(CryptoError::ParseCertificate)?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG)
            .ok_or(CryptoError::ParseCertificate)?;
        let expected_policy_hash = find_extension(extensions, &EXTNID_MIGTD_POLICY_HASH)
            .ok_or(CryptoError::ParseCertificate)?;

        let exact_policy_hash = digest_sha384(policy)?;
        if expected_policy_hash != exact_policy_hash.as_slice() {
            return Err(CryptoError::TlsVerifyPeerCert(
                INVALID_MIG_POLICY_ERROR.to_string(),
            ));
        }
        // MigTD-src acts as TLS client
        let policy_check_result =
            mig_policy::authenticate_remote(is_client, quote_report, policy, event_log);

        if let Err(e) = &policy_check_result {
            log::error!("Policy check failed, below is the detail information:\n");
            log::error!("{:x?}\n", e);
        }

        let suppl_data = policy_check_result.map_err(|e| match e {
            PolicyError::InvalidPolicy => {
                CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
            }
            _ => CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string()),
        })?;

        verify_signature(&cert, suppl_data.as_slice())
    }

    fn verify_signature(cert: &Certificate, verified_report: &[u8]) -> CryptoResult<()> {
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(CryptoError::ParseCertificate)?;
        let tbs = cert.tbs_certificate.to_der()?;
        let signature = cert
            .signature_value
            .as_bytes()
            .ok_or(CryptoError::ParseCertificate)?;

        verify_public_key(verified_report, public_key)?;
        ecdsa_verify(public_key, &tbs, signature)
    }

    fn verify_public_key(verified_report: &[u8], public_key: &[u8]) -> CryptoResult<()> {
        if cfg!(feature = "AzCVMEmu") {
            // In AzCVMEmu mode, REPORTDATA is constructed differently.
            // Bypass public key hash check in this development environment.
            log::warn!(
                "AzCVMEmu mode: Skipping public key verification in TD report. This is NOT secure for production use.\n"
            );
            return Ok(());
        }
        const PUBLIC_KEY_HASH_SIZE: usize = 48;

        let report_data = &verified_report[520..520 + PUBLIC_KEY_HASH_SIZE];
        let digest = digest_sha384(public_key)?;

        if report_data == digest.as_slice() {
            Ok(())
        } else {
            Err(CryptoError::TlsVerifyPeerCert(
                MISMATCH_PUBLIC_KEY.to_string(),
            ))
        }
    }
}

// Only for test to bypass the quote verification
#[cfg(feature = "test_disable_ra_and_accept_all")]
mod verify {
    use super::*;

    pub fn verify_peer_cert(
        _is_client: bool,
        cert: &[u8],
        _quote_local: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| CryptoError::ParseCertificate)?;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(CryptoError::ParseCertificate)?;
        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions)?;
        // Parse out quote report and event log from certificate extensions
        let quote_report = find_extension(extensions, &EXTNID_MIGTD_QUOTE_REPORT)
            .ok_or(CryptoError::ParseCertificate)?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG)
            .ok_or(CryptoError::ParseCertificate)?;

        // As the remote attestation is disabled, the certificate can't be verified. Aways return
        // success for test purpose.
        Ok(())
    }
}

fn check_migtd_eku(extensions: &Extensions) -> core::result::Result<(), CryptoError> {
    for extn in extensions.get() {
        if extn.extn_id == EXTENDED_KEY_USAGE {
            if let Some(extn_value) = extn.extn_value {
                let eku = ExtendedKeyUsage::from_der(extn_value.as_bytes())?;
                if eku.contains(&MIGTD_EXTENDED_KEY_USAGE) {
                    return Ok(());
                }
            }
        }
    }

    Err(CryptoError::ParseCertificate)
}

fn find_extension<'a>(extensions: &'a Extensions, id: &ObjectIdentifier) -> Option<&'a [u8]> {
    extensions.get().iter().find_map(|extn| {
        if &extn.extn_id == id {
            extn.extn_value.map(|v| v.as_bytes())
        } else {
            None
        }
    })
}
