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
use crate::{config::get_policy, event_log::get_event_log, migration::data::MigrationInformation};
use verify::*;

type Result<T> = core::result::Result<T, RatlsError>;

pub fn server<T: AsyncRead + AsyncWrite + Unpin>(stream: T) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new()?;
    let pub_key = signing_key.public_key()?;
    let quote = gen_quote(&pub_key)?;
    let certs = vec![gen_cert_server(&signing_key, &pub_key, &quote)?];

    // Server verifies certificate of client
    let config = TlsConfig::new(certs, signing_key, verify_client_cert, quote)?;
    config.tls_server(stream).map_err(|e| e.into())
}

pub fn client<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    mig_info: &MigrationInformation,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new()?;
    let pub_key = signing_key.public_key()?;
    let quote = gen_quote(&pub_key)?;
    #[cfg(not(feature = "policy_v2"))]
    let certs = vec![gen_cert_client(mig_info, &signing_key, &pub_key, &quote)?];
    #[cfg(feature = "policy_v2")]
    let certs = vec![gen_cert_client_v2(
        mig_info,
        &signing_key,
        &pub_key,
        &quote,
    )?];

    // Client verifies certificate of server
    let config = TlsConfig::new(certs, signing_key, verify_server_cert, quote)?;
    config.tls_client(stream).map_err(|e| e.into())
}

fn gen_cert_client(
    _mig_info: &MigrationInformation,
    signing_key: &EcdsaPk,
    pub_key: &[u8],
    quote: &[u8],
) -> Result<Vec<u8>> {
    build_x509_common(quote, pub_key, |builder| {
        let cert = builder.build();
        sign_certificate(cert, signing_key)
    })
}

fn gen_cert_server(signing_key: &EcdsaPk, pub_key: &[u8], quote: &[u8]) -> Result<Vec<u8>> {
    build_x509_common(quote, pub_key, |builder| {
        let cert = builder.build();
        sign_certificate(cert, signing_key)
    })
}

#[cfg(feature = "policy_v2")]
fn gen_cert_client_v2(
    mig_info: &MigrationInformation,
    signing_key: &EcdsaPk,
    pub_key: &[u8],
    quote: &[u8],
) -> Result<Vec<u8>> {
    use crate::migration::with_init_migtd_config;

    let servtd_ext: &[u8] = &[];
    with_init_migtd_config(&mig_info.mig_info, |init| {
        build_x509_common(quote, pub_key, |builder| {
            let cert = builder
                .add_extension(Extension::new(
                    EXTNID_MIGTD_SERVTD_EXT,
                    Some(false),
                    Some(servtd_ext),
                )?)?
                .add_extension(Extension::new(
                    EXTNID_MIGTD_TDREPORT_INIT,
                    Some(false),
                    Some(&init.td_report),
                )?)?
                .add_extension(Extension::new(
                    EXTNID_MIGTD_POLICY_INIT,
                    Some(false),
                    Some(&init.mig_policy),
                )?)?
                .add_extension(Extension::new(
                    EXTNID_MIGTD_EVENTLOG_INIT,
                    Some(false),
                    Some(&init.event_log),
                )?)?
                .build();
            sign_certificate(cert, signing_key)
        })
        .ok()
    })
    .ok_or(RatlsError::Config)
}

fn build_x509_common<F>(quote: &[u8], pub_key: &[u8], customizer: F) -> Result<Vec<u8>>
where
    F: FnOnce(CertificateBuilder<'_>) -> Result<Vec<u8>>,
{
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(AnyRef::new(
            Tag::ObjectIdentifier,
            SECP384R1_OID.as_bytes(),
        )?),
    };
    let eku = vec![SERVER_AUTH, CLIENT_AUTH, MIGTD_EXTENDED_KEY_USAGE].to_der()?;

    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };
    let key_usage = BitStringRef::from_bytes(&[0x80])?.to_der()?;
    let event_log = get_event_log().ok_or(RatlsError::Config)?;
    let mig_policy = get_policy().ok_or(RatlsError::Config)?;

    let builder = CertificateBuilder::new(sig_alg, algorithm, pub_key)?
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
            Some(quote),
        )?)?
        .add_extension(Extension::new(
            EXTNID_MIGTD_EVENT_LOG,
            Some(false),
            Some(event_log),
        )?)?
        .add_extension(Extension::new(
            EXTNID_MIGTD_POLICY,
            Some(false),
            Some(mig_policy),
        )?)
        .map_err(|e| RatlsError::X509(e))?;

    customizer(builder)
}

fn sign_certificate(cert: Certificate, signing_key: &EcdsaPk) -> Result<Vec<u8>> {
    let tbs = cert.tbs_certificate.to_der()?;
    let mut cert = cert;
    let signature = signing_key.sign(&tbs)?;
    cert.set_signature(&signature)?;
    Ok(cert.to_der()?)
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

        let (quote_report, event_log) =
            parse_extensions(extensions).ok_or(CryptoError::ParseCertificate)?;

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
        let _ = parse_extensions(extensions).ok_or(CryptoError::ParseCertificate)?;

        // As the remote attestation is disabled, the certificate can't be verified. Aways return
        // success for test purpose.
        Ok(())
    }
}

fn parse_extensions<'a>(extensions: &'a Extensions) -> Option<(&'a [u8], &'a [u8])> {
    let mut has_migtd_usage = false;
    let mut quote_report = None;
    let mut eventlog = None;

    for extn in extensions.get() {
        if extn.extn_id == EXTENDED_KEY_USAGE {
            if let Some(extn_value) = extn.extn_value {
                let eku = ExtendedKeyUsage::from_der(extn_value.as_bytes()).ok()?;
                if eku.contains(&MIGTD_EXTENDED_KEY_USAGE) {
                    has_migtd_usage = true;
                }
            }
        } else if extn.extn_id == EXTNID_MIGTD_QUOTE_REPORT {
            quote_report = extn.extn_value.map(|v| v.as_bytes());
        } else if extn.extn_id == EXTNID_MIGTD_EVENT_LOG {
            eventlog = extn.extn_value.map(|v| v.as_bytes());
        }
    }

    if !has_migtd_usage {
        return None;
    }

    if let (Some(quote_report), Some(eventlog)) = (quote_report, eventlog) {
        Some((quote_report, eventlog))
    } else {
        None
    }
}
