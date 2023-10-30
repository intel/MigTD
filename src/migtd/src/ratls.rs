// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{string::ToString, vec::Vec};
use rust_std_stub::io::{Read, Write};
use tdx_tdcall::TdCallError;

use crate::{event_log::get_event_log, mig_policy};
use crypto::{
    ecdsa::{ecdsa_verify, EcdsaPk},
    hash::digest_sha384,
    tls::{SecureChannel, TlsConfig},
    x509::{
        AlgorithmIdentifier, Any, BitString, Certificate, CertificateBuilder, Decodable, DerError,
        Encodable, ExtendedKeyUsage, Extension, Extensions, ObjectIdentifier, Tag,
    },
    Error as CryptoError, Result as CryptoResult,
};

type Result<T> = core::result::Result<T, RatlsError>;

pub enum RatlsError {
    GetQuote,
    VerifyQuote,
    TdxModule(TdCallError),
    Crypto(CryptoError),
    X509(DerError),
    InvalidEventlog,
}

impl From<TdCallError> for RatlsError {
    fn from(value: TdCallError) -> Self {
        Self::TdxModule(value)
    }
}

impl From<CryptoError> for RatlsError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<DerError> for RatlsError {
    fn from(value: DerError) -> Self {
        Self::X509(value)
    }
}

pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.19");
pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.14");
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.35");
pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");
pub const MIGTD_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113741.1.5.5.1.1");
pub const EXTNID_MIGTD_QUOTE_REPORT: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113741.1.5.5.1.2");
pub const EXTNID_MIGTD_EVENT_LOG: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113741.1.5.5.1.3");

// As specified in https://datatracker.ietf.org/doc/html/rfc5480#appendix-A
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//     iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1
// }
pub const ID_EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
// secp384r1 OBJECT IDENTIFIER ::= {
//     iso(1) identified-organization(3) certicom(132) curve(0) 34
// }
pub const SECP384R1_OID: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");
pub const KEY_USAGE_EXTENSION: ObjectIdentifier = ObjectIdentifier::new("2.5.29.15");
pub const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.1");
pub const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.2");
pub const ID_EC_SIG_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.3");

pub const MIG_POLICY_ERROR: &str = "MigPolicyError";
pub const MUTUAL_ATTESTATION_ERROR: &str = "MutualAttestationError";
pub const MISMATCH_PUBLIC_KEY: &str = "MismatchPublicKeyError";

const PUBLIC_KEY_HASH_SIZE: usize = 48;

pub fn server<T: Read + Write>(stream: T) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new()?;
    let certs = vec![gen_cert(&signing_key)?];

    // Server verifies certificate of client
    let config = TlsConfig::new(certs, signing_key, verify_client_cert)?;
    config.tls_server(stream).map_err(|e| e.into())
}

pub fn client<T: Read + Write>(stream: T) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new()?;
    let certs = vec![gen_cert(&signing_key)?];

    // Client verifies certificate of server
    let config = TlsConfig::new(certs, signing_key, verify_server_cert)?;
    config.tls_client(stream).map_err(|e| e.into())
}

fn gen_cert(signing_key: &EcdsaPk) -> Result<Vec<u8>> {
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes())?),
    };
    let eku = vec![SERVER_AUTH, CLIENT_AUTH, MIGTD_EXTENDED_KEY_USAGE].to_vec()?;

    let pub_key = signing_key.public_key()?;
    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };
    let key_usage = BitString::from_bytes(&[0x80])?.to_vec()?;
    let quote = gen_quote(&pub_key)?;
    let event_log = get_event_log().ok_or(RatlsError::InvalidEventlog)?;
    let mut x509_certificate = CertificateBuilder::new(sig_alg, algorithm, &pub_key)?
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
        )?)?
        .build();
    let tbs = x509_certificate.tbs_certificate.to_vec()?;
    let signature = signing_key.sign(&tbs)?;
    x509_certificate.set_signature(&signature)?;

    x509_certificate.to_vec().map_err(|e| e.into())
}

fn gen_quote(public_key: &[u8]) -> Result<Vec<u8>> {
    let hash = digest_sha384(public_key)?;

    // Generate the TD Report that contains the public key hash as nonce
    let mut additional_data = [0u8; 64];
    additional_data[..hash.len()].copy_from_slice(hash.as_ref());
    let td_report = tdx_tdcall::tdreport::tdcall_report(&additional_data)?;

    attestation::get_quote(td_report.as_bytes()).map_err(|_| RatlsError::GetQuote)
}

fn verify_server_cert(cert: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(true, cert)
}

fn verify_client_cert(cert: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(false, cert)
}

fn verify_peer_cert(is_client: bool, cert: &[u8]) -> core::result::Result<(), CryptoError> {
    let cert = Certificate::from_der(cert).map_err(|_| CryptoError::ParseCertificate)?;

    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(CryptoError::ParseCertificate)?;

    let (quote_report, event_log) =
        parse_extensions(extensions).ok_or(CryptoError::ParseCertificate)?;

    if let Ok(report) = attestation::verify_quote(quote_report) {
        verify_signature(&cert, report.as_slice())?;

        // MigTD-src acts as TLS client
        if mig_policy::authenticate_policy(is_client, report.as_slice(), event_log)
            != policy::PolicyVerifyReulst::Succeed
        {
            return Err(CryptoError::TlsVerifyPeerCert(MIG_POLICY_ERROR.to_string()));
        }
    } else {
        return Err(CryptoError::TlsVerifyPeerCert(
            MUTUAL_ATTESTATION_ERROR.to_string(),
        ));
    }

    Ok(())
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

fn verify_signature(cert: &Certificate, td_report: &[u8]) -> CryptoResult<()> {
    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(CryptoError::ParseCertificate)?;
    let tbs = cert.tbs_certificate.to_vec()?;
    let signature = cert
        .signature_value
        .as_bytes()
        .ok_or(CryptoError::ParseCertificate)?;

    verify_public_key(td_report, public_key)?;
    ecdsa_verify(public_key, &tbs, signature)
}

fn verify_public_key(td_report: &[u8], public_key: &[u8]) -> CryptoResult<()> {
    let report_data = &td_report[128..128 + PUBLIC_KEY_HASH_SIZE];
    let digest = digest_sha384(public_key)?;

    if report_data == digest.as_slice() {
        Ok(())
    } else {
        Err(CryptoError::TlsVerifyPeerCert(
            MISMATCH_PUBLIC_KEY.to_string(),
        ))
    }
}
