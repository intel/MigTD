// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

#[macro_use]
extern crate alloc;

use alloc::{string::String, vec::Vec};
use der::{Decode, Encode};
use pki_types::{pem::PemObject, CertificateDer};

cfg_if::cfg_if! {
    if #[cfg(feature = "rustls")] {
        pub mod rustls_impl;
        pub use rustls_impl::ecdsa;
        pub use rustls_impl::hash;
        pub use rustls_impl::tls;
    }
}

pub mod crl;
pub mod x509;

pub type Result<T> = core::result::Result<T, Error>;

pub const SHA384_DIGEST_SIZE: usize = 48;

#[derive(Debug)]
pub enum Error {
    /// Couldn't caculate the hash digest of the given data
    CalculateDigest,

    /// Couldn't generate random number
    GetRandom,

    /// Failed to generate asymmetric key
    GenerateKeyPair,

    /// Failed to generate X.509 certificate used for TLS
    GenerateCertificate(x509::DerError),

    /// Failed to parse X.509 certificate
    ParseCertificate,

    /// Failed to calculate the ECDSA digital signature of the given data
    EcdsaSign,

    /// Failed to verify the ECDSA digital signature of the given data
    EcdsaVerify,

    /// Couldn't configure the TLS contex, e.g., cipher suite, TLS protocol version.
    SetupTlsContext(tls::TlsLibError),

    /// Invalid DNS name
    InvalidDnsName,

    /// Error occurs during reading/writing the tls connection
    TlsStream,

    /// Unable to get the TLS peer's certificates
    TlsGetPeerCert,

    /// Unable to verify the TLS peer's certificates
    TlsVerifyPeerCert(String),

    /// Error occurs during processing the tls connection
    TlsConnection,

    /// Pem certificate parsing error
    DecodePemCert,

    /// Certificate chain verification failed
    CertChainVerification(String),

    /// Signature verification failed
    SignatureVerification,

    /// Unsupported signature algorithm
    UnsupportedAlgorithm,

    /// CRL number extension missing
    CrlNumberNotFound,

    /// Peer certificate chain validation failed
    PeerCertChainValidation(String),

    /// Unexpected error that should not happen
    Unexpected,
}

impl From<x509::DerError> for Error {
    fn from(e: x509::DerError) -> Error {
        Error::GenerateCertificate(e)
    }
}

pub fn pem_cert_to_der(cert: &[u8]) -> Result<CertificateDer<'static>> {
    CertificateDer::from_pem_slice(cert).map_err(|_| Error::DecodePemCert)
}

/// Returns the SHA-384 hash of the leaf certificate's public key from a PEM cert chain.
/// Per GHCI 1.5: this hash is placed in tdinfo.MROWNER as the policy signing key identifier.
pub fn get_policy_signer_key_hash(cert_chain_pem: &[u8]) -> Result<[u8; SHA384_DIGEST_SIZE]> {
    let cert_chain = extract_cert_chain_from_pem(cert_chain_pem)?;
    if cert_chain.is_empty() {
        return Err(Error::CertChainVerification(
            "No certificates found in chain".into(),
        ));
    }
    let leaf_cert = &cert_chain[0];
    let cert =
        x509::Certificate::from_der(leaf_cert.as_ref()).map_err(|_| Error::ParseCertificate)?;
    let public_key = extract_public_key_from_cert(&cert)?;
    let hash_vec = hash::digest_sha384(&public_key).map_err(|_| Error::CalculateDigest)?;
    let mut hash = [0u8; SHA384_DIGEST_SIZE];
    hash.copy_from_slice(&hash_vec);
    Ok(hash)
}

/// Verifies a certificate chain and then verifies a message signature
pub fn verify_cert_chain_and_signature(
    cert_chain_pem: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let cert_chain = extract_cert_chain_from_pem(cert_chain_pem)?;

    verify_certificate_chain(&cert_chain)?;

    // Extract public key from the leaf certificate and verify signature
    let leaf_cert = &cert_chain[0];
    verify_signature_with_cert(leaf_cert, message, signature)?;

    Ok(())
}

fn extract_cert_chain_from_pem(cert_chain_pem: &[u8]) -> Result<Vec<CertificateDer>> {
    let mut cert_chain = Vec::new();

    // Extract all certificates from the PEM chain
    for cert in CertificateDer::pem_slice_iter(cert_chain_pem) {
        let cert = cert.map_err(|_| Error::DecodePemCert)?;
        cert_chain.push(cert);
    }

    if cert_chain.is_empty() {
        return Err(Error::CertChainVerification(
            "No certificates found in chain".into(),
        ));
    }

    Ok(cert_chain)
}

/// Verifies a certificate chain (leaf to root)
fn verify_certificate_chain(cert_chain: &[CertificateDer<'_>]) -> Result<()> {
    if cert_chain.is_empty() {
        return Err(Error::CertChainVerification(
            "Empty certificate chain".into(),
        ));
    }

    if cert_chain.len() == 1 {
        return Ok(());
    }

    // Verify each certificate in the chain against its issuer
    for i in 0..cert_chain.len() - 1 {
        let subject_cert = x509::Certificate::from_der(cert_chain[i].as_ref())
            .map_err(|_| Error::ParseCertificate)?;
        let issuer_cert = x509::Certificate::from_der(cert_chain[i + 1].as_ref())
            .map_err(|_| Error::ParseCertificate)?;

        verify_cert_signature(&subject_cert, &issuer_cert)?;
    }

    Ok(())
}

/// Verifies that subject_cert was signed by issuer_cert
fn verify_cert_signature(
    subject_cert: &x509::Certificate,
    issuer_cert: &x509::Certificate,
) -> Result<()> {
    let issuer_public_key = extract_public_key_from_cert(issuer_cert)?;
    let signature_algorithm = &subject_cert.signature_algorithm;

    // Get the signature from subject certificate
    let signature = subject_cert
        .signature_value
        .as_bytes()
        .ok_or(Error::ParseCertificate)?;

    // Get the signed data (tbsCertificate)
    let tbs_cert_der = subject_cert
        .tbs_certificate
        .to_der()
        .map_err(|_| Error::ParseCertificate)?;

    verify_signature_with_algorithm(
        &issuer_public_key,
        &tbs_cert_der,
        signature,
        signature_algorithm,
    )
}

/// Verifies a message signature using the public key from a certificate
fn verify_signature_with_cert(
    cert_der: &CertificateDer<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let cert =
        x509::Certificate::from_der(cert_der.as_ref()).map_err(|_| Error::ParseCertificate)?;
    let public_key = extract_public_key_from_cert(&cert)?;
    let signature_algorithm = &cert.signature_algorithm;

    verify_signature_with_algorithm(&public_key, message, signature, signature_algorithm)
}

/// Extracts the public key from a certificate
fn extract_public_key_from_cert(cert: &x509::Certificate) -> Result<Vec<u8>> {
    let public_key_info = &cert.tbs_certificate.subject_public_key_info;

    let public_key_bytes = public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(Error::ParseCertificate)?;

    Ok(public_key_bytes.to_vec())
}

/// Verifies a signature using the specified algorithm
fn verify_signature_with_algorithm(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    signature_algorithm: &x509::AlgorithmIdentifier,
) -> Result<()> {
    // ECDSA with SHA-384: 1.2.840.10045.4.3.3
    const ECDSA_WITH_SHA384: &[u32] = &[1, 2, 840, 10045, 4, 3, 3];

    // Match against known signature algorithm OIDs
    let algorithm_oid = &signature_algorithm.algorithm;
    let oid_arcs: Vec<u32> = algorithm_oid.arcs().collect();

    // Only ECDSA-P384 with SHA384 signature is supported
    match oid_arcs.as_slice() {
        ECDSA_WITH_SHA384 => ecdsa::ecdsa_verify_with_algorithm(
            public_key,
            message,
            signature,
            &ecdsa::ECDSA_P384_SHA384_ASN1,
        )
        .map_err(|_| Error::SignatureVerification),
        _ => {
            // Unsupported algorithm
            Err(Error::UnsupportedAlgorithm)
        }
    }
}

/// Validates a peer's certificate chain against the local certificate chain.
///
/// Performs the following checks:
/// 1. Verifies the peer chain's internal signature integrity
/// 2. Root CA must match between local and peer chains
/// 3. Leaf certificate Subject Name must match
pub fn validate_peer_cert_chain(local_chain_pem: &[u8], peer_chain_pem: &[u8]) -> Result<()> {
    let local_chain = extract_cert_chain_from_pem(local_chain_pem)?;
    let peer_chain = extract_cert_chain_from_pem(peer_chain_pem)?;

    // 1. Verify the peer chain's own signature integrity
    verify_certificate_chain(&peer_chain)?;

    // 2. Root CA must match (DER byte comparison)
    check_root_ca_match(&local_chain, &peer_chain)?;

    // Parse leaf certs for subject name check
    let local_leaf = x509::Certificate::from_der(local_chain[0].as_ref())
        .map_err(|_| Error::ParseCertificate)?;
    let peer_leaf =
        x509::Certificate::from_der(peer_chain[0].as_ref()).map_err(|_| Error::ParseCertificate)?;

    // 3. Leaf certificate Subject Name must match
    if local_leaf.tbs_certificate.subject != peer_leaf.tbs_certificate.subject {
        return Err(Error::PeerCertChainValidation(
            "Leaf certificate Subject Name mismatch between local and peer chains".into(),
        ));
    }

    Ok(())
}

fn check_root_ca_match(
    local_chain: &[CertificateDer<'_>],
    peer_chain: &[CertificateDer<'_>],
) -> Result<()> {
    // extract_cert_chain_from_pem guarantees non-empty chains
    let local_root = local_chain.last().unwrap();
    let peer_root = peer_chain.last().unwrap();

    if local_root.as_ref() != peer_root.as_ref() {
        return Err(Error::PeerCertChainValidation(
            "Root CA mismatch between local and peer certificate chains".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_chain_verification() {
        let test_pem = b"-----BEGIN CERTIFICATE-----
MIICVzCCAd6gAwIBAgIUVKXleE/7DfWQZ7seyT3TqMXwAqcwCgYIKoZIzj0EAwMw
dDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEiMCAGA1UECgwZTWlnVEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwV
TWlnVEQgSW50ZXJtZWRpYXRlIENBMB4XDTI1MDkwNTA1NTI1M1oXDTI2MDkwNTA1
NTI1M1owYzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50
YSBDbGFyYTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRowGAYDVQQDDBFNaWdURCBJ
bmZvIElzc3VlcjB2MBAGByqGSM49AgEGBSuBBAAiA2IABL1rH/Pc4KUchfNLqm2z
Wc1FC7RfBI4xGUSU/hBnRDmEj5HKWdN2p7YIeUn+z0RiYXUxr5nHed+pvaD2CZ1b
y2wymsVZQpWIwtf8shfePFJcQrHsYsmmvvwi5ocOXe6ZkaNCMEAwHQYDVR0OBBYE
FHIbR1J8L+HjJNaHdXioZJ5r9zrSMB8GA1UdIwQYMBaAFJYGgWjSezCJ0vsgGDCl
W1a/KQLdMAoGCCqGSM49BAMDA2cAMGQCMCshcjFfbTVDx6XJL+ERXKqfTJdhK1oH
tMQ+m74KW6AfKZt0lqZ5eeFXc/RFW8pKpQIwHsObyRhFH6OaFqxw+oItj2qCRUlz
cCnHD8l/TBHhUoubb2OMLoENlBLECLtFHV2X
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICVDCCAdqgAwIBAgIUY4sE3O7mKGtP/otJ0s4WQtwn4ZswCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI1MDkwNTA1NDQ0M1oXDTMwMDkwNDA1NDQ0M1owdDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEiMCAGA1UECgwZTWln
VEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwVTWlnVEQgSW50ZXJtZWRp
YXRlIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhf4d4GTrO4NhJ24aG5A3i4Qu
mwGZ+Jsfo3siVVy1/vke9tN+ylkZlR5M2bl4O4y2eeUMGrzwSu84L/7crgqnnZsH
XrOQslNsSYJzB+YrbeJ1GBG+oDnCxvYgLTvCDtDio0IwQDAdBgNVHQ4EFgQUlgaB
aNJ7MInS+yAYMKVbVr8pAt0wHwYDVR0jBBgwFoAUpXzUSS/yVomZP8e814EZVbC8
FY0wCgYIKoZIzj0EAwMDaAAwZQIwHoKqUxUqI2Zw8omp82svEjmN477njoK9YtOU
XtukW4+7RkU6VqSR6ND/9H83PMrLAjEAkPcCM/8QG3yZL1pxvKv87JwOIMJd5eUu
QDT7gy1UxPCjOETC2ygJyjJdYxBbXQrr
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICTzCCAdagAwIBAgIUeUyrqFAE0stc3jxOpGo12mTasB0wCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI1MDkwNTA1NDIxNVoXDTM1MDkwMzA1NDIxNVowXzELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEVMBMGA1UECgwMTWln
VEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENBMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEDnCmBt1r87/4VTwChvkyyrbfL79z5cx0NrVN4Gmp6HvpndL95MCd
ArnSdslXL/WmupFbxzy+a6mP4jdmR3oC7KyEaCKftOAct+Pz/e1KVI+QA3arR3IK
xW5TYzSQpoMdo1MwUTAdBgNVHQ4EFgQUpXzUSS/yVomZP8e814EZVbC8FY0wHwYD
VR0jBBgwFoAUpXzUSS/yVomZP8e814EZVbC8FY0wDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDAwNnADBkAjBLN5JiAwPChO4RWfAMy+XjUbllaTFTxRqwCRliwx0v
f4aNNQ6Vrzv3pYXXmwl0CaoCMGFKKLm6EVwvQcILpSL3JpkfcKMfsUlJgdkVlF/W
rPSb+wS9KsT0dcF2DU5F12BycQ==
-----END CERTIFICATE-----
";

        let cert_chain = extract_cert_chain_from_pem(test_pem).unwrap();
        assert!(verify_certificate_chain(&cert_chain).is_ok());
    }

    // Test chain for peer cert chain validation tests:
    // Leaf: CN=MigTD Info Issuer, expires 2026-09-05
    // Intermediate: CN=MigTD Intermediate CA, expires 2030-09-04
    // Root: CN=MigTD Root CA, expires 2035-09-03
    fn test_chain() -> &'static [u8] {
        b"-----BEGIN CERTIFICATE-----
MIICVzCCAd6gAwIBAgIUVKXleE/7DfWQZ7seyT3TqMXwAqcwCgYIKoZIzj0EAwMw
dDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEiMCAGA1UECgwZTWlnVEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwV
TWlnVEQgSW50ZXJtZWRpYXRlIENBMB4XDTI1MDkwNTA1NTI1M1oXDTI2MDkwNTA1
NTI1M1owYzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50
YSBDbGFyYTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRowGAYDVQQDDBFNaWdURCBJ
bmZvIElzc3VlcjB2MBAGByqGSM49AgEGBSuBBAAiA2IABL1rH/Pc4KUchfNLqm2z
Wc1FC7RfBI4xGUSU/hBnRDmEj5HKWdN2p7YIeUn+z0RiYXUxr5nHed+pvaD2CZ1b
y2wymsVZQpWIwtf8shfePFJcQrHsYsmmvvwi5ocOXe6ZkaNCMEAwHQYDVR0OBBYE
FHIbR1J8L+HjJNaHdXioZJ5r9zrSMB8GA1UdIwQYMBaAFJYGgWjSezCJ0vsgGDCl
W1a/KQLdMAoGCCqGSM49BAMDA2cAMGQCMCshcjFfbTVDx6XJL+ERXKqfTJdhK1oH
tMQ+m74KW6AfKZt0lqZ5eeFXc/RFW8pKpQIwHsObyRhFH6OaFqxw+oItj2qCRUlz
cCnHD8l/TBHhUoubb2OMLoENlBLECLtFHV2X
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICVDCCAdqgAwIBAgIUY4sE3O7mKGtP/otJ0s4WQtwn4ZswCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI1MDkwNTA1NDQ0M1oXDTMwMDkwNDA1NDQ0M1owdDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEiMCAGA1UECgwZTWln
VEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwVTWlnVEQgSW50ZXJtZWRp
YXRlIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhf4d4GTrO4NhJ24aG5A3i4Qu
mwGZ+Jsfo3siVVy1/vke9tN+ylkZlR5M2bl4O4y2eeUMGrzwSu84L/7crgqnnZsH
XrOQslNsSYJzB+YrbeJ1GBG+oDnCxvYgLTvCDtDio0IwQDAdBgNVHQ4EFgQUlgaB
aNJ7MInS+yAYMKVbVr8pAt0wHwYDVR0jBBgwFoAUpXzUSS/yVomZP8e814EZVbC8
FY0wCgYIKoZIzj0EAwMDaAAwZQIwHoKqUxUqI2Zw8omp82svEjmN477njoK9YtOU
XtukW4+7RkU6VqSR6ND/9H83PMrLAjEAkPcCM/8QG3yZL1pxvKv87JwOIMJd5eUu
QDT7gy1UxPCjOETC2ygJyjJdYxBbXQrr
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICTzCCAdagAwIBAgIUeUyrqFAE0stc3jxOpGo12mTasB0wCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI1MDkwNTA1NDIxNVoXDTM1MDkwMzA1NDIxNVowXzELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEVMBMGA1UECgwMTWln
VEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENBMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEDnCmBt1r87/4VTwChvkyyrbfL79z5cx0NrVN4Gmp6HvpndL95MCd
ArnSdslXL/WmupFbxzy+a6mP4jdmR3oC7KyEaCKftOAct+Pz/e1KVI+QA3arR3IK
xW5TYzSQpoMdo1MwUTAdBgNVHQ4EFgQUpXzUSS/yVomZP8e814EZVbC8FY0wHwYD
VR0jBBgwFoAUpXzUSS/yVomZP8e814EZVbC8FY0wDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDAwNnADBkAjBLN5JiAwPChO4RWfAMy+XjUbllaTFTxRqwCRliwx0v
f4aNNQ6Vrzv3pYXXmwl0CaoCMGFKKLm6EVwvQcILpSL3JpkfcKMfsUlJgdkVlF/W
rPSb+wS9KsT0dcF2DU5F12BycQ==
-----END CERTIFICATE-----
"
    }

    // Extract only root CA cert (last in chain)
    fn root_ca_only() -> &'static [u8] {
        b"-----BEGIN CERTIFICATE-----
MIICTzCCAdagAwIBAgIUeUyrqFAE0stc3jxOpGo12mTasB0wCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI1MDkwNTA1NDIxNVoXDTM1MDkwMzA1NDIxNVowXzELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEVMBMGA1UECgwMTWln
VEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENBMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEDnCmBt1r87/4VTwChvkyyrbfL79z5cx0NrVN4Gmp6HvpndL95MCd
ArnSdslXL/WmupFbxzy+a6mP4jdmR3oC7KyEaCKftOAct+Pz/e1KVI+QA3arR3IK
xW5TYzSQpoMdo1MwUTAdBgNVHQ4EFgQUpXzUSS/yVomZP8e814EZVbC8FY0wHwYD
VR0jBBgwFoAUpXzUSS/yVomZP8e814EZVbC8FY0wDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDAwNnADBkAjBLN5JiAwPChO4RWfAMy+XjUbllaTFTxRqwCRliwx0v
f4aNNQ6Vrzv3pYXXmwl0CaoCMGFKKLm6EVwvQcILpSL3JpkfcKMfsUlJgdkVlF/W
rPSb+wS9KsT0dcF2DU5F12BycQ==
-----END CERTIFICATE-----
"
    }

    // Intermediate CA cert (different root from test_chain) for root CA mismatch test
    fn different_root_chain() -> &'static [u8] {
        // Use intermediate cert as "root" to simulate different root CA
        b"-----BEGIN CERTIFICATE-----
MIICVDCCAdqgAwIBAgIUY4sE3O7mKGtP/otJ0s4WQtwn4ZswCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI1MDkwNTA1NDQ0M1oXDTMwMDkwNDA1NDQ0M1owdDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEiMCAGA1UECgwZTWln
VEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwVTWlnVEQgSW50ZXJtZWRp
YXRlIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhf4d4GTrO4NhJ24aG5A3i4Qu
mwGZ+Jsfo3siVVy1/vke9tN+ylkZlR5M2bl4O4y2eeUMGrzwSu84L/7crgqnnZsH
XrOQslNsSYJzB+YrbeJ1GBG+oDnCxvYgLTvCDtDio0IwQDAdBgNVHQ4EFgQUlgaB
aNJ7MInS+yAYMKVbVr8pAt0wHwYDVR0jBBgwFoAUpXzUSS/yVomZP8e814EZVbC8
FY0wCgYIKoZIzj0EAwMDaAAwZQIwHoKqUxUqI2Zw8omp82svEjmN477njoK9YtOU
XtukW4+7RkU6VqSR6ND/9H83PMrLAjEAkPcCM/8QG3yZL1pxvKv87JwOIMJd5eUu
QDT7gy1UxPCjOETC2ygJyjJdYxBbXQrr
-----END CERTIFICATE-----
"
    }

    #[test]
    fn test_validate_peer_cert_chain_same_chain() {
        let chain = test_chain();
        assert!(validate_peer_cert_chain(chain, chain).is_ok());
    }

    #[test]
    fn test_validate_peer_cert_chain_root_ca_mismatch() {
        let chain = test_chain();
        let diff = different_root_chain();
        let result = validate_peer_cert_chain(chain, diff);
        assert!(result.is_err());
        match result {
            Err(Error::PeerCertChainValidation(msg)) => {
                assert!(msg.contains("Root CA mismatch"));
            }
            _ => panic!("Expected PeerCertChainValidation error"),
        }
    }

    #[test]
    fn test_validate_peer_cert_chain_subject_name_mismatch() {
        let chain = test_chain();
        let root = root_ca_only();
        let result = validate_peer_cert_chain(chain, root);
        assert!(result.is_err());
        match result {
            Err(Error::PeerCertChainValidation(msg)) => {
                assert!(msg.contains("Subject Name mismatch"));
            }
            _ => panic!("Expected PeerCertChainValidation error"),
        }
    }
}
