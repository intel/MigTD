// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

#[macro_use]
extern crate alloc;

use alloc::{string::String, vec::Vec};
use der::{Decode, Encode};
use pki_types::CertificateDer;
use rustls_pemfile::Item;

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

    /// Unexpected error that should not happen
    Unexpected,
}

impl From<x509::DerError> for Error {
    fn from(e: x509::DerError) -> Error {
        Error::GenerateCertificate(e)
    }
}

pub fn pem_cert_to_der(cert: &[u8]) -> Result<CertificateDer<'static>> {
    let item = rustls_pemfile::read_one_from_slice(cert)
        .map_err(|_| Error::DecodePemCert)?
        .map(|(item, _)| item)
        .ok_or(Error::DecodePemCert)?;
    match item {
        Item::X509Certificate(cert) => Ok(cert),
        _ => Err(Error::DecodePemCert),
    }
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
    let mut remaining = cert_chain_pem;

    // Extract all certificates from the PEM chain
    while !remaining.is_empty() {
        match rustls_pemfile::read_one_from_slice(remaining) {
            Ok(Some((Item::X509Certificate(cert), rest))) => {
                cert_chain.push(cert);
                remaining = rest;
            }
            Ok(Some((_, rest))) => {
                // Skip non-certificate items
                remaining = rest;
            }
            Ok(None) => break,
            Err(_) => return Err(Error::DecodePemCert),
        }
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
    // ECDSA with SHA-256: 1.2.840.10045.4.3.2
    const ECDSA_WITH_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];
    // ECDSA with SHA-384: 1.2.840.10045.4.3.3
    const ECDSA_WITH_SHA384: &[u32] = &[1, 2, 840, 10045, 4, 3, 3];

    // Match against known signature algorithm OIDs
    let algorithm_oid = &signature_algorithm.algorithm;
    let oid_arcs: Vec<u32> = algorithm_oid.arcs().collect();

    match oid_arcs.as_slice() {
        ECDSA_WITH_SHA256 => ecdsa::ecdsa_verify_with_algorithm(
            public_key,
            message,
            signature,
            &ecdsa::ECDSA_P256_SHA256_ASN1,
        )
        .map_err(|_| Error::SignatureVerification),
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
}
