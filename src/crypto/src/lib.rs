// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

#[macro_use]
extern crate alloc;

use alloc::{string::String, vec::Vec};
use der::{Decode, Encode, Sequence};
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
/// 4. Every issuer certificate in the peer chain MUST carry the X.509
///    `BasicConstraints` extension with `cA=TRUE` (RFC 5280 §4.2.1.9). This
///    prevents a peer from presenting `[fake_leaf, legit_leaf, …]` where the
///    legit leaf's private key was stolen and used to sign a synthetic
///    sub-leaf — the legit leaf is not a CA, so it is not a valid issuer.
///
/// Intentionally not checked:
/// - **Intermediate cert identity** — intermediate cert contents are not
///   compared against the local chain's intermediates. This lets either
///   side rotate its intermediate CA(s) independently, as long as the
///   shared root and the leaf Subject Name remain stable and every issuer
///   in the peer chain is itself a CA (check 4). Intermediate certs are
///   still validated structurally (signature integrity in check 1 and
///   CA-attribute in check 4).
///
/// Assumption: the leaf cert's Subject Name uniquely identifies the
/// intended usage for the product/model — distinct usages must use
/// distinct Subject Names in their leaf certs.
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

    // 4. Every issuer in the peer chain must be a CA.
    for cert_der in peer_chain.iter().skip(1) {
        let issuer =
            x509::Certificate::from_der(cert_der.as_ref()).map_err(|_| Error::ParseCertificate)?;
        if !is_ca_certificate(&issuer)? {
            return Err(Error::PeerCertChainValidation(
                "Peer chain contains a non-CA issuer certificate (BasicConstraints \
                 cA=TRUE missing)"
                    .into(),
            ));
        }
    }

    Ok(())
}

/// X.509 BasicConstraints extension OID (RFC 5280 §4.2.1.9).
const BASIC_CONSTRAINTS_OID: x509::ObjectIdentifier =
    x509::ObjectIdentifier::new_unwrap("2.5.29.19");

/// Minimal DER representation of `BasicConstraints` per RFC 5280 §4.2.1.9:
///
/// ```text
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
/// }
/// ```
///
/// Both fields are encoded as ASN.1 OPTIONAL. `cA` is omitted when FALSE
/// (DEFAULT) and `pathLenConstraint` is intentionally OPTIONAL, so a
/// tolerant parser is needed.
#[derive(Debug, Sequence)]
struct BasicConstraints {
    ca: Option<bool>,
    path_len: Option<u32>,
}

/// Returns `true` if the certificate carries the BasicConstraints extension
/// with `cA=TRUE`. Returns `false` if the extension is absent or `cA` is
/// FALSE. Returns `Error::ParseCertificate` if the extension cannot be
/// decoded.
fn is_ca_certificate(cert: &x509::Certificate<'_>) -> Result<bool> {
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(false);
    };
    for ext in extensions.get() {
        if ext.extn_id == BASIC_CONSTRAINTS_OID {
            let value = ext.extn_value.as_ref().ok_or(Error::ParseCertificate)?;
            let bc = BasicConstraints::from_der(value.as_bytes())
                .map_err(|_| Error::ParseCertificate)?;
            return Ok(bc.ca.unwrap_or(false));
        }
    }
    Ok(false)
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

    // Full 3-cert chain from key_gen.sh (leaf-to-root).
    // - Leaf:         CN=MigTD Info Issuer (NOT a CA — KeyUsage=digitalSignature only).
    // - Intermediate: CN=MigTD Intermediate CA (CA:TRUE, keyCertSign+cRLSign).
    // - Root:         CN=MigTD Root CA (CA:TRUE, self-signed).
    fn test_chain() -> &'static [u8] {
        b"-----BEGIN CERTIFICATE-----
MIICaTCCAe6gAwIBAgIUSrdf9Y+hTcE9dH+1uihg7mKJCXswCgYIKoZIzj0EAwMw
dDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEiMCAGA1UECgwZTWlnVEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwV
TWlnVEQgSW50ZXJtZWRpYXRlIENBMB4XDTI2MDUxMjIwNDA0MFoXDTI3MDUxMjIw
NDA0MFowYzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50
YSBDbGFyYTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRowGAYDVQQDDBFNaWdURCBJ
bmZvIElzc3VlcjB2MBAGByqGSM49AgEGBSuBBAAiA2IABP8JXaMsqGwwMJy3Ec5i
d/3/KF+Ti11YD0y866xGWT6xfuWqBljkvwy+xFBnwAh+SNisDYpldJ7y9iuA/jPf
YzbREHvU4CglU5oO96+9ZQacPFsSaN6OD1CwR5DhVGhi+6NSMFAwDgYDVR0PAQH/
BAQDAgeAMB0GA1UdDgQWBBRvBEchXoNXCUv5K48Q45ARGecJhDAfBgNVHSMEGDAW
gBRedFi0rhq/hbdRGgjzV1Q62kPMRDAKBggqhkjOPQQDAwNpADBmAjEAx/vI59IH
mdG27TBGsOS6KzfZ7avUDurwwFx++58HjoLq68p8jvKQBQJjco9bcwUFAjEA7otq
20JSaBxpLxkBJCcunZc7i9ySGRywIPCiynvgp4SLMCqXSr9po/wjufNMVyDc
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICdDCCAfugAwIBAgIUHMVbFQp3McoskjA3z+fkDslYWqowCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI2MDUxMjIwNDA0MFoXDTMxMDUxMTIwNDA0MFowdDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEiMCAGA1UECgwZTWln
VEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwVTWlnVEQgSW50ZXJtZWRp
YXRlIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8AtBvl6xficPzPr/1HKbVR2G
pqPAeoAB9+j/N58VbzOViyn0IUdnBGbHAcbbWgJnJJnCKikaLo0LYsIXr43zhu6h
KSn/Y6zqYvQX6Vg7P1fXykqOjD/BHTufsT6nbCVeo2MwYTAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUXnRYtK4av4W3URoI81dUOtpD
zEQwHwYDVR0jBBgwFoAUgcamhlxuWjL7bCdkQ/Wlio7wcqcwCgYIKoZIzj0EAwMD
ZwAwZAIwRq/4NxR8KpRKwAKRPmt/XPGpCwmVSwo3iz9Qg8bkXrgwm/eVaPm0ujH9
a87fGPZEAjAjOp2/u/qcNxJA/9TYwIazlGcIpgaicZsxrmNJO7/wvyKTqhnhqjD9
kXYiyuG9OEI=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICUDCCAdagAwIBAgIUHhqbod5/KXrSjOsYEXscanAe+BMwCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI2MDUxMjIwNDA0MFoXDTM2MDUwOTIwNDA0MFowXzELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEVMBMGA1UECgwMTWln
VEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENBMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEYTrowfeGuVxrFtuJe8VYRR97M+JIKnuDYSp/Lajw89O2nsvRqj0Q
Z6ZrLwnU+vVmvcWINKuh34BnXytkceZNb1CrLTd/u99fkFjwG3yzZkyIWdChSY8j
N7tLRdr/H5wVo1MwUTAdBgNVHQ4EFgQUgcamhlxuWjL7bCdkQ/Wlio7wcqcwHwYD
VR0jBBgwFoAUgcamhlxuWjL7bCdkQ/Wlio7wcqcwDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDAwNoADBlAjAG1gB8KRE9HtDQ6prOldA5698qAroyH2pcbfdSEFn3
LKLJ4Rm2r0hbHToxLm7QhBkCMQDUwcFqYZYHpjJXojYkH50o4erRwY/hz6XtjvTt
m07Y31+o+LpsZuEnlIETx/zemHA=
-----END CERTIFICATE-----
"
    }

    // Extract only root CA cert (last in chain)
    fn root_ca_only() -> &'static [u8] {
        b"-----BEGIN CERTIFICATE-----
MIICUDCCAdagAwIBAgIUHhqbod5/KXrSjOsYEXscanAe+BMwCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI2MDUxMjIwNDA0MFoXDTM2MDUwOTIwNDA0MFowXzELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEVMBMGA1UECgwMTWln
VEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENBMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEYTrowfeGuVxrFtuJe8VYRR97M+JIKnuDYSp/Lajw89O2nsvRqj0Q
Z6ZrLwnU+vVmvcWINKuh34BnXytkceZNb1CrLTd/u99fkFjwG3yzZkyIWdChSY8j
N7tLRdr/H5wVo1MwUTAdBgNVHQ4EFgQUgcamhlxuWjL7bCdkQ/Wlio7wcqcwHwYD
VR0jBBgwFoAUgcamhlxuWjL7bCdkQ/Wlio7wcqcwDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDAwNoADBlAjAG1gB8KRE9HtDQ6prOldA5698qAroyH2pcbfdSEFn3
LKLJ4Rm2r0hbHToxLm7QhBkCMQDUwcFqYZYHpjJXojYkH50o4erRwY/hz6XtjvTt
m07Y31+o+LpsZuEnlIETx/zemHA=
-----END CERTIFICATE-----
"
    }

    // Intermediate CA cert (different root from test_chain) for root CA mismatch test
    fn different_root_chain() -> &'static [u8] {
        // Use intermediate cert as "root" to simulate different root CA
        b"-----BEGIN CERTIFICATE-----
MIICdDCCAfugAwIBAgIUHMVbFQp3McoskjA3z+fkDslYWqowCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI2MDUxMjIwNDA0MFoXDTMxMDUxMTIwNDA0MFowdDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEiMCAGA1UECgwZTWln
VEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwVTWlnVEQgSW50ZXJtZWRp
YXRlIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8AtBvl6xficPzPr/1HKbVR2G
pqPAeoAB9+j/N58VbzOViyn0IUdnBGbHAcbbWgJnJJnCKikaLo0LYsIXr43zhu6h
KSn/Y6zqYvQX6Vg7P1fXykqOjD/BHTufsT6nbCVeo2MwYTAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUXnRYtK4av4W3URoI81dUOtpD
zEQwHwYDVR0jBBgwFoAUgcamhlxuWjL7bCdkQ/Wlio7wcqcwCgYIKoZIzj0EAwMD
ZwAwZAIwRq/4NxR8KpRKwAKRPmt/XPGpCwmVSwo3iz9Qg8bkXrgwm/eVaPm0ujH9
a87fGPZEAjAjOp2/u/qcNxJA/9TYwIazlGcIpgaicZsxrmNJO7/wvyKTqhnhqjD9
kXYiyuG9OEI=
-----END CERTIFICATE-----
"
    }

    // Adversarial chain demonstrating the stolen-leaf-key attack:
    //   [fake_leaf, legit_leaf, intermediate, root]
    // The legit leaf has no BasicConstraints; the fake leaf was signed by
    // the legit leaf's key while reusing the legit leaf's Subject Name, so
    // the existing subject-name + root-match + signature-integrity checks
    // all pass. Only the CA-attribute check on the legit leaf (as issuer)
    // rejects this chain.
    fn attacker_chain() -> &'static [u8] {
        b"-----BEGIN CERTIFICATE-----
MIICVzCCAd2gAwIBAgIUHTraNuO2R92W3rj+VUu757uTU/0wCgYIKoZIzj0EAwMw
YzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRowGAYDVQQDDBFNaWdURCBJbmZvIElz
c3VlcjAeFw0yNjA1MTIyMDQwNTFaFw0yNzA1MTIyMDQwNTFaMGMxCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExFTATBgNVBAoM
DE1pZ1REIElzc3VlcjEaMBgGA1UEAwwRTWlnVEQgSW5mbyBJc3N1ZXIwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAASSxgLL0LwBReD+XOcpX+sofsCF1cuwD1V78omG4FTR
sM9BiUlLMzx3wS7eGyfc2E06LE0Yoe701LU0HbpoA7dh48ZaAiov18ACmaJzjCU+
WwKqLkk3pzv+ZI4D9/b0CoqjUjBQMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU
EJLTAf3lyV3K8sZTp2rn0H1WNoMwHwYDVR0jBBgwFoAUbwRHIV6DVwlL+SuPEOOQ
ERnnCYQwCgYIKoZIzj0EAwMDaAAwZQIwME3HTmUH1tI0jQgwPhcF0r/xIMsI6suv
T42M1YqZtbLc7OYmG5PXfvTH1PwPFkAFAjEApGGfk3iBkY0QRybxwbE2bmL+7HqN
yCfVJCtt1codfb8+xNkUHsH+kXEIzAqRAU5+
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICaTCCAe6gAwIBAgIUSrdf9Y+hTcE9dH+1uihg7mKJCXswCgYIKoZIzj0EAwMw
dDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEiMCAGA1UECgwZTWlnVEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwV
TWlnVEQgSW50ZXJtZWRpYXRlIENBMB4XDTI2MDUxMjIwNDA0MFoXDTI3MDUxMjIw
NDA0MFowYzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50
YSBDbGFyYTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRowGAYDVQQDDBFNaWdURCBJ
bmZvIElzc3VlcjB2MBAGByqGSM49AgEGBSuBBAAiA2IABP8JXaMsqGwwMJy3Ec5i
d/3/KF+Ti11YD0y866xGWT6xfuWqBljkvwy+xFBnwAh+SNisDYpldJ7y9iuA/jPf
YzbREHvU4CglU5oO96+9ZQacPFsSaN6OD1CwR5DhVGhi+6NSMFAwDgYDVR0PAQH/
BAQDAgeAMB0GA1UdDgQWBBRvBEchXoNXCUv5K48Q45ARGecJhDAfBgNVHSMEGDAW
gBRedFi0rhq/hbdRGgjzV1Q62kPMRDAKBggqhkjOPQQDAwNpADBmAjEAx/vI59IH
mdG27TBGsOS6KzfZ7avUDurwwFx++58HjoLq68p8jvKQBQJjco9bcwUFAjEA7otq
20JSaBxpLxkBJCcunZc7i9ySGRywIPCiynvgp4SLMCqXSr9po/wjufNMVyDc
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICdDCCAfugAwIBAgIUHMVbFQp3McoskjA3z+fkDslYWqowCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI2MDUxMjIwNDA0MFoXDTMxMDUxMTIwNDA0MFowdDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEiMCAGA1UECgwZTWln
VEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwVTWlnVEQgSW50ZXJtZWRp
YXRlIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8AtBvl6xficPzPr/1HKbVR2G
pqPAeoAB9+j/N58VbzOViyn0IUdnBGbHAcbbWgJnJJnCKikaLo0LYsIXr43zhu6h
KSn/Y6zqYvQX6Vg7P1fXykqOjD/BHTufsT6nbCVeo2MwYTAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUXnRYtK4av4W3URoI81dUOtpD
zEQwHwYDVR0jBBgwFoAUgcamhlxuWjL7bCdkQ/Wlio7wcqcwCgYIKoZIzj0EAwMD
ZwAwZAIwRq/4NxR8KpRKwAKRPmt/XPGpCwmVSwo3iz9Qg8bkXrgwm/eVaPm0ujH9
a87fGPZEAjAjOp2/u/qcNxJA/9TYwIazlGcIpgaicZsxrmNJO7/wvyKTqhnhqjD9
kXYiyuG9OEI=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICUDCCAdagAwIBAgIUHhqbod5/KXrSjOsYEXscanAe+BMwCgYIKoZIzj0EAwMw
XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENB
MB4XDTI2MDUxMjIwNDA0MFoXDTM2MDUwOTIwNDA0MFowXzELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEVMBMGA1UECgwMTWln
VEQgSXNzdWVyMRYwFAYDVQQDDA1NaWdURCBSb290IENBMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEYTrowfeGuVxrFtuJe8VYRR97M+JIKnuDYSp/Lajw89O2nsvRqj0Q
Z6ZrLwnU+vVmvcWINKuh34BnXytkceZNb1CrLTd/u99fkFjwG3yzZkyIWdChSY8j
N7tLRdr/H5wVo1MwUTAdBgNVHQ4EFgQUgcamhlxuWjL7bCdkQ/Wlio7wcqcwHwYD
VR0jBBgwFoAUgcamhlxuWjL7bCdkQ/Wlio7wcqcwDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDAwNoADBlAjAG1gB8KRE9HtDQ6prOldA5698qAroyH2pcbfdSEFn3
LKLJ4Rm2r0hbHToxLm7QhBkCMQDUwcFqYZYHpjJXojYkH50o4erRwY/hz6XtjvTt
m07Y31+o+LpsZuEnlIETx/zemHA=
-----END CERTIFICATE-----
"
    }

    fn run_with_cert<R>(pem: &[u8], f: impl FnOnce(&x509::Certificate<'_>) -> R) -> R {
        let der = pem_cert_to_der(pem).unwrap();
        let cert = x509::Certificate::from_der(der.as_ref()).unwrap();
        f(&cert)
    }

    #[test]
    fn test_cert_chain_verification() {
        let cert_chain = extract_cert_chain_from_pem(test_chain()).unwrap();
        assert!(verify_certificate_chain(&cert_chain).is_ok());
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

    #[test]
    fn test_is_ca_certificate_leaf_is_not_ca() {
        // Extract the leaf cert (first cert in test_chain).
        let leaf_pem = b"-----BEGIN CERTIFICATE-----
MIICaTCCAe6gAwIBAgIUSrdf9Y+hTcE9dH+1uihg7mKJCXswCgYIKoZIzj0EAwMw
dDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEiMCAGA1UECgwZTWlnVEQgSW50ZXJtZWRpYXRlIElzc3VlcjEeMBwGA1UEAwwV
TWlnVEQgSW50ZXJtZWRpYXRlIENBMB4XDTI2MDUxMjIwNDA0MFoXDTI3MDUxMjIw
NDA0MFowYzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50
YSBDbGFyYTEVMBMGA1UECgwMTWlnVEQgSXNzdWVyMRowGAYDVQQDDBFNaWdURCBJ
bmZvIElzc3VlcjB2MBAGByqGSM49AgEGBSuBBAAiA2IABP8JXaMsqGwwMJy3Ec5i
d/3/KF+Ti11YD0y866xGWT6xfuWqBljkvwy+xFBnwAh+SNisDYpldJ7y9iuA/jPf
YzbREHvU4CglU5oO96+9ZQacPFsSaN6OD1CwR5DhVGhi+6NSMFAwDgYDVR0PAQH/
BAQDAgeAMB0GA1UdDgQWBBRvBEchXoNXCUv5K48Q45ARGecJhDAfBgNVHSMEGDAW
gBRedFi0rhq/hbdRGgjzV1Q62kPMRDAKBggqhkjOPQQDAwNpADBmAjEAx/vI59IH
mdG27TBGsOS6KzfZ7avUDurwwFx++58HjoLq68p8jvKQBQJjco9bcwUFAjEA7otq
20JSaBxpLxkBJCcunZc7i9ySGRywIPCiynvgp4SLMCqXSr9po/wjufNMVyDc
-----END CERTIFICATE-----
";
        run_with_cert(leaf_pem, |cert| {
            assert!(!is_ca_certificate(cert).unwrap());
        });
    }

    #[test]
    fn test_is_ca_certificate_intermediate_is_ca() {
        run_with_cert(different_root_chain(), |cert| {
            assert!(is_ca_certificate(cert).unwrap());
        });
    }

    #[test]
    fn test_is_ca_certificate_root_is_ca() {
        run_with_cert(root_ca_only(), |cert| {
            assert!(is_ca_certificate(cert).unwrap());
        });
    }

    #[test]
    fn test_validate_peer_cert_chain_non_ca_intermediate() {
        // Sanity: ensure the attacker chain otherwise passes lower-level
        // checks — its signature integrity verifies because the legit leaf
        // private key was used to sign the fake leaf.
        let attacker = attacker_chain();
        let cert_chain = extract_cert_chain_from_pem(attacker).unwrap();
        assert!(verify_certificate_chain(&cert_chain).is_ok());

        // The full validation must reject the attacker chain because the
        // legit leaf (acting as the issuer of the fake leaf) is not a CA.
        let local = test_chain();
        let result = validate_peer_cert_chain(local, attacker);
        match result {
            Err(Error::PeerCertChainValidation(msg)) => {
                assert!(msg.contains("non-CA"), "unexpected error message: {msg}");
            }
            other => panic!("Expected PeerCertChainValidation, got: {other:?}"),
        }
    }
}
