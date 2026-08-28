// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::x509::{AlgorithmIdentifier, Extension, Time};
use crate::Error;
use alloc::vec::Vec;
use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier, UintRef};
use der::{Choice, Decode, Encode, ErrorKind, Header, Sequence, Tag, TagMode, TagNumber, Tagged};
use pki_types::{pem::PemObject, CertificateRevocationListDer};

const CRL_NUMBER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.20");

/// ECDSA-with-SHA384 signature algorithm OID (1.2.840.10045.4.3.3). The only
/// CRL signature algorithm supported in-guest, matching the rest of the crypto
/// crate.
const ECDSA_WITH_SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

#[derive(Sequence)]
pub struct Crl<'a> {
    tbs_cert_list: TbsCertList<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature_value: BitStringRef<'a>,
}

#[derive(Sequence)]
struct TbsCertList<'a> {
    version: Option<AnyRef<'a>>,
    signature: AnyRef<'a>,
    issuer: AnyRef<'a>,
    this_update: Time,
    next_update: Option<Time>,
    revoked_certificates: Option<Vec<RevokedCertificate<'a>>>,
    crl_extensions: Option<Extensions<'a>>,
}

#[derive(Sequence)]
struct RevokedCertificate<'a> {
    user_certificate: UintRef<'a>,
    revocation_date: AnyRef<'a>,
    crl_entry_extensions: Option<AnyRef<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extensions<'a>(Vec<Extension<'a>>);

impl<'a> Extensions<'a> {
    pub fn get(&self) -> &Vec<Extension<'a>> {
        &self.0
    }
}

impl Encode for Extensions<'_> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl<'a> Decode<'a> for Extensions<'a> {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let ext = decoder
            .context_specific(TagNumber::new(0), TagMode::Explicit)?
            .ok_or(der::Error::new(ErrorKind::Failed, decoder.position()))?;
        Ok(Self(ext))
    }
}

impl Tagged for Extensions<'_> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(0),
        }
    }
}

impl<'a> Choice<'a> for Extensions<'a> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(0),
        }
    }
}

/// Parses a CRL and returns the CRL Number extension value
pub fn get_crl_number(crl: &[u8]) -> Result<u32, Error> {
    let crl_der =
        CertificateRevocationListDer::from_pem_slice(crl).map_err(|_| Error::DecodePemCert)?;

    let crl = Crl::from_der(&crl_der).map_err(|_| Error::ParseCertificate)?;

    if let Some(cs) = crl.tbs_cert_list.crl_extensions {
        for ext in cs.get().iter() {
            if ext.extn_id == CRL_NUMBER_OID {
                let number =
                    u32::from_der(ext.extn_value.ok_or(Error::CrlNumberNotFound)?.as_bytes())
                        .map_err(|_| Error::CrlNumberNotFound)?;
                return Ok(number);
            }
        }
    }

    Err(Error::CrlNumberNotFound)
}

fn crl_pem_to_der(crl: &[u8]) -> Result<Vec<u8>, Error> {
    CertificateRevocationListDer::from_pem_slice(crl)
        .map(|der| der.as_ref().to_vec())
        .map_err(|_| Error::DecodePemCert)
}

/// Returns the DER encoding of the CRL's `issuer` Name.
///
/// The caller matches this against a candidate CA certificate's `subject` DER
/// to find which certificate in a signer chain issued (and therefore should
/// have signed) this CRL.
pub fn get_crl_issuer_der(crl: &[u8]) -> Result<Vec<u8>, Error> {
    let der = crl_pem_to_der(crl)?;
    let crl = Crl::from_der(&der).map_err(|_| Error::ParseCertificate)?;
    crl.tbs_cert_list
        .issuer
        .to_der()
        .map_err(|_| Error::ParseCertificate)
}

/// Verify the CRL's ECDSA-P384/SHA-384 signature using the issuing CA's raw
/// public-key bytes (`SubjectPublicKey`, e.g. from
/// `extract_public_key_from_cert`).
///
/// Fails (`UnsupportedAlgorithm`) if the CRL is not signed with
/// ECDSA-with-SHA384, and (`EcdsaVerify`) if the signature does not verify.
/// This authenticates the CRL before any of its `revokedCertificates` entries
/// are trusted.
pub fn verify_crl_signature(crl: &[u8], issuer_public_key: &[u8]) -> Result<(), Error> {
    let der = crl_pem_to_der(crl)?;
    let crl = Crl::from_der(&der).map_err(|_| Error::ParseCertificate)?;

    if crl.signature_algorithm.algorithm != ECDSA_WITH_SHA384_OID {
        return Err(Error::UnsupportedAlgorithm);
    }

    let tbs = crl
        .tbs_cert_list
        .to_der()
        .map_err(|_| Error::ParseCertificate)?;
    let signature = crl
        .signature_value
        .as_bytes()
        .ok_or(Error::ParseCertificate)?;

    crate::ecdsa::ecdsa_verify_with_algorithm(
        issuer_public_key,
        &tbs,
        signature,
        &crate::ecdsa::ECDSA_P384_SHA384_ASN1,
    )
    .map_err(|_| Error::EcdsaVerify)
}

/// Returns `true` if `serial` (big-endian magnitude bytes, as returned by
/// `der`'s `UintRef::as_bytes` / the crypto crate's certificate
/// `serial_number.as_bytes()`) is listed in the CRL's `revokedCertificates`.
///
/// This performs **no** signature check — callers MUST authenticate the CRL
/// with [`verify_crl_signature`] first (see `verify_signer_chain_not_revoked`).
pub fn is_serial_revoked(crl: &[u8], serial: &[u8]) -> Result<bool, Error> {
    let der = crl_pem_to_der(crl)?;
    let crl = Crl::from_der(&der).map_err(|_| Error::ParseCertificate)?;

    Ok(crl
        .tbs_cert_list
        .revoked_certificates
        .iter()
        .flatten()
        .any(|entry| entry.user_certificate.as_bytes() == serial))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_crl_number() {
        const CRL1: &[u8] = b"-----BEGIN X509 CRL-----
MIIBITCByAIBATAKBggqhkjOPQQDAjBoMRowGAYDVQQDDBFJbnRlbCBTR1ggUm9v
dCBDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRh
IENsYXJhMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMXDTI1MDkxNjExNTMxMloX
DTI2MDkxNjExNTMxMlqgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFOnoRFJT
NlxLGJoR/EMYLKXcIIBIMAoGCCqGSM49BAMCA0gAMEUCIQDv5KEBogNCzPgupOPj
FIYJaOubypBPCGqnE0XcYTgFDwIgeSfXk71tIbV5lqp6gWCpN98/xu/8c7y36EV3
pkfootI=
-----END X509 CRL-----";

        const CRL2: &[u8] = b"-----BEGIN X509 CRL-----
MIIBKTCB0AIBATAKBggqhkjOPQQDAjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENL
IFBsYXRmb3JtIENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UE
BwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQGEwJVUxcNMjUxMTIw
MDY0ODQ5WhcNMjUxMjIwMDY0ODQ5WqAvMC0wCgYDVR0UBAMCAQEwHwYDVR0jBBgw
FoAUWSPTp0qoY1QuOXCt4A8HK1ckKrcwCgYIKoZIzj0EAwIDSAAwRQIgQB8+Xmh7
QJEvrDG15ucaA2b2pByR86M8+3mDd5g5c0sCIQD1WVRItKvP90kBT6EZp03qAOCU
IrrRoE+AsML37e56hg==
-----END X509 CRL-----";

        assert_eq!(get_crl_number(CRL1).unwrap(), 1);
        assert_eq!(get_crl_number(CRL2).unwrap(), 1);
    }

    // Fixtures generated by sh_script (P-384): a root CA that revokes a leaf
    // signer. See src/crypto/test/crl/.
    const CRL_EMPTY: &[u8] = include_bytes!("../test/crl/crl_empty.pem");
    const CRL_REVOKED: &[u8] = include_bytes!("../test/crl/crl_revoked.pem");
    // Big-endian serial magnitude of the revoked leaf (first byte 0x30 has its
    // high bit clear, so there is no DER sign-padding zero to strip).
    const LEAF_SERIAL: &[u8] = &[
        0x30, 0x2A, 0x09, 0xF6, 0x12, 0x40, 0x99, 0x78, 0xFF, 0xE6, 0x63, 0xAD, 0x71, 0xE4, 0x06,
        0xFF, 0x35, 0xE2, 0xC5, 0x3A,
    ];

    #[test]
    fn get_crl_number_parses_generated_crls() {
        // openssl `ca -gencrl` seeded crlnumber at 0x1000; revocation bumps it.
        assert_eq!(get_crl_number(CRL_EMPTY).unwrap(), 0x1000);
        assert_eq!(get_crl_number(CRL_REVOKED).unwrap(), 0x1001);
    }

    #[test]
    fn is_serial_revoked_detects_revoked_leaf() {
        assert!(is_serial_revoked(CRL_REVOKED, LEAF_SERIAL).unwrap());
    }

    #[test]
    fn is_serial_revoked_false_for_unrevoked_or_empty() {
        assert!(!is_serial_revoked(CRL_REVOKED, &[0x01, 0x02, 0x03]).unwrap());
        assert!(!is_serial_revoked(CRL_EMPTY, LEAF_SERIAL).unwrap());
    }
}
