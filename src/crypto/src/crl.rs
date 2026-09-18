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

pub fn get_crl_issuer_der(crl: &[u8]) -> Result<Vec<u8>, Error> {
    let der = crl_pem_to_der(crl)?;
    let crl = Crl::from_der(&der).map_err(|_| Error::ParseCertificate)?;
    crl.tbs_cert_list
        .issuer
        .to_der()
        .map_err(|_| Error::ParseCertificate)
}

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
    use crate::crl_test_data as fixtures;

    fn public_key(chain_pem: &[u8]) -> Vec<u8> {
        let chain = crate::extract_cert_chain_from_pem(chain_pem).unwrap();
        let certificate = crate::x509::Certificate::from_der(chain[0].as_ref()).unwrap();
        crate::extract_public_key_from_cert(&certificate).unwrap()
    }

    #[test]
    fn test_servtd_crl_signature() {
        let issuer_key = public_key(fixtures::ISSUER_CERT);
        for crl in [
            fixtures::EMPTY_CRL,
            fixtures::REVOKED_POLICY_CRL,
            fixtures::REVOKED_IDENTITY_CRL,
            fixtures::NO_NUMBER_CRL,
        ] {
            verify_crl_signature(crl, &issuer_key).unwrap();
        }
        verify_crl_signature(
            fixtures::REVOKED_ISSUER_CRL,
            &public_key(fixtures::ROOT_CERT),
        )
        .unwrap();
        verify_crl_signature(fixtures::ROOT_EMPTY_CRL, &public_key(fixtures::ROOT_CERT)).unwrap();
        verify_crl_signature(fixtures::NON_CA_CRL, &public_key(fixtures::POLICY_CHAIN)).unwrap();

        assert!(matches!(
            verify_crl_signature(fixtures::TAMPERED_CRL, &issuer_key),
            Err(Error::EcdsaVerify)
        ));
        assert!(matches!(
            verify_crl_signature(fixtures::EMPTY_CRL, &public_key(fixtures::ROOT_CERT)),
            Err(Error::EcdsaVerify)
        ));
    }

    #[test]
    fn test_servtd_crl_issuer() {
        let issuer_der = crate::pem_cert_to_der(fixtures::ISSUER_CERT).unwrap();
        let issuer = crate::x509::Certificate::from_der(issuer_der.as_ref()).unwrap();
        let subject = issuer.tbs_certificate.subject.to_der().unwrap();

        assert_eq!(get_crl_issuer_der(fixtures::EMPTY_CRL).unwrap(), subject);
        assert_ne!(
            get_crl_issuer_der(fixtures::UNRELATED_CRL).unwrap(),
            subject
        );
    }

    #[test]
    fn test_servtd_crl_serials() {
        assert!(is_serial_revoked(fixtures::REVOKED_POLICY_CRL, &[0x80]).unwrap());
        assert!(!is_serial_revoked(fixtures::REVOKED_POLICY_CRL, &[0x81]).unwrap());
        assert!(is_serial_revoked(fixtures::REVOKED_IDENTITY_CRL, &[0x81]).unwrap());
        assert!(is_serial_revoked(fixtures::REVOKED_ISSUER_CRL, &[2]).unwrap());
        assert!(!is_serial_revoked(fixtures::EMPTY_CRL, &[0x80]).unwrap());

        assert_eq!(get_crl_number(fixtures::EMPTY_CRL).unwrap(), 7);
        assert_eq!(get_crl_number(fixtures::REVOKED_POLICY_CRL).unwrap(), 8);
        assert!(matches!(
            get_crl_number(fixtures::NO_NUMBER_CRL),
            Err(Error::CrlNumberNotFound)
        ));
    }

    #[test]
    fn test_servtd_crl_rejects_empty_input() {
        assert!(matches!(get_crl_issuer_der(b""), Err(Error::DecodePemCert)));
        assert!(matches!(
            verify_crl_signature(b"", &public_key(fixtures::ISSUER_CERT)),
            Err(Error::DecodePemCert)
        ));
        assert!(matches!(
            is_serial_revoked(b"", &[0x80]),
            Err(Error::DecodePemCert)
        ));
    }

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
}
