// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::x509::{Extension, Time};
use crate::Error;
use alloc::vec::Vec;
use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier};
use der::{Choice, Decode, Encode, ErrorKind, Header, Sequence, Tag, TagMode, TagNumber, Tagged};
use rustls_pemfile::Item;

const CRL_NUMBER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.20");

#[derive(Sequence)]
pub struct Crl<'a> {
    tbs_cert_list: TbsCertList<'a>,
    signature_algorithm: AnyRef<'a>,
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
    user_certificate: AnyRef<'a>,
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
    let crl_der = match rustls_pemfile::read_one_from_slice(crl) {
        Ok(Some((Item::Crl(data), _))) => data.to_vec(),
        Ok(Some(_)) | Ok(None) | Err(_) => return Err(Error::DecodePemCert),
    };

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
}
