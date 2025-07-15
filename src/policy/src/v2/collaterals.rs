// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;

use alloc::{collections::btree_map::BTreeMap, string::String, vec::Vec};
use crypto::x509::{self, AnyRef, Decode, DerResult, ObjectIdentifier, OctetStringRef, Reader};
use serde::{Deserialize, Serialize};

use crate::{v2::bytes_to_hex_string, PolicyError};

pub fn get_fmspc_from_quote(quote: &[u8]) -> Result<[u8; 6], PolicyError> {
    const PEM_CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----\n";
    const PEM_CERT_END: &str = "-----END CERTIFICATE-----\n";

    let mid = String::from_utf8_lossy(quote);
    let start_index = mid.find(PEM_CERT_BEGIN).ok_or(PolicyError::InvalidQuote)?;
    let end_index = mid.find(PEM_CERT_END).ok_or(PolicyError::InvalidQuote)? + PEM_CERT_END.len();

    let pck_cert = mid[start_index..end_index].as_bytes();
    let pck_der = crypto::pem_cert_to_der(pck_cert).map_err(|_| PolicyError::InvalidQuote)?;

    parse_fmspc_from_pck_cert(pck_der.as_ref())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InnerValue<'a> {
    pub id: ObjectIdentifier,
    pub value: Option<AnyRef<'a>>,
}

impl<'a> Decode<'a> for InnerValue<'a> {
    fn decode<R: Reader<'a>>(decoder: &mut R) -> DerResult<Self> {
        decoder.sequence(|decoder| {
            let id = decoder.decode()?;
            let value = decoder.decode()?;

            Ok(Self { id, value })
        })
    }
}

fn parse_fmspc_from_pck_cert(pck_der: &[u8]) -> Result<[u8; 6], PolicyError> {
    const PCK_FMSPC_EXTENSION_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
    const PCK_FMSPC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");

    let x509 = x509::Certificate::from_der(pck_der).map_err(|_| PolicyError::InvalidQuote)?;
    let extensions = x509
        .tbs_certificate
        .extensions
        .ok_or(PolicyError::InvalidQuote)?;
    for ext in extensions.get() {
        if ext.extn_id == PCK_FMSPC_EXTENSION_OID {
            let vals = Vec::<InnerValue>::from_der(
                ext.extn_value.ok_or(PolicyError::InvalidQuote)?.as_bytes(),
            )
            .map_err(|_| PolicyError::InvalidQuote)?;
            for val in vals {
                if val.id == PCK_FMSPC_OID {
                    return val
                        .value
                        .ok_or(PolicyError::InvalidQuote)?
                        .decode_as::<OctetStringRef>()
                        .map_err(|_| PolicyError::InvalidQuote)?
                        .as_bytes()
                        .try_into()
                        .map_err(|_| PolicyError::InvalidQuote);
                }
            }
        }
    }
    Err(PolicyError::InvalidQuote)
}

pub type Collaterals = BTreeMap<String, Collateral>;

/// Deserialize Collaterals from JSON byte slice
pub fn deserialize_collaterals(json: &[u8]) -> Result<Collaterals, PolicyError> {
    Ok(serde_json::from_slice(json).unwrap())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub tcb_info_issuer_chain: String,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    pub tcb_info: String,
}

impl Collateral {
    /// Deserialize a Collateral from JSON byte slice
    pub fn from_json_slice(json: &[u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice(json).map_err(|_| PolicyError::InvalidCollateral)
    }
}

pub fn get_collateral_with_fmspc<'a>(
    fmspc: &[u8],
    collaterals: &'a Collaterals,
) -> Result<&'a Collateral, PolicyError> {
    if fmspc.len() != 6 {
        return Err(PolicyError::InvalidParameter);
    }

    let fmspc_str = bytes_to_hex_string(fmspc);
    collaterals
        .get(&fmspc_str)
        .ok_or(PolicyError::InvalidCollateral)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformTcb {
    tcb_info: TcbInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub tcb_evaluation_data_number: u32,
}

pub fn get_tcb_evaluation_number_from_collateral(
    collateral: &Collateral,
) -> Result<u32, PolicyError> {
    let platform_tcb = serde_json::from_str::<PlatformTcb>(&collateral.tcb_info)
        .map_err(|_| PolicyError::InvalidCollateral)?;
    Ok(platform_tcb.tcb_info.tcb_evaluation_data_number)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_deserialize_collaterals() {
        let collaterals_json = include_bytes!("../../test/policy_v2/collaterals.json");
        let result = deserialize_collaterals(collaterals_json);
        assert!(result.is_ok());

        let collaterals = result.unwrap();
        assert!(!collaterals.is_empty());
    }

    #[test]
    fn test_get_collateral_with_fmspc() {
        let fmspc = [0x00, 0xC0, 0x6F, 0x00, 0x00, 0x00];
        let collaterals_bytes = include_bytes!("../../test/policy_v2/collaterals.json");
        let collaterals = deserialize_collaterals(collaterals_bytes).unwrap();

        let result = get_collateral_with_fmspc(&fmspc, &collaterals);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_tcb_evaluation_number_from_collateral() {
        let collaterals_json = include_bytes!("../../test/policy_v2/collaterals.json");
        let collaterals = deserialize_collaterals(collaterals_json).unwrap();

        let collateral = collaterals.get("20C06F000000").unwrap();
        let tcb_evaluation_number = get_tcb_evaluation_number_from_collateral(collateral);

        assert!(tcb_evaluation_number.is_ok());
        assert_eq!(tcb_evaluation_number.unwrap(), 5);
    }
}
