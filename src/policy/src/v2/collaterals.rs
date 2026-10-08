// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;

use alloc::{string::String, vec::Vec};
use crypto::x509::{self, AnyRef, Decode, DerResult, ObjectIdentifier, OctetStringRef, Reader};
use serde::{Deserialize, Serialize};

use crate::{v2::bytes_to_hex_string, PolicyError};

pub fn verify_migtd_servtd_hash(quote: &[u8]) -> Result<(), PolicyError> {
    const QUOTE_HEADER_SIZE: usize = 48;
    const QUOTE_V5_BODY_HEADER_SIZE: usize = 6;
    const TD_REPORT_15_BODY_TYPE: u16 = 3;
    const TD_REPORT_15_BODY_SIZE: usize = 648;
    const MR_SERVICETD_OFFSET: usize = 600;
    const MR_SERVICETD_SIZE: usize = 48;

    let version = quote
        .get(..2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(PolicyError::InvalidQuote)?;
    if version != 5 {
        return Ok(());
    }

    let body_type = quote
        .get(QUOTE_HEADER_SIZE..QUOTE_HEADER_SIZE + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(PolicyError::InvalidQuote)?;
    if body_type != TD_REPORT_15_BODY_TYPE {
        return Ok(());
    }

    let body_size = quote
        .get(QUOTE_HEADER_SIZE + 2..QUOTE_HEADER_SIZE + QUOTE_V5_BODY_HEADER_SIZE)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .map(|value| value as usize)
        .ok_or(PolicyError::InvalidQuote)?;
    if body_size != TD_REPORT_15_BODY_SIZE {
        return Err(PolicyError::InvalidQuote);
    }

    let body_offset = QUOTE_HEADER_SIZE + QUOTE_V5_BODY_HEADER_SIZE;
    let mr_servicetd = quote
        .get(
            body_offset + MR_SERVICETD_OFFSET
                ..body_offset + MR_SERVICETD_OFFSET + MR_SERVICETD_SIZE,
        )
        .ok_or(PolicyError::InvalidQuote)?;
    if mr_servicetd.iter().any(|value| *value != 0) {
        return Err(PolicyError::UnqualifiedMigTdInfo);
    }

    Ok(())
}

pub fn get_fmspc_from_quote(quote: &[u8]) -> Result<[u8; 6], PolicyError> {
    const PEM_CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----\n";
    const PEM_CERT_END: &str = "-----END CERTIFICATE-----\n";

    let mid = String::from_utf8_lossy(quote);
    let start_index = mid.find(PEM_CERT_BEGIN).ok_or(PolicyError::InvalidQuote)?;
    let end_index = mid[start_index..]
        .find(PEM_CERT_END)
        .and_then(|i| i.checked_add(start_index))
        .and_then(|i| i.checked_add(PEM_CERT_END.len()))
        .ok_or(PolicyError::InvalidQuote)?;
    if start_index >= end_index {
        return Err(PolicyError::InvalidQuote);
    }

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collaterals {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub root_ca: String,
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub platforms: Vec<Platform>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    fmspc: String,
    tcb_info_issuer_chain: String,
    tcb_info: String,
}

impl Collaterals {
    pub fn get_tcb_with_fmspc(&self, fmspc: &str) -> Option<&Platform> {
        self.platforms.iter().find(|p| p.fmspc == fmspc)
    }
}

/// Deserialize Collaterals from JSON byte slice
pub fn deserialize_collaterals(json: &[u8]) -> Result<Collaterals, PolicyError> {
    serde_json::from_slice(json).map_err(|_| PolicyError::InvalidCollateral)
}

pub struct Collateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub root_ca: String,
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
}

pub fn get_collateral_with_fmspc(
    fmspc: &[u8],
    collaterals: &Collaterals,
) -> Result<Collateral, PolicyError> {
    if fmspc.len() != 6 {
        return Err(PolicyError::InvalidParameter);
    }

    let fmspc_str = bytes_to_hex_string(fmspc);
    let platform_tcb = collaterals
        .get_tcb_with_fmspc(&fmspc_str)
        .ok_or(PolicyError::InvalidCollateral)?;

    Ok(Collateral {
        major_version: collaterals.major_version,
        minor_version: collaterals.minor_version,
        tee_type: collaterals.tee_type,
        root_ca: collaterals.root_ca.clone(),
        pck_crl_issuer_chain: collaterals.pck_crl_issuer_chain.clone(),
        root_ca_crl: collaterals.root_ca_crl.clone(),
        pck_crl: collaterals.pck_crl.clone(),
        tcb_info_issuer_chain: platform_tcb.tcb_info_issuer_chain.clone(),
        tcb_info: platform_tcb.tcb_info.clone(),
        qe_identity_issuer_chain: collaterals.qe_identity_issuer_chain.clone(),
        qe_identity: collaterals.qe_identity.clone(),
    })
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
    use alloc::vec;

    #[test]
    fn reject_nonzero_migtd_servtd_hash() {
        const BODY_OFFSET: usize = 54;
        const MR_SERVICETD_OFFSET: usize = 600;

        let mut quote = vec![0u8; BODY_OFFSET + 648];
        quote[..2].copy_from_slice(&5u16.to_le_bytes());
        quote[48..50].copy_from_slice(&3u16.to_le_bytes());
        quote[50..54].copy_from_slice(&648u32.to_le_bytes());
        assert!(verify_migtd_servtd_hash(&quote).is_ok());

        quote[BODY_OFFSET + MR_SERVICETD_OFFSET] = 1;
        assert!(matches!(
            verify_migtd_servtd_hash(&quote),
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
    }

    #[test]
    fn test_deserialize_collaterals() {
        let collaterals_json = include_bytes!("../../test/policy_v2/collaterals.json");
        let result = deserialize_collaterals(collaterals_json);
        assert!(result.is_ok());

        let collaterals = result.unwrap();
        assert!(!collaterals.platforms.is_empty());
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

        let collateral =
            get_collateral_with_fmspc(&[0x20, 0xC0, 0x6F, 0x0, 0x0, 0x0], &collaterals).unwrap();
        let tcb_evaluation_number = get_tcb_evaluation_number_from_collateral(&collateral);

        assert!(tcb_evaluation_number.is_ok());
        assert_eq!(tcb_evaluation_number.unwrap(), 5);
    }
}
