// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use serde_json::{self, value::RawValue};

use crate::{
    v2::{bytes_to_hex_string, hex_string_to_bytes},
    MigTdInfoProperty, PolicyError, Report,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedServtdCollateral {
    pub servtd_identity: TdIdentity,
    pub servtd_tcb_mapping: TdTcbMapping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServtdCollateral<'a> {
    pub major_version: u32,
    pub minor_version: u32,
    pub servtd_identity_issuer_chain: String,
    #[serde(borrow)]
    pub servtd_identity: RawServtdIdentity<'a>,
    pub servtd_tcb_mapping_issuer_chain: String,
    pub servtd_tcb_mapping: RawServtdTcbMapping<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawServtdIdentity<'a> {
    #[serde(borrow)]
    pub td_identity: &'a RawValue,
    pub signature: String,
}

impl<'a> RawServtdIdentity<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<RawServtdIdentity>(slice)
            .map_err(|_| PolicyError::InvalidEngineSvnMap)
    }

    pub fn verify_signature(&self, issuer_chain: &[u8]) -> Result<TdIdentity, PolicyError> {
        let signature = hex_string_to_bytes(&self.signature)?;

        crypto::verify_cert_chain_and_signature(
            issuer_chain,
            self.td_identity.get().as_bytes(),
            &signature,
        )
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        serde_json::from_str::<TdIdentity>(self.td_identity.get())
            .map_err(|_| PolicyError::InvalidPolicy)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_evaluation_number: u32,
    pub xfam: String,
    pub attributes: String,
    pub mr_config_id: String,
    pub mr_owner: String,
    pub mr_owner_config: String,
    pub mrsigner: String,
    pub isv_prod_id: u16,
    pub tcb_levels: Vec<TcbLevel>,
}

impl TdIdentity {
    pub fn deserialize_from_json(slice: &[u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<TdIdentity>(slice).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn get_tcb_level_by_svn(&self, svn: u16) -> Option<&TcbLevel> {
        for level in &self.tcb_levels {
            if level.tcb.isvsvn == svn {
                return Some(level);
            }
        }
        None
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: String,
    pub tcb_status: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tcb {
    pub isvsvn: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawServtdTcbMapping<'a> {
    #[serde(borrow)]
    pub td_tcb_mapping: &'a RawValue,
    pub signature: String,
}

impl<'a> RawServtdTcbMapping<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<RawServtdTcbMapping>(slice)
            .map_err(|_| PolicyError::InvalidEngineSvnMap)
    }

    pub fn verify_signature(&self, issuer_chain: &[u8]) -> Result<TdTcbMapping, PolicyError> {
        let signature = hex_string_to_bytes(&self.signature)?;

        crypto::verify_cert_chain_and_signature(
            issuer_chain,
            self.td_tcb_mapping.get().as_bytes(),
            &signature,
        )
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        serde_json::from_str::<TdTcbMapping>(self.td_tcb_mapping.get())
            .map_err(|_| PolicyError::InvalidPolicy)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdTcbMapping {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub mr_signer: String,
    pub isv_prod_id: u16,
    pub svn_mappings: Vec<SvnMapping>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SvnMapping {
    pub td_measurements: Measurements,
    pub isvsvn: u16,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Measurements {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: Option<String>,
    pub rtmr3: Option<String>,
}

impl TdTcbMapping {
    pub fn get_engine_svn_by_report(&self, report: &Report) -> Option<u16> {
        let measurements = Measurements {
            mrtd: bytes_to_hex_string(
                report
                    .get_migtd_info_property(&MigTdInfoProperty::MrTd)
                    .ok()?,
            ),
            rtmr0: bytes_to_hex_string(
                report
                    .get_migtd_info_property(&MigTdInfoProperty::Rtmr0)
                    .ok()?,
            ),
            rtmr1: bytes_to_hex_string(
                report
                    .get_migtd_info_property(&MigTdInfoProperty::Rtmr1)
                    .ok()?,
            ),
            rtmr2: Some(bytes_to_hex_string(
                report
                    .get_migtd_info_property(&MigTdInfoProperty::Rtmr2)
                    .ok()?,
            )),
            rtmr3: Some(bytes_to_hex_string(
                report
                    .get_migtd_info_property(&MigTdInfoProperty::Rtmr3)
                    .ok()?,
            )),
        };
        self.get_engine_svn_by_measurements(&measurements)
    }

    pub fn get_engine_svn_by_measurements(&self, measurements: &Measurements) -> Option<u16> {
        for mapping in &self.svn_mappings {
            if Self::compare_measurements(&mapping.td_measurements, measurements) {
                return Some(mapping.isvsvn);
            }
        }
        None
    }

    #[inline]
    fn compare_measurements(pattern: &Measurements, target: &Measurements) -> bool {
        if pattern.mrtd != target.mrtd
            || pattern.rtmr0 != target.rtmr0
            || pattern.rtmr1 != target.rtmr1
        {
            return false;
        }

        // Optional RTMR2 / RTMR3:
        // If pattern provides a value -> target must also provide and match.
        // If pattern is None -> treated as wildcard (ignore target value).
        if let Some(_) = pattern.rtmr2 {
            match (&pattern.rtmr2, &target.rtmr2) {
                (Some(p), Some(t)) if p != t => return false,
                (Some(_), None) => return false,
                _ => {}
            }
        }

        if let Some(_) = pattern.rtmr3 {
            match (&pattern.rtmr3, &target.rtmr3) {
                (Some(p), Some(t)) if p != t => return false,
                (Some(_), None) => return false,
                _ => {}
            }
        }

        true
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_engine_svn() {
        let engine_bytes = include_bytes!("../../test/policy_v2/tcb_mapping.json");
        let engine: TdTcbMapping = serde_json::from_slice(engine_bytes).unwrap();
        let mrtd = String::from("E2C7DA7CF0D93973480F0A34A6FE52A204EA81B4F1B6CD16018F5B4CAEE7B3B544A9738464A7C95E1705E20687A0ADA6");
        let rtmr0 = String::from("518923B0F955D08DA077C96AABA522B9DECEDE61C599CEA6C41889CFBEA4AE4D50529D96FE4D1AFDAFB65E7F95BF23C4");
        let rtmr1 = String::from("518923B0F955D08DA077C96AABA522B9DECEDE61C599CEA6C41889CFBEA4AE4D50529D96FE4D1AFDAFB65E7F95BF23C4");
        let rtmr3 = String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

        let mut td_measurements = Measurements {
            mrtd: mrtd.clone(),
            rtmr0,
            rtmr1,
            rtmr2: None,
            rtmr3: Some(rtmr3),
        };
        assert_eq!(
            engine.get_engine_svn_by_measurements(&td_measurements),
            Some(1)
        );

        td_measurements.mrtd = String::from("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        assert!(engine
            .get_engine_svn_by_measurements(&td_measurements)
            .is_none());
        td_measurements.mrtd = mrtd.clone();

        td_measurements.rtmr3 = None;
        assert!(engine
            .get_engine_svn_by_measurements(&td_measurements)
            .is_none());
    }

    #[test]
    fn verify_servtd_collateral_signatures() {
        let servtd_collateral = include_bytes!("../../test/policy_v2/servtd_collateral.json");
        let collateral: ServtdCollateral =
            serde_json::from_slice(servtd_collateral).expect("Failed to parse collateral");
        assert!(collateral
            .servtd_tcb_mapping
            .verify_signature(collateral.servtd_tcb_mapping_issuer_chain.as_bytes())
            .is_ok());
        assert!(collateral
            .servtd_identity
            .verify_signature(collateral.servtd_tcb_mapping_issuer_chain.as_bytes())
            .is_ok());
    }
}
