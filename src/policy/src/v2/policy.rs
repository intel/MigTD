// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{string::String, vec::Vec};
use core::convert::TryFrom;
use serde::{Deserialize, Serialize};
use serde_json::{self, value::RawValue};

use crate::{
    parse_events,
    v2::{bytes_to_hex_string, hex_string_to_bytes, policy, verify_event_hash},
    Collaterals, EventName, PolicyError, ServtdCollateral, TdIdentity, TdTcbMapping,
};

#[derive(Debug)]
pub enum TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

impl TcbStatus {
    pub fn as_str(&self) -> &str {
        match self {
            TcbStatus::UpToDate => "UpToDate",
            TcbStatus::SWHardeningNeeded => "SWHardeningNeeded",
            TcbStatus::ConfigurationNeeded => "ConfigurationNeeded",
            TcbStatus::ConfigurationAndSWHardeningNeeded => "ConfigurationAndSWHardeningNeeded",
            TcbStatus::OutOfDate => "OutOfDate",
            TcbStatus::OutOfDateConfigurationNeeded => "OutOfDateConfigurationNeeded",
            TcbStatus::Revoked => "Revoked",
        }
    }
}

impl TryFrom<&str> for TcbStatus {
    type Error = PolicyError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "UpToDate" => Ok(TcbStatus::UpToDate),
            "SWHardeningNeeded" => Ok(TcbStatus::SWHardeningNeeded),
            "ConfigurationNeeded" => Ok(TcbStatus::ConfigurationNeeded),
            "ConfigurationAndSWHardeningNeeded" => Ok(TcbStatus::ConfigurationAndSWHardeningNeeded),
            "OutOfDate" => Ok(TcbStatus::OutOfDate),
            "OutOfDateConfigurationNeeded" => Ok(TcbStatus::OutOfDateConfigurationNeeded),
            "Revoked" => Ok(TcbStatus::Revoked),
            _ => Err(PolicyError::InvalidParameter),
        }
    }
}

/// Contains all required data to be evaluated against a policy
#[derive(Debug, Clone, Default)]
pub struct PolicyEvaluationInfo {
    /// The date of the Trusted Computing Base (TCB) in ISO-8601 format, e.g. "2023-06-19T00:00:00Z"
    pub tcb_date: Option<String>,

    /// The status of the TCB
    pub tcb_status: Option<String>,

    /// The TCB evaluation data number used to track TCB revocations and updates
    pub tcb_evaluation_number: Option<u32>,

    /// The FMSPC of platform
    pub fmspc: Option<[u8; 6]>,

    /// The status of the MigTD TCB
    pub migtd_tcb_status: Option<String>,

    /// The date of the MigTD TCB in ISO-8601 format, e.g. "2023-06-19T00:00:00Z"
    pub migtd_tcb_date: Option<String>,
}

pub struct VerifiedPolicy<'a> {
    pub policy_data: policy::PolicyData<'a>,
    pub servtd_identity: TdIdentity,
    pub servtd_identity_issuer_chain: String,
    pub servtd_tcb_mapping: TdTcbMapping,
    pub servtd_tcb_mapping_issuer_chain: String,
}

impl VerifiedPolicy<'_> {
    pub fn get_collaterals(&self) -> &Collaterals {
        &self.policy_data.collaterals
    }

    pub fn get_version(&self) -> &str {
        &self.policy_data.version
    }
}

pub fn check_policy_integrity(policy: &[u8], event_log: &[u8]) -> Result<(), PolicyError> {
    let events = parse_events(event_log).ok_or(PolicyError::InvalidEventLog)?;

    if !verify_event_hash(&events, &EventName::MigTdPolicy, policy)? {
        return Err(PolicyError::PolicyHashMismatch);
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawPolicyData<'a> {
    #[serde(borrow)]
    pub policy_data: &'a RawValue,
    pub signature: String,
}

impl<'a> RawPolicyData<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<RawPolicyData>(slice).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn get_collaterals(&self) -> Result<Collaterals, PolicyError> {
        let policy_data: PolicyData<'a> =
            serde_json::from_str(self.policy_data.get()).map_err(|_| PolicyError::InvalidPolicy)?;
        Ok(policy_data.collaterals)
    }

    pub fn verify<'c>(
        &self,
        policy_issuer_chain: &'c [u8],
        servtd_identity_issuer_chain: Option<&'c [u8]>,
        servtd_tcb_mapping_issuer_chain: Option<&'c [u8]>,
    ) -> Result<VerifiedPolicy<'a>, PolicyError> {
        // Step 1: Deserialize raw policy and verify signature
        let policy_data = self.verify_policy_data_signature(policy_issuer_chain)?;

        // Step 2: Verify and deserialize servtd collateral
        let servtd_collateral = &policy_data.servtd_collateral;
        let servtd_identity = servtd_collateral.servtd_identity.verify_signature(
            servtd_identity_issuer_chain
                .unwrap_or(servtd_collateral.servtd_identity_issuer_chain.as_bytes()),
        )?;
        let servtd_tcb_mapping = servtd_collateral.servtd_tcb_mapping.verify_signature(
            servtd_tcb_mapping_issuer_chain
                .unwrap_or(servtd_collateral.servtd_tcb_mapping_issuer_chain.as_bytes()),
        )?;

        let servtd_identity_issuer_chain = servtd_collateral.servtd_identity_issuer_chain.clone();
        let servtd_tcb_mapping_issuer_chain =
            servtd_collateral.servtd_tcb_mapping_issuer_chain.clone();

        // Step 3: Sanity checks
        if !policy_data.validate() {
            return Err(PolicyError::InvalidParameter);
        }

        Ok(VerifiedPolicy {
            policy_data,
            servtd_identity,
            servtd_identity_issuer_chain,
            servtd_tcb_mapping,
            servtd_tcb_mapping_issuer_chain,
        })
    }

    fn verify_policy_data_signature(
        &self,
        issuer_chain: &[u8],
    ) -> Result<PolicyData<'a>, PolicyError> {
        let signature = hex_string_to_bytes(&self.signature)?;

        crypto::verify_cert_chain_and_signature(
            issuer_chain,
            self.policy_data.get().as_bytes(),
            &signature,
        )
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        serde_json::from_str::<PolicyData>(self.policy_data.get())
            .map_err(|_| PolicyError::InvalidPolicy)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyData<'a> {
    id: String,
    version: String,
    policy_svn: u32,
    policy: Option<Vec<PolicyTypes>>,
    forward_policy: Option<Vec<PolicyTypes>>,
    backward_policy: Option<Vec<PolicyTypes>>,
    pub collaterals: Collaterals,
    #[serde(borrow)]
    pub servtd_collateral: ServtdCollateral<'a>,
}

impl<'a> PolicyData<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<PolicyData>(slice).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn validate(&self) -> bool {
        !self.id.is_empty() && self.version == "2.0"
    }

    pub fn evaluate_policy_forward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        match self.forward_policy.as_ref() {
            Some(policy) => Self::evaluate_policy_block(policy, value, relative_reference),
            None => Ok(()),
        }
    }

    pub fn evaluate_policy_backward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        match self.backward_policy.as_ref() {
            Some(policy) => Self::evaluate_policy_block(policy, value, relative_reference),
            None => Ok(()),
        }
    }

    pub fn evaluate_policy_common(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        match self.policy.as_ref() {
            Some(policy) => Self::evaluate_policy_block(policy, value, relative_reference),
            None => Ok(()),
        }
    }

    fn evaluate_policy_block(
        block: &Vec<PolicyTypes>,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        for policy_type in block {
            match policy_type {
                PolicyTypes::Global(global) => global.evaluate(value, relative_reference)?,
                PolicyTypes::Servtd(migtd) => migtd.evaluate(value, relative_reference)?,
            }
        }
        Ok(())
    }

    pub fn evaluate_against_policy(&self, other_policy: &PolicyData) -> Result<(), PolicyError> {
        // Check if the SVN in this policy is qualified
        if self.policy_svn < other_policy.policy_svn {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum PolicyTypes {
    Global(GlobalPolicy),
    Servtd(ServtdPolicy),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GlobalPolicy {
    tcb: Option<TcbPolicy>,
    platform: Option<PlatformPolicy>,
}

impl GlobalPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(tcb_policy) = &self.tcb {
            tcb_policy.evaluate(value, relative_reference)?;
        }

        if let Some(platform_policy) = &self.platform {
            platform_policy.evaluate(value, relative_reference)?;
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbPolicy {
    tcb_date: Option<PolicyProperty>,
    tcb_status_accepted: Option<PolicyProperty>,
    tcb_evaluation_data_number: Option<PolicyProperty>,
}

impl TcbPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.tcb_evaluation_data_number {
            if let Some(tcb_evaluation_number) = value.tcb_evaluation_number {
                if !property.evaluate_integer(
                    tcb_evaluation_number,
                    relative_reference.tcb_evaluation_number,
                )? {
                    return Err(PolicyError::TcbEvaluation);
                }
            }
        }

        if let Some(tcb_status_policy) = &self.tcb_status_accepted {
            if !tcb_status_policy.evaluate_string(
                value
                    .tcb_status
                    .as_deref()
                    .ok_or(PolicyError::TcbEvaluation)?,
                relative_reference.tcb_status.as_deref(),
            )? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        if let Some(tcb_date_policy) = &self.tcb_date {
            if !tcb_date_policy.evaluate_string(
                &value
                    .tcb_date
                    .as_deref()
                    .ok_or(PolicyError::TcbEvaluation)?,
                relative_reference.tcb_date.as_deref(),
            )? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PlatformPolicy {
    fmspc: Option<PolicyProperty>,
}

impl PlatformPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.fmspc {
            if let Some(fmspc) = value.fmspc.as_ref() {
                let relative = relative_reference
                    .fmspc
                    .as_ref()
                    .map(|s| bytes_to_hex_string(s));
                if !property.evaluate_string(&bytes_to_hex_string(fmspc), relative.as_deref())? {
                    return Err(PolicyError::TcbEvaluation);
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServtdPolicy {
    migtd_identity: MigTdIdentityPolicy,
}

impl ServtdPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.migtd_identity.tcb_date {
            if !property.evaluate_string(
                value
                    .migtd_tcb_date
                    .as_deref()
                    .ok_or(PolicyError::UnqualifiedMigTdInfo)?,
                relative_reference.migtd_tcb_date.as_deref(),
            )? {
                return Err(PolicyError::SvnMismatch);
            }
        }

        if let Some(property) = &self.migtd_identity.tcb_status_accepted {
            if !property.evaluate_string(
                value
                    .migtd_tcb_status
                    .as_deref()
                    .ok_or(PolicyError::UnqualifiedMigTdInfo)?,
                relative_reference.migtd_tcb_status.as_deref(),
            )? {
                return Err(PolicyError::SvnMismatch);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MigTdIdentityPolicy {
    pub tcb_date: Option<PolicyProperty>,
    pub tcb_status_accepted: Option<PolicyProperty>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum Reference {
    Integer(u32),
    String(String),
    IntegerList(Vec<u32>),
    StringList(Vec<String>),
}

#[derive(Serialize, Deserialize, Debug)]
struct PolicyField {
    operation: String,
    reference: Reference,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyProperty {
    pub operation: String,
    pub reference: Reference,
}

impl PolicyProperty {
    pub fn evaluate_integer(
        &self,
        value: u32,
        relative_reference: Option<u32>,
    ) -> Result<bool, PolicyError> {
        let is_in_range = |value: &u32, range: &str| -> Result<bool, PolicyError> {
            let parts = range.split("..").collect::<Vec<&str>>();
            if parts.len() != 2 {
                return Err(PolicyError::InvalidOperation);
            }
            let start = parts[0]
                .parse::<u32>()
                .map_err(|_| PolicyError::InvalidReference)?;
            let end = parts[1]
                .parse::<u32>()
                .map_err(|_| PolicyError::InvalidReference)?;

            Ok(*value >= start && *value <= end)
        };

        match &self.reference {
            Reference::Integer(reference) => match self.operation.as_str() {
                "equal" => Ok(value == *reference),
                "greater-or-equal" => Ok(value >= *reference),
                _ => return Err(PolicyError::InvalidOperation),
            },
            Reference::String(reference) => {
                if reference != "self" && reference != "init" {
                    return Err(PolicyError::InvalidReference);
                }
                let relative_reference = relative_reference.ok_or(PolicyError::InvalidReference)?;
                match self.operation.as_str() {
                    "equal" => Ok(value == relative_reference),
                    "greater-or-equal" => Ok(value >= relative_reference),
                    "in-range" => is_in_range(&value, &reference),
                    "in-time-range" => is_in_range(&value, &reference),
                    _ => Err(PolicyError::InvalidOperation),
                }
            }
            Reference::IntegerList(items) => match self.operation.as_str() {
                "subset" => Ok(items.contains(&value)),
                _ => Err(PolicyError::InvalidOperation),
            },
            _ => Err(PolicyError::InvalidReference),
        }
    }

    #[allow(unused)]
    pub fn evaluate_integer_list(
        &self,
        values: &[u32],
        relative_reference: Option<&[u32]>,
    ) -> Result<bool, PolicyError> {
        let integer_list_op = |values: &[u32], reference: &[u32]| {
            match self.operation.as_str() {
                "array-equal" => {
                    for (i, val) in values.iter().enumerate() {
                        if *val != reference[i] {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                "array-greater-or-equal" => {
                    // Each value in input must be >= corresponding value in reference at same position
                    for (i, val) in values.iter().enumerate() {
                        if *val < reference[i] {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                _ => return Err(PolicyError::InvalidOperation),
            }
        };

        match &self.reference {
            Reference::IntegerList(reference) => {
                if values.len() != reference.len() {
                    return Ok(false);
                }
                integer_list_op(values, &reference)
            }
            Reference::String(reference) => {
                if reference != "self" && reference != "init" {
                    return Err(PolicyError::InvalidReference);
                }
                let relative_reference = relative_reference.ok_or(PolicyError::InvalidReference)?;
                integer_list_op(values, relative_reference)
            }
            _ => Err(PolicyError::InvalidReference),
        }
    }

    /// Evaluate a String property against a reference value
    pub fn evaluate_string(
        &self,
        value: &str,
        relative_reference: Option<&str>,
    ) -> Result<bool, PolicyError> {
        match &self.reference {
            Reference::String(reference) => {
                let reference_value = match reference.as_str() {
                    "self" | "init" => relative_reference.ok_or(PolicyError::InvalidReference)?,
                    other => other,
                };
                match self.operation.as_str() {
                    "equal" => Ok(value == reference_value),
                    "greater-or-equal" => {
                        // Simple lexicographical comparison works for ISO-8601 format (e.g. "2025-01-01T00:00:00Z")
                        // This is because ISO-8601 is designed to be sortable as strings
                        Ok(value >= reference_value)
                    }
                    _ => Err(PolicyError::InvalidOperation),
                }
            }
            Reference::StringList(reference) => match self.operation.as_str() {
                "allow-list" => {
                    if reference.iter().any(|item| item == value) {
                        return Ok(true);
                    }
                    Ok(false)
                }
                "deny-list" => {
                    if reference.iter().any(|item| item == value) {
                        return Ok(false);
                    }
                    Ok(true)
                }
                _ => Err(PolicyError::InvalidOperation),
            },
            _ => Err(PolicyError::InvalidReference),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{string::ToString, vec};

    #[test]
    fn test_parse_policy_data() {
        let policy = include_str!("../../test/policy_v2/policy_data.json");
        assert!(serde_json::from_str::<PolicyData>(policy).is_ok());
    }

    #[test]
    fn test_verify_policy() {
        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let policy = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        let issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        policy.verify(issuer_chain, None, None).unwrap();
    }

    #[test]
    fn test_global_policy() {
        let global = include_str!("../../test/policy_v2/global.json");
        let global_policy = serde_json::from_str::<GlobalPolicy>(global).unwrap();
        let mut value = PolicyEvaluationInfo {
            tcb_date: Some("2025-09-01T00:00:00Z".to_string()),
            tcb_status: Some("UpToDate".to_string()),
            tcb_evaluation_number: Some(15),
            fmspc: Some([0x10, 0xC0, 0x6F, 0x00, 0x00, 0x00]),
            migtd_tcb_status: None,
            migtd_tcb_date: None,
        };
        let relative_ref = PolicyEvaluationInfo::default();
        assert!(global_policy.evaluate(&value, &relative_ref).is_ok());

        // Unqualified TCB date
        value.tcb_date = Some("2024-09-01T00:00:00Z".to_string());
        assert!(global_policy.evaluate(&value, &relative_ref).is_err());
        value.tcb_date = Some("2025-09-01T00:00:00Z".to_string());

        // Unqualified TCB status
        value.tcb_status = Some("Revoked".to_string());
        assert!(global_policy.evaluate(&value, &relative_ref).is_err());
        value.tcb_status = Some("ConfigurationNeeded".to_string());

        // Unqualified TCB evaluation data number
        value.tcb_evaluation_number = Some(10);
        assert!(global_policy.evaluate(&value, &relative_ref).is_err());
        value.tcb_evaluation_number = Some(15);

        // Unqualified FMSPC

        value.fmspc = Some([0x10, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(global_policy.evaluate(&value, &relative_ref).is_err());
        value.fmspc = Some([0x10, 0xC0, 0x6F, 0x00, 0x00, 0x00]);

        assert!(global_policy.evaluate(&value, &relative_ref).is_ok());
    }

    #[test]
    fn test_policy_tcb_date() {
        // Test with a value reference
        let tcb_date_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::String("2025-01-01T00:00:00Z".to_string()),
        };
        assert!(tcb_date_policy
            .evaluate_string("2025-06-15T12:00:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());
        assert!(!tcb_date_policy
            .evaluate_string("2024-01-01T00:00:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());

        // Test with "self" reference
        let tcb_date_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::String("self".to_string()),
        };
        assert!(tcb_date_policy
            .evaluate_string("2025-06-15T12:01:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());
        assert!(!tcb_date_policy
            .evaluate_string("2025-06-15T11:00:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());
    }

    #[test]
    fn test_policy_tcb_status() {
        // Test with an "allow-list" operation
        let tcb_status_policy = PolicyProperty {
            operation: "allow-list".to_string(),
            reference: Reference::StringList(vec![
                "UpToDate".to_string(),
                "SwHardeningNeeded".to_string(),
                "ConfigurationNeeded".to_string(),
            ]),
        };
        let relative_reference = "null";
        assert!(
            tcb_status_policy
                .evaluate_string("UpToDate", Some(relative_reference))
                .unwrap()
                && tcb_status_policy
                    .evaluate_string("SwHardeningNeeded", Some(relative_reference))
                    .unwrap()
                && tcb_status_policy
                    .evaluate_string("ConfigurationNeeded", Some(relative_reference))
                    .unwrap()
        );
        assert!(
            !(tcb_status_policy
                .evaluate_string("OutOfDate", Some(relative_reference))
                .unwrap()
                || tcb_status_policy
                    .evaluate_string("OutOfDateConfigurationNeeded", Some(relative_reference))
                    .unwrap()
                || tcb_status_policy
                    .evaluate_string("Revoked", Some(relative_reference))
                    .unwrap())
        );

        // Test with "deny-list" reference
        let tcb_status_policy = PolicyProperty {
            operation: "deny-list".to_string(),
            reference: Reference::StringList(vec![
                "Revoked".to_string(),
                "OutOfDateConfigurationNeeded".to_string(),
            ]),
        };
        assert!(
            tcb_status_policy
                .evaluate_string("UpToDate", Some(relative_reference))
                .unwrap()
                && tcb_status_policy
                    .evaluate_string("SwHardeningNeeded", Some(relative_reference))
                    .unwrap()
                && tcb_status_policy
                    .evaluate_string("ConfigurationNeeded", Some(relative_reference))
                    .unwrap()
                && tcb_status_policy
                    .evaluate_string("OutOfDate", Some(relative_reference))
                    .unwrap()
        );
        assert!(
            !(tcb_status_policy
                .evaluate_string("OutOfDateConfigurationNeeded", Some(relative_reference))
                .unwrap()
                || tcb_status_policy
                    .evaluate_string("Revoked", Some(relative_reference))
                    .unwrap())
        );
    }

    #[test]
    fn test_policy_tcb_evaluation_number() {
        // Test with a value reference
        let tcb_evaluation_number_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::Integer(5),
        };
        let relative_reference = u32::MAX;
        assert!(
            tcb_evaluation_number_policy
                .evaluate_integer(5, Some(relative_reference))
                .unwrap()
                && tcb_evaluation_number_policy
                    .evaluate_integer(10, Some(relative_reference))
                    .unwrap()
        );
        assert!(!tcb_evaluation_number_policy
            .evaluate_integer(4, Some(relative_reference))
            .unwrap());
    }
}
