// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{string::String, vec::Vec};
use core::convert::{TryFrom, TryInto};
use serde::{Deserialize, Serialize};
use serde_json::{self, value::RawValue};

use crate::{
    parse_events,
    v2::{bytes_to_hex_string, ecdsa_der_pubkey_to_raw, hex_string_to_bytes, verify_event_hash},
    EventName, PolicyError,
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

/// Contains all required data to verify a policy
#[derive(Debug, Clone)]
pub struct PolicyEvaluationInfo {
    /// The date of the Trusted Computing Base (TCB) in ISO-8601 format, e.g. "2023-06-19T00:00:00Z"
    pub tcb_date: Option<String>,

    /// The status of the TCB
    pub tcb_status: Option<String>,

    /// The TCB evaluation data number used to track TCB revocations and updates
    pub tcb_evaluation_number: Option<u32>,

    /// The engine SVN
    pub engine_svn: Option<u32>,
}

pub fn verify_policy_signature<'a>(
    policy: &'a [u8],
    public_key: &[u8],
) -> Result<PartialMigPolicy<'a>, PolicyError> {
    let partial_mig_policy = PartialMigPolicy::deserialize_from_json(policy)?;

    let signature_bytes = hex_string_to_bytes(
        partial_mig_policy
            .signature
            .as_ref()
            .ok_or(PolicyError::SignatureVerificationFailed)?,
    )?;
    let public_key = ecdsa_der_pubkey_to_raw(public_key)?;

    crypto::ecdsa::ecdsa_verify_with_raw_public_key(
        &public_key,
        partial_mig_policy.policy.get().as_bytes(),
        &signature_bytes,
    )
    .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    Ok(partial_mig_policy)
}

pub fn verify_policy_integrity(
    policy: &[u8],
    public_key: &[u8],
    event_log: &[u8],
) -> Result<MigPolicy, PolicyError> {
    let partial_mig_policy = verify_policy_signature(policy, public_key)?;
    let events = parse_events(event_log).ok_or(PolicyError::InvalidEventLog)?;

    if !verify_event_hash(
        &events,
        &EventName::MigTdEngine,
        partial_mig_policy.policy.get().as_bytes(),
    )? {
        return Err(PolicyError::InvalidEngineSvnMap);
    }
    partial_mig_policy.try_into()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialMigPolicy<'a> {
    #[serde(borrow)]
    policy: &'a RawValue,
    signature: Option<String>,
}

impl<'a> PartialMigPolicy<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<PartialMigPolicy>(slice).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn sign(&mut self, signing_key: &[u8]) -> Result<(), PolicyError> {
        let signature = crypto::ecdsa::ecdsa_sign(self.policy.get().as_bytes(), signing_key)
            .map_err(|_| PolicyError::Crypto)?;
        self.signature = Some(bytes_to_hex_string(&signature));

        Ok(())
    }
}

impl TryInto<MigPolicy> for PartialMigPolicy<'_> {
    type Error = PolicyError;
    fn try_into(self) -> Result<MigPolicy, Self::Error> {
        let policy =
            serde_json::from_str(self.policy.get()).map_err(|_| PolicyError::InvalidPolicy)?;
        Ok(MigPolicy {
            policy,
            signature: self.signature.ok_or(PolicyError::InvalidPolicy)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigPolicy {
    policy: Policy,
    signature: String,
}

impl MigPolicy {
    pub fn deserialize_from_json(json: &[u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<MigPolicy>(json).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn validate(&self) -> bool {
        if self.policy.id.is_empty() || self.policy.version.is_empty() {
            return false;
        }

        self.policy
            .common_policy
            .as_ref()
            .is_none_or(|common| MigPolicy::validate_policy_block(&common, PolicyBlockType::Common))
            && self.policy.forward_policy.as_ref().is_none_or(|forward| {
                MigPolicy::validate_policy_block(&forward, PolicyBlockType::Forward)
            })
            && self.policy.backward_policy.as_ref().is_none_or(|backward| {
                MigPolicy::validate_policy_block(&backward, PolicyBlockType::Backward)
            })
    }

    fn validate_policy_block(block: &Vec<PolicyTypes>, block_type: PolicyBlockType) -> bool {
        for policy_type in block {
            match policy_type {
                PolicyTypes::Global(global) => {
                    if !global
                        .tcb_number
                        .tcb_date
                        .as_ref()
                        .is_none_or(|p| p.validate(block_type))
                    {
                        return false;
                    }
                }
                PolicyTypes::MigTD(migtd) => {
                    if !migtd.migtd_identity.svn.validate(PolicyBlockType::Common) {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn evaluate_policy_forward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        match self.policy.forward_policy.as_ref() {
            Some(policy) => MigPolicy::evaluate_policy_block(policy, value, relative_reference),
            None => Ok(()),
        }
    }

    pub fn evaluate_policy_backward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        match self.policy.backward_policy.as_ref() {
            Some(policy) => MigPolicy::evaluate_policy_block(policy, value, relative_reference),
            None => Ok(()),
        }
    }

    pub fn evaluate_policy_common(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        match self.policy.common_policy.as_ref() {
            Some(policy) => MigPolicy::evaluate_policy_block(policy, value, relative_reference),
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
                PolicyTypes::MigTD(migtd) => migtd.evaluate(value, relative_reference)?,
            }
        }
        Ok(())
    }

    /// Evaluate another MigPolicy against this policy
    ///
    /// # Arguments
    /// * `other_policy` - The policy to evaluate against this one
    ///
    /// # Returns
    /// * `Ok(())` if all evaluations pass
    /// * `Err(PolicyError)` if evaluation fails or required policy blocks are missing
    pub fn evaluate_against_policy(
        &self,
        other_policy: &MigPolicy,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        // Check if required policy blocks exist in both policies
        if self.policy.common_policy.is_some() && other_policy.policy.common_policy.is_none() {
            return Err(PolicyError::InvalidPolicy);
        }
        if self.policy.forward_policy.is_some() && other_policy.policy.forward_policy.is_none() {
            return Err(PolicyError::InvalidPolicy);
        }
        if self.policy.backward_policy.is_some() && other_policy.policy.backward_policy.is_none() {
            return Err(PolicyError::InvalidPolicy);
        }

        // Evaluate common policy if it exists
        if let Some(_) = &self.policy.common_policy {
            let other_eval_info =
                Self::extract_policy_evaluation_info(other_policy, PolicyBlockType::Common);
            self.evaluate_policy_common(&other_eval_info, relative_reference)?;
        }

        // Evaluate forward policy if it exists
        if let Some(_) = &self.policy.forward_policy {
            let other_eval_info =
                Self::extract_policy_evaluation_info(other_policy, PolicyBlockType::Forward);
            self.evaluate_policy_forward(&other_eval_info, relative_reference)?;
        }

        // Evaluate backward policy if it exists
        if let Some(_) = &self.policy.backward_policy {
            let other_eval_info =
                Self::extract_policy_evaluation_info(other_policy, PolicyBlockType::Backward);
            self.evaluate_policy_backward(&other_eval_info, relative_reference)?;
        }

        Ok(())
    }

    /// Extract PolicyEvaluationInfo from a MigPolicy
    fn extract_policy_evaluation_info(
        policy: &MigPolicy,
        block_type: PolicyBlockType,
    ) -> PolicyEvaluationInfo {
        let mut tcb_date = None;
        let mut tcb_status = None;
        let mut tcb_evaluation_number = None;
        let mut engine_svn = None;

        // Helper function to extract values from a policy block
        let extract_from_block =
            |block: &Vec<PolicyTypes>| -> (Option<String>, Option<String>, Option<u32>, Option<u32>) {
                let mut date = None;
                let mut status = None;
                let mut eval_num = None;
                let mut svn = None;

                for policy_type in block {
                    match policy_type {
                        PolicyTypes::Global(global) => {
                            // Extract TCB information from GlobalPolicy
                            if let Some(ref tcb_date_prop) = global.tcb_number.tcb_date {
                                if let Reference::String(val) = &tcb_date_prop.reference {
                                    date = Some(val.clone());
                                }
                            }
                            if let Some(ref tcb_eval_prop) =
                                global.tcb_number.tcb_evaluation_data_number
                            {
                                if let Reference::Integer(val) = &tcb_eval_prop.reference {
                                    eval_num = Some(*val);
                                }
                            }
                            // For tcb_status, if it's a string list, we might need special handling
                            if let Some(ref tcb_status_prop) = global.tcb_number.tcb_status {
                                // This is simplified - you might need to handle string references differently
                                if let Reference::String(val) = &tcb_status_prop.reference {
                                    status = Some(val.clone());
                                }
                            }
                        }
                        PolicyTypes::MigTD(migtd) => {
                            // Extract SVN from MigTdPolicy
                            if let Reference::Integer(val) = &migtd.migtd_identity.svn.reference {
                                svn = Some(*val);
                            }
                        }
                    }
                }

                (date, status, eval_num, svn)
            };

        let policy_block = match block_type {
            PolicyBlockType::Common => &policy.policy.common_policy,
            PolicyBlockType::Forward => &policy.policy.forward_policy,
            PolicyBlockType::Backward => &policy.policy.backward_policy,
        };

        // Extract from policy block (as base values)
        if let Some(common) = policy_block {
            let (date, status, eval_num, svn) = extract_from_block(common);
            tcb_date = date;
            tcb_status = status;
            tcb_evaluation_number = eval_num;
            engine_svn = svn;
        }

        PolicyEvaluationInfo {
            tcb_date,
            tcb_status,
            tcb_evaluation_number,
            engine_svn,
        }
    }
}

#[derive(Clone, Copy)]
pub enum PolicyBlockType {
    Common,
    Forward,
    Backward,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    id: String,
    version: String,
    #[serde(rename = "forward-policy")]
    common_policy: Option<Vec<PolicyTypes>>,
    #[serde(rename = "forward-policy")]
    forward_policy: Option<Vec<PolicyTypes>>,
    #[serde(rename = "backward-policy")]
    backward_policy: Option<Vec<PolicyTypes>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PolicyTypes {
    Global(GlobalPolicy),
    MigTD(MigTdPolicy),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Global {
    #[serde(rename = "Global")]
    global_policy: GlobalPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalPolicy {
    #[serde(rename = "TcbNumber")]
    pub tcb_number: TcbNumberPolicy,
}

impl GlobalPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.tcb_number.tcb_evaluation_data_number {
            if let Some(tcb_evaluation_number) = value.tcb_evaluation_number {
                if !property.evaluate_integer(
                    tcb_evaluation_number,
                    relative_reference.tcb_evaluation_number,
                )? {
                    return Err(PolicyError::TcbEvaluation);
                }
            }
        }

        if let Some(tcb_status_policy) = &self.tcb_number.tcb_status {
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

        if let Some(tcb_date_policy) = &self.tcb_number.tcb_date {
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
#[serde(rename_all = "camelCase")]
pub struct TcbNumberPolicy {
    pub tcb_date: Option<PolicyProperty>,
    pub tcb_status: Option<PolicyProperty>,
    pub tcb_evaluation_data_number: Option<PolicyProperty>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigTd {
    #[serde(rename = "MigTD")]
    pub migtd_policy: MigTdPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigTdPolicy {
    #[serde(rename = "MigTdIdentity")]
    pub migtd_identity: MigTdIdentityPolicy,
}

impl MigTdPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if !self.migtd_identity.svn.evaluate_integer(
            value.engine_svn.ok_or(PolicyError::UnqulifiedMigTdInfo)?,
            relative_reference.engine_svn,
        )? {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigTdIdentityPolicy {
    #[serde(rename = "SVN")]
    pub svn: PolicyProperty,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Reference {
    Integer(u32),
    String(String),
    IntegerList(Vec<u32>),
    StringList(Vec<String>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyField {
    operation: String,
    reference: Reference,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyProperty {
    pub operation: String,
    pub reference: Reference,
}

impl PolicyProperty {
    pub fn validate(&self, block_type: PolicyBlockType) -> bool {
        if self.operation.is_empty() {
            return false;
        }
        match &self.reference {
            Reference::String(s) => {
                if s.is_empty() {
                    return false;
                }

                // Check reference string based on policy block type
                match block_type {
                    PolicyBlockType::Common => s != "self" && s != "init",
                    PolicyBlockType::Forward => s != "init",
                    PolicyBlockType::Backward => s != "self",
                }
            }
            _ => true,
        }
    }

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
                if reference != "self" || reference != "init" {
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
                _ => panic!("Invalid operation"),
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
                if reference != "self" || reference != "init" {
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
    fn test_verify_policy_signature() {
        let policy_bytes = include_bytes!("../../test/policy_v2/policy.json");
        let public_key = include_bytes!("../../test/policy_v2/policy-public.der");
        verify_policy_signature(policy_bytes, public_key).unwrap();
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
