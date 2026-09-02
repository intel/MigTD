// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};
use chrono::NaiveDateTime;
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
};
use serde::{Deserialize, Serialize};
use serde_json::{self, value::RawValue};

use crate::{
    v2::{
        bytes_to_hex_string, compute_signer_anchor_from_chain_pem,
        measurement::extract_canonical_policy_data_bytes, policy, resolve_signer_anchor,
        verify_event_hash,
    },
    CcEvent, Collaterals, EventName, PolicyError, Report, ServtdCollateral, TdIdentity,
    TdTcbMapping,
};
use crypto::SHA384_DIGEST_SIZE;

#[cfg(feature = "servtd_corim")]
use crate::v2::ServtdCorim;

/// MigTD TCB information resolved from authenticated collateral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServtdLookup {
    pub isvsvn: u16,
    pub tcb_date: Option<String>,
    pub tcb_status: Option<String>,
}

#[derive(Clone, Copy, Debug)]
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

    // "UpToDate" == "SWHardeningNeeded" == "OutOfDate" >= "ConfigurationNeeded" ==
    // "ConfigurationAndSWHardeningNeeded" == "OutOfDateConfigurationNeeded” > "Revoked"
    fn rank(&self) -> u8 {
        match self {
            TcbStatus::UpToDate | TcbStatus::SWHardeningNeeded | TcbStatus::OutOfDate => 2,
            TcbStatus::ConfigurationNeeded
            | TcbStatus::ConfigurationAndSWHardeningNeeded
            | TcbStatus::OutOfDateConfigurationNeeded => 1,
            TcbStatus::Revoked => 0,
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

impl PartialOrd for TcbStatus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.rank().cmp(&other.rank()))
    }
}

impl PartialEq for TcbStatus {
    fn eq(&self, other: &Self) -> bool {
        self.rank() == other.rank()
    }
}

impl Eq for TcbStatus {}

#[derive(Clone, Copy, Debug)]
pub enum ServtdTcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
}

impl ServtdTcbStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ServtdTcbStatus::UpToDate => "UpToDate",
            ServtdTcbStatus::OutOfDate => "OutOfDate",
            ServtdTcbStatus::Revoked => "Revoked",
        }
    }

    // "UpToDate" == "OutOfDate" > "Revoked"
    fn rank(&self) -> u8 {
        match self {
            ServtdTcbStatus::UpToDate | ServtdTcbStatus::OutOfDate => 2,
            ServtdTcbStatus::Revoked => 0,
        }
    }
}

impl TryFrom<&str> for ServtdTcbStatus {
    type Error = PolicyError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "UpToDate" => Ok(ServtdTcbStatus::UpToDate),
            "OutOfDate" => Ok(ServtdTcbStatus::OutOfDate),
            "Revoked" => Ok(ServtdTcbStatus::Revoked),
            _ => Err(PolicyError::InvalidParameter),
        }
    }
}

impl PartialOrd for ServtdTcbStatus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.rank().cmp(&other.rank()))
    }
}

impl PartialEq for ServtdTcbStatus {
    fn eq(&self, other: &Self) -> bool {
        self.rank() == other.rank()
    }
}

impl Eq for ServtdTcbStatus {}

/// Contains all required data to be evaluated against a rebinding policy
#[derive(Debug, Clone, Default)]
pub struct PolicyEvaluationInfo {
    /// The TEE_TCB_SVN of MigTD
    pub tee_tcb_svn: Option<[u8; 16]>,

    /// The date of the Trusted Computing Base (TCB) in ISO-8601 format, e.g. "2023-06-19T00:00:00Z"
    pub tcb_date: Option<String>,

    /// The status of the TCB
    pub tcb_status: Option<String>,

    /// The TCB evaluation data number used to track TCB revocations and updates
    pub tcb_evaluation_number: Option<u32>,

    /// The FMSPC of platform
    pub fmspc: Option<[u8; 6]>,

    /// The isvsvn of the MigTD TCB
    pub migtd_isvsvn: Option<u16>,

    pub migtd_tcb_status: Option<String>,

    /// The date of the MigTD TCB in ISO-8601 format (from the optional TD
    /// Identity), e.g. "2023-06-19T00:00:00Z"
    pub migtd_tcb_date: Option<String>,

    /// The minimal crl_num of pck_crl
    pub pck_crl_num: Option<u32>,

    /// The minimal crl_num of root_ca_crl
    pub root_ca_crl_num: Option<u32>,

    /// The CRL number of the servTD signer CRL, used for
    /// monotonic anti-rollback of the signer revocation list.
    pub servtd_crl_num: Option<u32>,
}

pub struct VerifiedPolicy<'a> {
    pub policy_data: policy::PolicyData<'a>,
    /// JSON TCB mapping; absent for CoRIM-only policies.
    pub servtd_tcb_mapping: Option<TdTcbMapping>,
    /// JSON mapping signer chain retained for CRL checks.
    pub servtd_tcb_mapping_issuer_chain: Option<String>,
    /// Optional JSON TD Identity for date and status lookup.
    pub servtd_identity: Option<TdIdentity>,
    /// JSON TD Identity signer chain retained for CRL checks.
    pub servtd_identity_issuer_chain: Option<String>,
    /// Optional PEM CRL for the servTD signer chain, from
    /// `servtdCollateral.servtdCrl`. Retained so the runtime can cross-check a
    /// peer's signer chain against the local trusted CRL.
    pub servtd_crl: Option<String>,
    /// The RTMR1 signer anchor `A = SHA384(tag ‖ H(rootDER) ‖ leafEkuOidDER)`
    /// used to authenticate peer collateral.
    pub signer_anchor: [u8; SHA384_DIGEST_SIZE],
    /// Optional CoRIM-encoded servtd collateral. When attached it is the sole
    /// authority for servtd lookups (fail-closed: a CoRIM miss is a miss,
    /// with no fallback to the legacy JSON collateral). Only available with
    /// the `servtd_corim` feature.
    #[cfg(feature = "servtd_corim")]
    servtd_corim: Option<ServtdCorim>,
}

impl VerifiedPolicy<'_> {
    pub fn get_collaterals(&self) -> &Collaterals {
        &self.policy_data.collaterals
    }

    pub fn get_version(&self) -> &str {
        &self.policy_data.version
    }

    /// Attach decoded CoRIM servtd collateral. Once set, **all** servtd
    /// lookups resolve against the CoRIM and the legacy JSON collateral is no
    /// longer consulted.
    #[cfg(feature = "servtd_corim")]
    pub fn set_servtd_corim(&mut self, corim: ServtdCorim) {
        self.servtd_corim = Some(corim);
    }

    /// Resolve a TDINFO hash through the CoRIM, or through the JSON mapping and
    /// optional TD Identity when no CoRIM is attached.
    pub fn servtd_lookup_by_tdinfo_hash(&self, tdinfo_hash: &[u8]) -> Option<ServtdLookup> {
        #[cfg(feature = "servtd_corim")]
        if let Some(corim) = &self.servtd_corim {
            return corim.lookup_by_tdinfo_hash(tdinfo_hash);
        }
        let isvsvn = self
            .servtd_tcb_mapping
            .as_ref()?
            .get_engine_svn_by_tdinfo_hash(tdinfo_hash)?;
        let (tcb_date, tcb_status) = match &self.servtd_identity {
            Some(identity) => {
                let level = identity.get_tcb_level_by_svn(isvsvn)?;
                (Some(level.tcb_date.clone()), Some(level.tcb_status.clone()))
            }
            None => (None, None),
        };
        Some(ServtdLookup {
            isvsvn,
            tcb_date,
            tcb_status,
        })
    }

    /// Resolve the TDINFO hash in a verified report.
    pub fn servtd_lookup_by_report(&self, report: &Report) -> Option<ServtdLookup> {
        let hash = crate::v2::compute_tdinfo_hash_from_report(report).ok()?;
        self.servtd_lookup_by_tdinfo_hash(&hash)
    }
}

pub fn check_policy_integrity(
    policy: &[u8],
    events: &BTreeMap<EventName, CcEvent>,
) -> Result<(), PolicyError> {
    let policy_data_bytes = extract_canonical_policy_data_bytes(policy)?;
    if !verify_event_hash(events, &EventName::MigTdPolicyData, &policy_data_bytes)? {
        return Err(PolicyError::PolicyHashMismatch);
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawPolicyData<'a> {
    #[serde(borrow)]
    pub policy_data: &'a RawValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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

    /// Verify the servtd collateral using the given (RTMR1-anchored) issuer
    /// chain.
    pub fn verify(&self, issuer_chain: &[u8]) -> Result<VerifiedPolicy<'a>, PolicyError> {
        let cfv_anchor = resolve_signer_anchor(issuer_chain)?;

        let policy_data: PolicyData<'a> =
            serde_json::from_str(self.policy_data.get()).map_err(|_| PolicyError::InvalidPolicy)?;

        let (
            servtd_tcb_mapping,
            servtd_tcb_mapping_issuer_chain,
            servtd_identity,
            servtd_identity_issuer_chain,
            servtd_crl,
        ) = match &policy_data.servtd_collateral {
            Some(servtd_collateral) => {
                let servtd_tcb_mapping = servtd_collateral.servtd_tcb_mapping.verify_signature(
                    servtd_collateral.servtd_tcb_mapping_issuer_chain.as_bytes(),
                )?;

                // Identity and its signer chain must be present together.
                let servtd_identity = match (
                    servtd_collateral.servtd_identity.as_ref(),
                    servtd_collateral.servtd_identity_issuer_chain.as_deref(),
                ) {
                    (Some(raw_identity), Some(identity_chain)) => {
                        Some(raw_identity.verify_signature(identity_chain.as_bytes())?)
                    }
                    (None, None) => None,
                    _ => return Err(PolicyError::InvalidServtdIdentity),
                };

                let mapping_anchor = compute_signer_anchor_from_chain_pem(
                    servtd_collateral.servtd_tcb_mapping_issuer_chain.as_bytes(),
                )?;
                if cfv_anchor != mapping_anchor {
                    return Err(PolicyError::SignerAnchorMismatch);
                }

                // The optional TD Identity issuer chain is redacted from RTMR2
                // too, so bind it to the same RTMR1 signer anchor when present.
                if let Some(identity_chain) =
                    servtd_collateral.servtd_identity_issuer_chain.as_deref()
                {
                    let identity_anchor =
                        compute_signer_anchor_from_chain_pem(identity_chain.as_bytes())?;
                    if cfv_anchor != identity_anchor {
                        return Err(PolicyError::SignerAnchorMismatch);
                    }
                }

                // Signer-key revocation (fail-closed).
                if let Some(servtd_crl) = servtd_collateral.servtd_crl.as_deref() {
                    crypto::verify_signer_chain_not_revoked(
                        servtd_collateral.servtd_tcb_mapping_issuer_chain.as_bytes(),
                        servtd_crl.as_bytes(),
                    )
                    .map_err(|_| PolicyError::SignerRevoked)?;
                    if let Some(identity_chain) =
                        servtd_collateral.servtd_identity_issuer_chain.as_deref()
                    {
                        crypto::verify_signer_chain_not_revoked(
                            identity_chain.as_bytes(),
                            servtd_crl.as_bytes(),
                        )
                        .map_err(|_| PolicyError::SignerRevoked)?;
                    }
                }

                (
                    Some(servtd_tcb_mapping),
                    Some(servtd_collateral.servtd_tcb_mapping_issuer_chain.clone()),
                    servtd_identity,
                    servtd_collateral.servtd_identity_issuer_chain.clone(),
                    servtd_collateral.servtd_crl.clone(),
                )
            }
            None => (None, None, None, None, None),
        };

        if !policy_data.validate() {
            return Err(PolicyError::InvalidParameter);
        }

        Ok(VerifiedPolicy {
            policy_data,
            servtd_tcb_mapping,
            servtd_tcb_mapping_issuer_chain,
            servtd_identity,
            servtd_identity_issuer_chain,
            servtd_crl,
            signer_anchor: cfv_anchor,
            #[cfg(feature = "servtd_corim")]
            servtd_corim: None,
        })
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
    /// JSON servTD collateral, absent for CoRIM-only policies.
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub servtd_collateral: Option<ServtdCollateral<'a>>,
}

impl<'a> PolicyData<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<PolicyData>(slice).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn validate(&self) -> bool {
        !self.id.is_empty() && self.version == "2.0"
    }

    pub fn get_policy_svn(&self) -> u32 {
        self.policy_svn
    }

    pub fn evaluate_policy_forward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
        skip_global: bool,
    ) -> Result<(), PolicyError> {
        Self::evaluate_policy_block(
            self.forward_policy.as_ref(),
            value,
            relative_reference,
            skip_global,
        )
    }

    pub fn evaluate_policy_backward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
        skip_global: bool,
    ) -> Result<(), PolicyError> {
        Self::evaluate_policy_block(
            self.backward_policy.as_ref(),
            value,
            relative_reference,
            skip_global,
        )
    }

    pub fn evaluate_policy_common(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
        skip_global: bool,
    ) -> Result<(), PolicyError> {
        Self::evaluate_policy_block(self.policy.as_ref(), value, relative_reference, skip_global)
    }

    fn evaluate_policy_block(
        block: Option<&Vec<PolicyTypes>>,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
        skip_global: bool,
    ) -> Result<(), PolicyError> {
        // Apply explicit policy constraints, if present.
        if let Some(block) = block {
            for policy_type in block {
                match policy_type {
                    PolicyTypes::Global(global) if !skip_global => {
                        global.evaluate(value, relative_reference)?
                    }
                    PolicyTypes::Servtd(migtd) => migtd.evaluate(value, relative_reference)?,
                    _ => {}
                }
            }
        }

        // Always enforce mandatory deny checks, even if a policy block is absent.
        Self::enforce_mandatory_deny(value, skip_global)?;

        Ok(())
    }

    /// Enforce non-optional deny checks.
    ///
    /// Reject `Revoked` platform status when global checks are enabled.
    /// Always check engine status; treat unknown (`None`) as denied.
    fn enforce_mandatory_deny(
        value: &PolicyEvaluationInfo,
        skip_global: bool,
    ) -> Result<(), PolicyError> {
        if !skip_global {
            if let Some(status) = value.tcb_status.as_deref() {
                if TcbStatus::try_from(status)? == TcbStatus::Revoked {
                    return Err(PolicyError::TcbEvaluation);
                }
            }
        }

        // Engine status must be known; fail closed on `None`.
        match value.migtd_tcb_status.as_deref() {
            Some(status) => {
                if ServtdTcbStatus::try_from(status)? == ServtdTcbStatus::Revoked {
                    return Err(PolicyError::SvnMismatch);
                }
            }
            None => return Err(PolicyError::UnqualifiedMigTdInfo),
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
    crl: Option<CrlPolicy>,
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

        if let Some(crl_policy) = &self.crl {
            crl_policy.evaluate(value, relative_reference)?;
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
            let tcb_evaluation_number = value
                .tcb_evaluation_number
                .ok_or(PolicyError::TcbEvaluation)?;
            if !property.evaluate_integer(
                tcb_evaluation_number,
                relative_reference.tcb_evaluation_number,
            )? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        if let Some(tcb_status_policy) = &self.tcb_status_accepted {
            if !tcb_status_policy.evaluate_tcb_status(
                value
                    .tcb_status
                    .as_deref()
                    .and_then(|s| s.try_into().ok())
                    .ok_or(PolicyError::TcbEvaluation)?,
                relative_reference
                    .tcb_status
                    .as_deref()
                    .and_then(|s| s.try_into().ok()),
            )? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        if let Some(tcb_date_policy) = &self.tcb_date {
            if !tcb_date_policy.evaluate_string(
                value
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
            let fmspc = value.fmspc.as_ref().ok_or(PolicyError::TcbEvaluation)?;
            let relative = relative_reference
                .fmspc
                .as_ref()
                .map(|s| bytes_to_hex_string(s));
            if !property.evaluate_string(&bytes_to_hex_string(fmspc), relative.as_deref())? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CrlPolicy {
    pck_crl_num: Option<PolicyProperty>,
    root_ca_crl_num: Option<PolicyProperty>,
    servtd_crl_num: Option<PolicyProperty>,
}

impl CrlPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.pck_crl_num {
            let pck_crl_num = value.pck_crl_num.ok_or(PolicyError::CrlEvaluation)?;
            if !property.evaluate_integer(pck_crl_num, relative_reference.pck_crl_num)? {
                return Err(PolicyError::CrlEvaluation);
            }
        }

        if let Some(property) = &self.root_ca_crl_num {
            let root_ca_crl_num = value.root_ca_crl_num.ok_or(PolicyError::CrlEvaluation)?;
            if !property.evaluate_integer(root_ca_crl_num, relative_reference.root_ca_crl_num)? {
                return Err(PolicyError::CrlEvaluation);
            }
        }

        if let Some(property) = &self.servtd_crl_num {
            let servtd_crl_num = value.servtd_crl_num.ok_or(PolicyError::CrlEvaluation)?;
            if !property.evaluate_integer(servtd_crl_num, relative_reference.servtd_crl_num)? {
                return Err(PolicyError::CrlEvaluation);
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
        if let Some(property) = &self.migtd_identity.isvsvn {
            if !property.evaluate_integer(
                value
                    .migtd_isvsvn
                    .map(|v| v as u32)
                    .ok_or(PolicyError::UnqualifiedMigTdInfo)?,
                relative_reference.migtd_isvsvn.map(|v| v as u32),
            )? {
                return Err(PolicyError::SvnMismatch);
            }
        }

        // Date and status constraints require a TD Identity.
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
            if !property.evaluate_servtd_tcb_status(
                value
                    .migtd_tcb_status
                    .as_deref()
                    .and_then(|s| s.try_into().ok())
                    .ok_or(PolicyError::UnqualifiedMigTdInfo)?,
                relative_reference
                    .migtd_tcb_status
                    .as_deref()
                    .and_then(|s| s.try_into().ok()),
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
    pub isvsvn: Option<PolicyProperty>,
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

/// Returns true only for a canonical, fixed-width ISO-8601 UTC timestamp of the
/// exact form "YYYY-MM-DDTHH:MM:SSZ" (e.g. "2025-01-01T00:00:00Z"). Lexicographic
/// ordering of date strings is only valid under this canonical form, so callers
/// that compare dates with `>=` must reject anything else.
fn is_canonical_iso8601(s: &str) -> bool {
    const FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

    NaiveDateTime::parse_from_str(s, FORMAT)
        .map(|timestamp| timestamp.format(FORMAT).to_string() == s)
        .unwrap_or(false)
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
                _ => Err(PolicyError::InvalidOperation),
            },
            Reference::String(reference) => {
                if reference == "self" || reference == "init" {
                    let relative_reference =
                        relative_reference.ok_or(PolicyError::InvalidReference)?;
                    match self.operation.as_str() {
                        "equal" => Ok(value == relative_reference),
                        "greater-or-equal" => Ok(value >= relative_reference),
                        _ => Err(PolicyError::InvalidOperation),
                    }
                } else {
                    match self.operation.as_str() {
                        "in-range" | "in-time-range" => is_in_range(&value, reference),
                        _ => Err(PolicyError::InvalidOperation),
                    }
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
            if values.len() != reference.len() {
                return Ok(false);
            }
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
                _ => Err(PolicyError::InvalidOperation),
            }
        };

        match &self.reference {
            Reference::IntegerList(reference) => integer_list_op(values, reference),
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
                        // The lexicographical comparison below is only correct when both
                        // operands are canonical, fixed-width ISO-8601 timestamps (e.g.
                        // "2025-01-01T00:00:00Z"). A non-canonical value such as "2024-9-1"
                        // would sort incorrectly (byte '9' > '1'), so reject anything that is
                        // not in the canonical form before comparing, failing closed.
                        if !is_canonical_iso8601(value) || !is_canonical_iso8601(reference_value) {
                            return Err(PolicyError::InvalidReference);
                        }
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

    /// Evaluate a TcbStatus property against a reference value
    fn evaluate_tcb_status(
        &self,
        value: TcbStatus,
        relative_reference: Option<TcbStatus>,
    ) -> Result<bool, PolicyError> {
        // "UpToDate" is always allowed.
        // "SWHardeningNeeded" is always allowed, because the information is missing when the state
        // is moved to "OutOfDate".
        // "OutOfDate" is always allowed, because time stamp is not trusted.
        const ALWAYS_ALLOW: &[TcbStatus] = &[
            TcbStatus::UpToDate,
            TcbStatus::OutOfDate,
            TcbStatus::SWHardeningNeeded,
        ];
        // "Revoked" is always denied.
        const ALWAYS_DENY: &[TcbStatus] = &[TcbStatus::Revoked];

        if ALWAYS_DENY.contains(&value) {
            return Ok(false);
        }

        if ALWAYS_ALLOW.contains(&value) {
            return Ok(true);
        }

        match &self.reference {
            Reference::String(reference) => {
                let reference_value = match reference.as_str() {
                    "self" | "init" => relative_reference.ok_or(PolicyError::InvalidReference)?,
                    other => TcbStatus::try_from(other)?,
                };
                match self.operation.as_str() {
                    "equal" => Ok(value == reference_value),
                    "greater-or-equal" => Ok(value >= reference_value),
                    _ => Err(PolicyError::InvalidOperation),
                }
            }
            Reference::StringList(reference) => {
                let mut policy_allow = Vec::new();
                match self.operation.as_str() {
                    "allow-list" => {
                        for item in reference {
                            // Check if this is a valid reference.
                            let _ = TcbStatus::try_from(item.as_str())?;
                            // Compare the raw string instead of the parsed TcbStatus because
                            // ConfigurationNeeded, ConfigurationAndSWHardeningNeeded, and
                            // OutOfDateConfigurationNeeded all rank-equal under PartialEq.
                            if item == TcbStatus::ConfigurationNeeded.as_str() {
                                policy_allow.push(TcbStatus::ConfigurationNeeded);
                                policy_allow.push(TcbStatus::ConfigurationAndSWHardeningNeeded);
                                policy_allow.push(TcbStatus::OutOfDateConfigurationNeeded);
                            }
                        }
                    }
                    "deny-list" => {
                        // Check if this is a valid reference.
                        let _ = reference
                            .iter()
                            .map(|item| TcbStatus::try_from(item.as_str()))
                            .collect::<Result<Vec<_>, _>>()?;
                        // All TCB statuses that are not in the `ALWAYS_ALLOW` list will be denied.
                    }
                    _ => return Err(PolicyError::InvalidOperation),
                }
                Ok(policy_allow.contains(&value))
            }
            _ => Err(PolicyError::InvalidReference),
        }
    }

    fn evaluate_servtd_tcb_status(
        &self,
        value: ServtdTcbStatus,
        _relative_reference: Option<ServtdTcbStatus>,
    ) -> Result<bool, PolicyError> {
        // "UpToDate" is always allowed.
        // "OutOfDate" is always allowed, because the time stamp is not trusted.
        const ALWAYS_ALLOW: &[ServtdTcbStatus] =
            &[ServtdTcbStatus::UpToDate, ServtdTcbStatus::OutOfDate];
        // "Revoked" is always denied.
        const ALWAYS_DENY: &[ServtdTcbStatus] = &[ServtdTcbStatus::Revoked];

        if ALWAYS_DENY.contains(&value) {
            return Ok(false);
        }

        if ALWAYS_ALLOW.contains(&value) {
            return Ok(true);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, string::ToString, vec};

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
        policy.verify(issuer_chain).unwrap();
    }

    #[test]
    fn test_verify_policy_svn_only_no_identity() {
        use crate::v2::hex_string_to_bytes;

        let policy_data = include_bytes!("../../test/policy_v2/policy_v2_svn_only.json");
        let policy = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        let issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        let verified = policy.verify(issuer_chain).unwrap();

        assert!(verified.servtd_identity.is_none());
        assert!(verified.servtd_identity_issuer_chain.is_none());

        let known_hash = hex_string_to_bytes(
            &verified.servtd_tcb_mapping.as_ref().unwrap().svn_mappings[0]
                .td_measurements
                .tdinfo_hash,
        )
        .unwrap();
        let lookup = verified
            .servtd_lookup_by_tdinfo_hash(&known_hash)
            .expect("known hash resolves");
        assert!(lookup.tcb_date.is_none());
        assert!(lookup.tcb_status.is_none());
    }

    #[test]
    fn servtd_policy_svn_only_bars_and_fail_closed() {
        let mut value = PolicyEvaluationInfo {
            migtd_isvsvn: Some(5),
            ..Default::default()
        };
        let relative = PolicyEvaluationInfo::default();

        let svn_only: ServtdPolicy = serde_json::from_str(
            r#"{"migtdIdentity":{"isvsvn":{"operation":"greater-or-equal","reference":5}}}"#,
        )
        .unwrap();
        assert!(svn_only.evaluate(&value, &relative).is_ok());

        let status_bar: ServtdPolicy = serde_json::from_str(
            r#"{"migtdIdentity":{"isvsvn":{"operation":"greater-or-equal","reference":5},"tcbStatusAccepted":{"operation":"string-equal","reference":"UpToDate"}}}"#,
        )
        .unwrap();
        assert!(status_bar.evaluate(&value, &relative).is_err());

        let date_bar: ServtdPolicy = serde_json::from_str(
            r#"{"migtdIdentity":{"tcbDate":{"operation":"greater-or-equal","reference":"2024-01-01T00:00:00Z"}}}"#,
        )
        .unwrap();
        assert!(date_bar.evaluate(&value, &relative).is_err());

        value.migtd_tcb_status = Some("UpToDate".to_string());
        value.migtd_tcb_date = Some("2025-01-01T00:00:00Z".to_string());
        assert!(status_bar.evaluate(&value, &relative).is_ok());
        assert!(date_bar.evaluate(&value, &relative).is_ok());
    }

    #[test]
    fn test_verify_policy_without_outer_signature() {
        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let signed = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        assert!(
            signed.signature.is_some(),
            "fixture is expected to carry a legacy outer signature"
        );

        let no_sig = format!("{{\"policyData\":{}}}", signed.policy_data.get());
        let unsigned = RawPolicyData::deserialize_from_json(no_sig.as_bytes()).unwrap();
        assert!(unsigned.signature.is_none());

        let issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        unsigned.verify(issuer_chain).unwrap();
    }

    #[test]
    fn test_outer_signature_is_ignored() {
        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let signed = RawPolicyData::deserialize_from_json(policy_data).unwrap();

        let tampered = format!(
            "{{\"policyData\":{},\"signature\":\"deadbeef\"}}",
            signed.policy_data.get()
        );
        let policy = RawPolicyData::deserialize_from_json(tampered.as_bytes()).unwrap();
        assert_eq!(policy.signature.as_deref(), Some("deadbeef"));

        policy
            .verify(include_bytes!(
                "../../test/policy_v2/cert_chain/policy_issuer_chain.pem"
            ))
            .unwrap();
    }

    #[test]
    fn test_verify_policy_rejects_mapping_chain_anchor_mismatch() {
        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let policy = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        let unrelated_chain =
            include_bytes!("../../test/policy_v2/cert_chain/unrelated_issuer_chain.pem");
        match policy.verify(unrelated_chain) {
            Err(PolicyError::SignerAnchorMismatch) => {}
            Err(other) => panic!("expected SignerAnchorMismatch, got {:?}", other),
            Ok(_) => panic!("expected SignerAnchorMismatch, but verify() succeeded"),
        }
    }

    /// End-to-end `verify()` revocation enforcement: a policy whose
    /// `servtdCollateral.servtdCrl` revokes the signer leaf must fail closed
    /// with `SignerRevoked`, while the same policy carrying a revocation-free
    /// CRL verifies. The fixtures under `test/policy_v2/revocation/` are a
    /// self-contained PKI (one signer for both identity and mapping) with
    /// matching empty and revoking CRLs.
    #[test]
    fn verify_enforces_servtd_signer_revocation() {
        let chain = include_bytes!("../../test/policy_v2/revocation/signer_chain.pem");

        let ok = include_bytes!("../../test/policy_v2/revocation/policy_ok.json");
        RawPolicyData::deserialize_from_json(ok)
            .unwrap()
            .verify(chain)
            .expect("policy with an unrevoked signer should verify");

        let revoked = include_bytes!("../../test/policy_v2/revocation/policy_revoked.json");
        match RawPolicyData::deserialize_from_json(revoked)
            .unwrap()
            .verify(chain)
        {
            Err(PolicyError::SignerRevoked) => {}
            Err(other) => panic!("expected SignerRevoked, got {:?}", other),
            Ok(_) => panic!("expected SignerRevoked, but verify() succeeded"),
        }
    }

    #[test]
    fn crl_policy_enforces_servtd_crl_num_floor() {
        let policy: CrlPolicy = serde_json::from_str(
            r#"{"servtdCrlNum":{"operation":"greater-or-equal","reference":4097}}"#,
        )
        .unwrap();
        let reference = PolicyEvaluationInfo::default();

        let mut value = PolicyEvaluationInfo::default();
        value.servtd_crl_num = Some(4097);
        assert!(policy.evaluate(&value, &reference).is_ok());
        value.servtd_crl_num = Some(5000);
        assert!(policy.evaluate(&value, &reference).is_ok());
        value.servtd_crl_num = Some(4096);
        assert!(policy.evaluate(&value, &reference).is_err());
        value.servtd_crl_num = None;
        assert!(policy.evaluate(&value, &reference).is_err());
    }

    #[cfg(feature = "servtd_corim")]
    #[test]
    fn servtd_lookup_is_fail_closed_when_corim_attached() {
        use crate::v2::{hex_string_to_bytes, ServtdCorim};

        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let policy = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        let issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        let mut verified = policy.verify(issuer_chain).unwrap();

        let legacy_hash = hex_string_to_bytes(
            &verified.servtd_tcb_mapping.as_ref().unwrap().svn_mappings[0]
                .td_measurements
                .tdinfo_hash,
        )
        .unwrap();
        assert!(verified
            .servtd_lookup_by_tdinfo_hash(&legacy_hash)
            .is_some());

        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cbor");
        verified.set_servtd_corim(ServtdCorim::decode(tcb, 0).unwrap());

        assert!(verified
            .servtd_lookup_by_tdinfo_hash(&legacy_hash)
            .is_none());

        let corim_hash = hex_string_to_bytes(
            "347c6170a91341351937962e08a7695703e7b87984b1c69216372c380302ac420d42381e4585007057b20b2579286384",
        )
        .unwrap();
        let hit = verified.servtd_lookup_by_tdinfo_hash(&corim_hash);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().isvsvn, 1);
    }

    #[test]
    fn test_global_policy() {
        let global = include_str!("../../test/policy_v2/global.json");
        let global_policy = serde_json::from_str::<GlobalPolicy>(global).unwrap();
        let mut value = PolicyEvaluationInfo {
            tee_tcb_svn: None,
            tcb_date: Some("2025-09-01T00:00:00Z".to_string()),
            tcb_status: Some("UpToDate".to_string()),
            tcb_evaluation_number: Some(15),
            fmspc: Some([0x10, 0xC0, 0x6F, 0x00, 0x00, 0x00]),
            migtd_isvsvn: None,
            migtd_tcb_status: None,
            migtd_tcb_date: None,
            pck_crl_num: None,
            root_ca_crl_num: None,
            servtd_crl_num: None,
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
    fn test_policy_tcb_date_rejects_malformed_timestamps() {
        const VALID_TIMESTAMP: &str = "2025-06-15T12:00:00Z";
        const INVALID_TIMESTAMPS: [&str; 2] = ["2025-6-15T12:00:00Z", "2025-13-40T25:61:61Z"];

        let policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::String(VALID_TIMESTAMP.to_string()),
        };
        for value in INVALID_TIMESTAMPS {
            assert!(policy.evaluate_string(value, None).is_err());
        }

        for reference in INVALID_TIMESTAMPS {
            let policy = PolicyProperty {
                operation: "greater-or-equal".to_string(),
                reference: Reference::String(reference.to_string()),
            };
            assert!(policy.evaluate_string(VALID_TIMESTAMP, None).is_err());
        }
    }

    #[test]
    fn test_servtd_tcb_status_comparison() {
        assert!(ServtdTcbStatus::UpToDate == ServtdTcbStatus::OutOfDate);
        assert!(ServtdTcbStatus::UpToDate > ServtdTcbStatus::Revoked);
        assert!(ServtdTcbStatus::OutOfDate > ServtdTcbStatus::Revoked);
    }

    #[test]
    fn test_tcb_status_comparison() {
        assert!(TcbStatus::UpToDate == TcbStatus::OutOfDate);
        assert!(TcbStatus::UpToDate == TcbStatus::SWHardeningNeeded);
        assert!(TcbStatus::UpToDate > TcbStatus::ConfigurationNeeded);
        assert!(TcbStatus::UpToDate > TcbStatus::OutOfDateConfigurationNeeded);
        assert!(TcbStatus::UpToDate > TcbStatus::ConfigurationAndSWHardeningNeeded);
        assert!(TcbStatus::UpToDate > TcbStatus::Revoked);

        assert!(TcbStatus::ConfigurationNeeded < TcbStatus::SWHardeningNeeded);
        assert!(TcbStatus::ConfigurationNeeded < TcbStatus::OutOfDate);
        assert!(TcbStatus::ConfigurationNeeded == TcbStatus::ConfigurationAndSWHardeningNeeded);
        assert!(TcbStatus::ConfigurationNeeded == TcbStatus::OutOfDateConfigurationNeeded);
        assert!(TcbStatus::ConfigurationNeeded > TcbStatus::Revoked);
    }

    #[test]
    fn test_policy_tcb_status() {
        let assert_tcb_status_allowed =
            |policy: PolicyProperty,
             relative_reference: TcbStatus,
             allow_list: &[TcbStatus],
             deny_list: &[TcbStatus]| {
                for value in allow_list {
                    assert!(policy
                        .evaluate_tcb_status(*value, Some(relative_reference))
                        .unwrap());
                }
                for value in deny_list {
                    assert!(!policy
                        .evaluate_tcb_status(*value, Some(relative_reference))
                        .unwrap());
                }
            };

        let relative_reference = TcbStatus::UpToDate;
        // Test with an "allow-list" operation and "UpToDate" reference
        let tcb_status_policy = PolicyProperty {
            operation: "allow-list".to_string(),
            reference: Reference::StringList(vec!["UpToDate".to_string()]),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
            ],
            &[
                TcbStatus::Revoked,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
        );

        // Test with an "allow-list" operation and "ConfigurationNeeded" reference
        let tcb_status_policy = PolicyProperty {
            operation: "allow-list".to_string(),
            reference: Reference::StringList(vec!["ConfigurationNeeded".to_string()]),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
            &[TcbStatus::Revoked],
        );

        // Test with an empty "deny-list" reference
        let tcb_status_policy = PolicyProperty {
            operation: "deny-list".to_string(),
            reference: Reference::StringList(vec![]),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
            ],
            &[
                TcbStatus::Revoked,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
        );

        // Test with a "deny-list" reference that contains "OutOfDate"
        let tcb_status_policy = PolicyProperty {
            operation: "deny-list".to_string(),
            reference: Reference::StringList(vec!["OutOfDate".to_string()]),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
            ],
            &[
                TcbStatus::Revoked,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
        );

        // Test with "greater-or-equal" operation and "ConfigurationNeeded" reference
        let relative_reference = TcbStatus::ConfigurationNeeded;
        let tcb_status_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::String("self".to_string()),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
            &[TcbStatus::Revoked],
        );

        // Test with "equal" operation and "UpToDate" reference
        let tcb_status_policy = PolicyProperty {
            operation: "equal".to_string(),
            reference: Reference::String("UpToDate".to_string()),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
            ],
            &[
                TcbStatus::Revoked,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
        );

        // Test with "equal" operation and "ConfigurationNeeded" reference
        let tcb_status_policy = PolicyProperty {
            operation: "equal".to_string(),
            reference: Reference::String("ConfigurationNeeded".to_string()),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
            &[TcbStatus::Revoked],
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

    #[test]
    fn test_absent_block_denies_revoked_platform() {
        // No block: still deny `Revoked` platform status.
        let value = PolicyEvaluationInfo {
            tcb_status: Some("Revoked".to_string()),
            ..PolicyEvaluationInfo::default()
        };
        let relative = PolicyEvaluationInfo::default();

        // `skip_global = false` evaluates platform status.
        assert!(
            PolicyData::<'static>::evaluate_policy_block(None, &value, &relative, false).is_err()
        );
    }

    #[test]
    fn test_absent_block_denies_revoked_engine() {
        // No block: still deny `Revoked` engine status.
        let value = PolicyEvaluationInfo {
            migtd_tcb_status: Some("Revoked".to_string()),
            ..PolicyEvaluationInfo::default()
        };
        let relative = PolicyEvaluationInfo::default();

        // Engine status is checked even with `skip_global = true`.
        assert!(
            PolicyData::<'static>::evaluate_policy_block(None, &value, &relative, true).is_err()
        );
    }

    #[test]
    fn test_absent_block_allows_non_revoked() {
        // No block: non-`Revoked` status is allowed.
        let value = PolicyEvaluationInfo {
            tcb_status: Some("UpToDate".to_string()),
            migtd_tcb_status: Some("UpToDate".to_string()),
            ..PolicyEvaluationInfo::default()
        };
        let relative = PolicyEvaluationInfo::default();

        assert!(
            PolicyData::<'static>::evaluate_policy_block(None, &value, &relative, false).is_ok()
        );
    }

    #[test]
    fn test_skip_global_ignores_platform_status() {
        // In rebinding (`skip_global`), platform status is ignored.
        let value = PolicyEvaluationInfo {
            tcb_status: Some("Revoked".to_string()),
            migtd_tcb_status: Some("UpToDate".to_string()),
            ..PolicyEvaluationInfo::default()
        };
        let relative = PolicyEvaluationInfo::default();

        assert!(
            PolicyData::<'static>::evaluate_policy_block(None, &value, &relative, true).is_ok()
        );
    }

    #[test]
    fn test_unclassifiable_engine_is_denied() {
        // Fail closed: unknown engine status (`None`) is denied in all paths.
        let value = PolicyEvaluationInfo {
            tcb_status: Some("UpToDate".to_string()),
            migtd_tcb_status: None,
            ..PolicyEvaluationInfo::default()
        };
        let relative = PolicyEvaluationInfo::default();

        assert!(
            PolicyData::<'static>::evaluate_policy_block(None, &value, &relative, false).is_err()
        );
        assert!(
            PolicyData::<'static>::evaluate_policy_block(None, &value, &relative, true).is_err()
        );
    }
}
