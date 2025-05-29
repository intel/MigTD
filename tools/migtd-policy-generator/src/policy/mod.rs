// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use qe_identity::{create_qe_identity_policy, QePolicy};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use tcb_info::{create_platform_policy, PlatformPolicy, TdxModulePolicy};

use crate::pcs_client::{fetch_qe_identity, get_platform_tcb_list};

pub mod qe_identity;
pub mod tcb_info;

const PRODUCTION_POLICY_GUID: &str = "F65CD566-4D67-45EF-88E3-79963901B292";
const PRE_PRODUCTION_POLICY_GUID: &str = "B87BFE45-9CC7-46F9-8F2C-A6CB55BF7101";

pub fn generate_policy(for_production: bool) -> Result<Vec<u8>> {
    let platform_tcb_list = get_platform_tcb_list(for_production)?;
    let qe_identity = fetch_qe_identity(for_production)?;
    let (platform_policy, tdx_module) = create_platform_policy(&platform_tcb_list)?;
    let qe_policy = create_qe_identity_policy(&qe_identity)?;
    let migtd = MigTdInfoPolicy::default();

    let mut mig_policy = MigPolicy {
        id: if for_production {
            PRODUCTION_POLICY_GUID.to_string()
        } else {
            PRE_PRODUCTION_POLICY_GUID.to_string()
        },
        policy: platform_policy
            .into_iter()
            .map(|p| PolicyTypes::Platform(p))
            .collect(),
    };

    mig_policy.policy.push(PolicyTypes::Qe(qe_policy));
    mig_policy.policy.append(
        &mut tdx_module
            .into_iter()
            .map(|t| PolicyTypes::TdxModule(t))
            .collect(),
    );
    mig_policy.policy.push(PolicyTypes::Migtd(migtd));

    let mut data = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut data, formatter);
    let obj = json!(mig_policy);
    obj.serialize(&mut ser).unwrap();

    Ok(data)
}

#[derive(Debug, Serialize)]
pub struct MigPolicy {
    id: String,
    policy: Vec<PolicyTypes>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PolicyTypes {
    Platform(PlatformPolicy),
    Qe(QePolicy),
    TdxModule(TdxModulePolicy),
    Migtd(MigTdInfoPolicy),
}

#[derive(Debug, Default, Serialize)]
pub struct MigTdInfoPolicy {
    #[serde(rename = "MigTD")]
    migtd: TdInfo,
}

#[derive(Debug, Serialize)]
pub(crate) struct TdInfo {
    #[serde(rename = "TDINFO")]
    td_info: BTreeMap<String, Property>,
    #[serde(rename = "EventLog")]
    event_log: BTreeMap<String, Property>,
}

impl Default for TdInfo {
    fn default() -> Self {
        let mut td_info = BTreeMap::new();
        td_info.insert("ATTRIBUTES".to_string(), Property::default());
        td_info.insert("XFAM".to_string(), Property::default());
        td_info.insert("MRTD".to_string(), Property::default());
        td_info.insert("MRCONFIGID".to_string(), Property::default());
        td_info.insert("MROWNER".to_string(), Property::default());
        td_info.insert("MROWNERCONFIG".to_string(), Property::default());
        td_info.insert("RTMR0".to_string(), Property::default());
        td_info.insert("RTMR1".to_string(), Property::default());
        td_info.insert("RTMR2".to_string(), Property::default());
        td_info.insert("RTMR3".to_string(), Property::default());

        let mut event_log = BTreeMap::new();
        event_log.insert("Digest.MigTdPolicy".to_string(), Property::default());
        event_log.insert("Digest.MigTdSgxRootKey".to_string(), Property::default());

        Self { td_info, event_log }
    }
}

#[derive(Debug, Serialize)]
struct Property {
    operation: String,
    reference: Reference,
}

impl Default for Property {
    fn default() -> Self {
        Property {
            operation: "equal".to_string(),
            reference: Reference::Str("self".to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Reference {
    Array(Vec<u8>),
    Integer(u64),
    Str(String),
}
