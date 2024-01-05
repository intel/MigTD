// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;
use serde_json::json;

use crate::{
    platform_tcb::{get_platform_info, tcb_info::PlatformTcb},
    qe_identity::get_qe_identity,
};

const PRODUCTION_POLICY_GUID: &str = "F65CD566-4D67-45EF-88E3-79963901B292";
const PRE_PRODUCTION_POLICY_GUID: &str = "B87BFE45-9CC7-46F9-8F2C-A6CB55BF7101";

pub fn generate_policy(for_production: bool) -> Result<Vec<u8>> {
    let platform_tcb = get_platform_info(for_production)?;
    let qe_identity = get_qe_identity(for_production)?;
    let migtd = MigTdInfoPolicy::default();
    let tdx_module = TdxModulePolicy::new(for_production);

    let mut mig_policy = MigPolicy {
        id: if for_production {
            PRODUCTION_POLICY_GUID.to_string()
        } else {
            PRE_PRODUCTION_POLICY_GUID.to_string()
        },
        policy: platform_tcb
            .into_iter()
            .map(|p| PolicyTypes::Platform(p))
            .collect(),
    };

    mig_policy.policy.push(PolicyTypes::Qe(qe_identity));
    mig_policy.policy.push(PolicyTypes::TdxModule(tdx_module));
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

#[derive(Debug, Serialize)]
pub struct PlatformPolicy {
    pub(crate) fmspc: String,
    #[serde(rename = "Platform")]
    pub(crate) platform: Platform,
}

impl PlatformPolicy {
    pub fn new(platform_tcb: &PlatformTcb) -> Self {
        PlatformPolicy {
            fmspc: platform_tcb.tcb_info.fmspc.clone(),
            platform: Platform {
                tcb_info: TcbInfo {
                    sgxtcbcomponents: Property {
                        operation: "array-greater-or-equal".to_string(),
                        reference: Reference::Array(
                            platform_tcb.tcb_info.tcb_levels[0]
                                .tcb
                                .get_sgx_tcb()
                                .clone(),
                        ),
                    },
                    pcesvn: Property {
                        operation: "greater-or-equal".to_string(),
                        reference: Reference::Integer(
                            platform_tcb.tcb_info.tcb_levels[0].tcb.pcesvn,
                        ),
                    },
                    tdxtcbcomponents: Property {
                        operation: "array-greater-or-equal".to_string(),
                        reference: Reference::Array(
                            platform_tcb.tcb_info.tcb_levels[0]
                                .tcb
                                .get_tdx_tcb()
                                .clone(),
                        ),
                    },
                },
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Platform {
    #[serde(rename = "TcbInfo")]
    pub tcb_info: TcbInfo,
}

#[derive(Debug, Serialize)]
pub struct TcbInfo {
    sgxtcbcomponents: Property,
    pcesvn: Property,
    tdxtcbcomponents: Property,
}

#[derive(Debug, Serialize)]
pub struct QePolicy {
    #[serde(rename = "QE")]
    qe_info: QeInfo,
}

#[derive(Debug, Serialize)]
pub struct QeInfo {
    #[serde(rename = "QeIdentity")]
    qe_identity: QeIdentity,
}

impl QePolicy {
    pub fn new(
        miscselect: String,
        attributes: String,
        mrsigner: String,
        isvprodid: u64,
        isvsvn: u64,
    ) -> Self {
        Self {
            qe_info: QeInfo {
                qe_identity: QeIdentity {
                    miscselect: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Str(miscselect),
                    },
                    attributes: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Str(attributes),
                    },
                    mrsigner: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Str(mrsigner),
                    },
                    isvprodid: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Integer(isvprodid),
                    },
                    isvsvn: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Integer(isvsvn),
                    },
                },
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct QeIdentity {
    #[serde(rename = "MISCSELECT")]
    miscselect: Property,
    #[serde(rename = "ATTRIBUTES")]
    attributes: Property,
    #[serde(rename = "MRSIGNER")]
    mrsigner: Property,
    #[serde(rename = "ISVPRODID")]
    isvprodid: Property,
    #[serde(rename = "ISVSVN")]
    isvsvn: Property,
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
pub struct TdxModulePolicy {
    #[serde(rename = "TDXModule")]
    tdx_module: TdxModuleInfo,
}

#[derive(Debug, Serialize)]
pub(crate) struct TdxModuleInfo {
    #[serde(rename = "TDXModule_Identity")]
    tdx_module_identity: TdxModuleIdentityPolicy,
}

#[derive(Debug, Serialize)]
pub struct TdxModuleIdentityPolicy {
    #[serde(rename = "TDXModuleMajorVersion")]
    tdx_module_major_version: Property,
    #[serde(rename = "TDXModuleSVN")]
    tdx_module_svn: Property,
    #[serde(rename = "MRSIGNERSEAM")]
    mrsigner_seam: Property,
    #[serde(rename = "ATTRIBUTES")]
    attributes: Property,
}

impl TdxModulePolicy {
    fn new(for_production: bool) -> Self {
        Self {
            tdx_module: TdxModuleInfo {
                tdx_module_identity: TdxModuleIdentityPolicy {
                    tdx_module_major_version: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Integer(1),
                    },
                    tdx_module_svn: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Integer(if for_production { 2 } else { 0 }),
                    },
                    mrsigner_seam: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Str("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string()),
                    },
                    attributes: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Str("0000000000000000".to_string()),
                    },
                },
            },
        }
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
