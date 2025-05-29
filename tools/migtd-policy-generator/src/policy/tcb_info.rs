// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use serde::Serialize;
use std::collections::HashSet;

use super::{Property, Reference};
use crate::pcs_types::PlatformTcb;

pub fn create_platform_policy(
    platform_tcb_list: &Vec<Vec<u8>>,
) -> Result<(Vec<PlatformPolicy>, Vec<TdxModulePolicy>)> {
    let tcbs = deserialize_tcb_info(platform_tcb_list)?;

    let mut platform_tcb_policies = Vec::new();
    for platform_tcb in &tcbs {
        let policy = PlatformPolicy::new(platform_tcb);
        platform_tcb_policies.push(policy);
    }
    Ok((platform_tcb_policies, TdxModulePolicy::new(&tcbs)))
}

fn deserialize_tcb_info(platform_tcb_list: &Vec<Vec<u8>>) -> Result<Vec<PlatformTcb>> {
    platform_tcb_list
        .iter()
        .map(|tcb| {
            serde_json::from_slice::<PlatformTcb>(tcb)
                .map_err(|e| anyhow::anyhow!("Failed to parse platform TCB: {}", e))
        })
        .collect::<Result<Vec<_>>>()
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
                tcb_info: TcbInfoPolicy {
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
    pub tcb_info: TcbInfoPolicy,
}

#[derive(Debug, Serialize)]
pub struct TcbInfoPolicy {
    sgxtcbcomponents: Property,
    pcesvn: Property,
    tdxtcbcomponents: Property,
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
    fn new(platform_tcb: &[PlatformTcb]) -> Vec<Self> {
        let mut tdx_module_policy = Vec::new();
        let mut tdx_module_id = HashSet::new();
        for tcb in platform_tcb {
            for tdx_module in &tcb.tcb_info.tdx_module_identities {
                let id = TdxModulePolicy::tdx_module_major_version_mapping(tdx_module.id.as_str());
                if !tdx_module_id.contains(&id) {
                    tdx_module_id.insert(id);
                    tdx_module_policy.push(Self {
                        tdx_module: TdxModuleInfo {
                            tdx_module_identity: TdxModuleIdentityPolicy {
                                tdx_module_major_version: Property {
                                    operation: "equal".to_string(),
                                    reference: Reference::Integer(id),
                                },
                                tdx_module_svn: Property {
                                    operation: "greater-or-equal".to_string(),
                                    reference: Reference::Integer(
                                        tdx_module.tcb_levels[0].tcb.isvsvn,
                                    ),
                                },
                                mrsigner_seam: Property {
                                    operation: "equal".to_string(),
                                    reference: Reference::Str(tdx_module.mrsigner.clone()),
                                },
                                attributes: Property {
                                    operation: "equal".to_string(),
                                    reference: Reference::Str(tdx_module.attributes.clone()),
                                },
                            },
                        },
                    })
                }
            }
        }
        tdx_module_policy
    }

    fn tdx_module_major_version_mapping(id: &str) -> u64 {
        match id {
            "TDX_01" => 1,
            "TDX_02" => 2,
            "TDX_03" => 3,
            _ => {
                panic!("Unexpected TDX Module ID");
            }
        }
    }
}
