// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformTcb {
    pub tcb_info: TcbInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub fmspc: String,
    pub tcb_evaluation_data_number: u32,
    pub tdx_module_identities: Vec<TdxModuleIdentity>,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    pub id: String,
    pub mrsigner: String,
    pub attributes: String,
    pub tcb_levels: Vec<TdxMdouleTcbLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxMdouleTcbLevel {
    pub tcb: TdxModuleTcb,
}

#[derive(Debug, Deserialize)]
pub struct TdxModuleTcb {
    pub isvsvn: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_status: String,
}

#[derive(Debug, Deserialize)]
pub struct Tcb {
    pub sgxtcbcomponents: Vec<Svn>,
    pub pcesvn: u64,
    pub tdxtcbcomponents: Vec<Svn>,
}

impl Tcb {
    pub fn get_sgx_tcb(&self) -> Vec<u8> {
        self.sgxtcbcomponents.iter().map(|svn| svn.svn).collect()
    }

    pub fn get_tdx_tcb(&self) -> Vec<u8> {
        self.tdxtcbcomponents.iter().map(|svn| svn.svn).collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct Svn {
    svn: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeInfo {
    pub enclave_identity: EnalaveIdentity,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnalaveIdentity {
    pub miscselect: String,
    pub attributes: String,
    pub mrsigner: String,
    pub isvprodid: u64,
    pub tcb_levels: Vec<EnclaveTcbLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveTcbLevel {
    pub tcb: EnclaveTcb,
    pub tcb_status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveTcb {
    pub isvsvn: u64,
}
