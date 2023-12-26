// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use serde::Deserialize;

use crate::{fetch_data_from_url, policy::QePolicy};

const QE_IDENTITY_URL: &str =
    "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity?update=";
const SBX_QE_IDENTITY_URL: &str =
    "https://sbx.api.trustedservices.intel.com/tdx/certification/v4/qe/identity?update=";

pub fn get_qe_identity(for_production: bool) -> Result<QePolicy> {
    let qe_info = fetch_qe_identity(for_production)?;
    Ok(QePolicy::new(
        qe_info.enclave_identity.miscselect,
        qe_info.enclave_identity.attributes,
        qe_info.enclave_identity.mrsigner,
        qe_info.enclave_identity.isvprodid,
        qe_info.enclave_identity.tcb_levels[0].tcb.isvsvn,
    ))
}

fn fetch_qe_identity(for_production: bool) -> Result<QeInfo> {
    let url = if for_production {
        QE_IDENTITY_URL
    } else {
        SBX_QE_IDENTITY_URL
    };

    let (response_code, data) = fetch_data_from_url(&url)?;
    match response_code {
        200 => {
            println!("Got enclave identity");
            Ok(serde_json::from_slice::<QeInfo>(&data)?)
        }
        _ => {
            eprintln!("Error fetching enclave identity - {:?}", response_code);
            Err(anyhow!("AccessException"))
        }
    }
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
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tcb {
    pub isvsvn: u64,
}

mod test {
    #[test]
    fn test_json_deserialize() {
        use crate::qe_identity::QeInfo;

        let list = include_str!("../test/qe_identity.json");
        let result = serde_json::from_str::<QeInfo>(list);
        assert!(result.is_ok())
    }
}
