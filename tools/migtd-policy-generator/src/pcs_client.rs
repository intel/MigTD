// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use curl::easy::Easy;
use serde::Deserialize;

const TCB_INFO_URL: &str = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb";
const SBX_TCB_INFO_URL: &str = "https://sbx.api.trustedservices.intel.com/tdx/certification/v4/tcb";
const QE_IDENTITY_URL: &str =
    "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity?update=";
const SBX_QE_IDENTITY_URL: &str =
    "https://sbx.api.trustedservices.intel.com/tdx/certification/v4/qe/identity?update=";
const FMSPC_LIST_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/fmspcs";
const SBX_FMSPC_LIST_URL: &str =
    "https://sbx.api.trustedservices.intel.com/sgx/certification/v4/fmspcs";

pub fn fetch_qe_identity(for_production: bool) -> Result<Vec<u8>> {
    let url = if for_production {
        QE_IDENTITY_URL
    } else {
        SBX_QE_IDENTITY_URL
    };

    let (response_code, data) = fetch_data_from_url(&url).unwrap();
    match response_code {
        200 => {
            println!("Got enclave identity");
            Ok(data)
        }
        _ => {
            eprintln!("Error fetching enclave identity - {:?}", response_code);
            Err(anyhow!("AccessException"))
        }
    }
}

pub fn get_platform_tcb_list(for_production: bool) -> Result<Vec<Vec<u8>>> {
    let fmspc_list = fetch_fmspc_list(for_production)?;
    let mut platform_tcb_list = Vec::new();
    for platform in get_all_e5_platform(&fmspc_list) {
        let _ = fetch_platform_tcb(for_production, &platform.fmspc)?
            .and_then(|raw_tcb| Some(platform_tcb_list.push(raw_tcb)));
    }
    Ok(platform_tcb_list)
}

pub fn fetch_platform_tcb(for_production: bool, fmspc: &str) -> Result<Option<Vec<u8>>> {
    let tcb_info_url = if for_production {
        TCB_INFO_URL
    } else {
        SBX_TCB_INFO_URL
    };
    let url = format!("{}?fmspc={}", tcb_info_url, fmspc);
    let (response_code, data) = fetch_data_from_url(&url)?;

    let result = if response_code == 200 {
        println!("Got TCB info of fmspc - {}", fmspc,);
        Some(data)
    } else if response_code == 404 {
        // Ignore 404 errors
        None
    } else {
        eprintln!(
            "Error fetching details for fmspc {}: {:?}",
            fmspc, response_code
        );
        None
    };

    Ok(result)
}

pub(crate) fn fetch_data_from_url(url: &str) -> Result<(u32, Vec<u8>), curl::Error> {
    let mut handle = Easy::new();
    let mut data = Vec::new();

    handle.url(url)?;
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }

    Ok((handle.response_code()?, data))
}

pub fn fetch_fmspc_list(for_production: bool) -> Result<Vec<Fmspc>> {
    let fmspc_list_url = if for_production {
        FMSPC_LIST_URL
    } else {
        SBX_FMSPC_LIST_URL
    };

    let (response_code, data) = fetch_data_from_url(fmspc_list_url)?;
    match response_code {
        200 => Ok(serde_json::from_slice::<Vec<Fmspc>>(&data)?),
        _ => {
            eprintln!("Error fetching fmspc list - {:?}", response_code);
            Err(anyhow!("AccessException"))
        }
    }
}

pub fn get_all_e5_platform(list: &Vec<Fmspc>) -> Vec<&Fmspc> {
    list.iter()
        .filter(|p| p.platform.as_str() == "E5")
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct Fmspc {
    pub fmspc: String,
    platform: String,
}

impl Fmspc {
    pub fn is_e5(&self) -> bool {
        self.platform.as_str() == "E5"
    }
}

mod test {
    #[test]
    fn test_json_deserialize() {
        use super::*;

        let list = include_str!("../test/fmspc_list.json");
        let result = serde_json::from_str::<Vec<Fmspc>>(list);
        assert!(result.is_ok());
    }
}
