// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use serde::Deserialize;

use crate::fetch_data_from_url;

const FMSPC_LIST_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/fmspcs";
const SBX_FMSPC_LIST_URL: &str =
    "https://sbx.api.trustedservices.intel.com/sgx/certification/v4/fmspcs";

pub async fn fetch_fmspc_list(for_production: bool) -> Result<Vec<Fmspc>> {
    let fmspc_list_url = if for_production {
        FMSPC_LIST_URL
    } else {
        SBX_FMSPC_LIST_URL
    };

    let (response_code, data) = fetch_data_from_url(fmspc_list_url).await?;
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
        use crate::platform_tcb::fmspc::Fmspc;

        let list = include_str!("../../test/fmspc_list.json");
        let result = serde_json::from_str::<Vec<Fmspc>>(list);
        assert!(result.is_ok());
    }
}
