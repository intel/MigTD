// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;

use crate::policy::PlatformPolicy;
use fmspc::{fetch_fmspc_list, get_all_e5_platform};
use tcb_info::fetch_platform_tcb;

pub mod fmspc;
pub mod tcb_info;

pub fn get_platform_info(for_production: bool) -> Result<Vec<PlatformPolicy>> {
    match fetch_fmspc_list(for_production) {
        Ok(list) => {
            let mut platforms = Vec::new();
            for platform in get_all_e5_platform(&list) {
                if let Ok(platform_tcb) = fetch_platform_tcb(for_production, &platform.fmspc) {
                    if let Some(platform_tcb) = platform_tcb {
                        let platform = PlatformPolicy::new(&platform_tcb);
                        platforms.push(platform);
                    }
                }
            }
            Ok(platforms)
        }
        Err(err) => {
            eprintln!("Error fetching fmspc list: {}", err);
            Err(err.into())
        }
    }
}
