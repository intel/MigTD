// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use futures::future::try_join_all;

use crate::policy::PlatformPolicy;
use fmspc::{fetch_fmspc_list, get_all_e5_platform};
use tcb_info::fetch_platform_tcb;

use self::tcb_info::PlatformTcb;

pub mod fmspc;
pub mod tcb_info;

pub async fn get_platform_info(
    for_production: bool,
) -> Result<(Vec<PlatformPolicy>, Vec<PlatformTcb>)> {
    let list = fetch_fmspc_list(for_production).await?;

    let tasks = get_all_e5_platform(&list).into_iter().map(|platform| {
        let fmspc = platform.fmspc.clone();
        async move { fetch_platform_tcb(for_production, &fmspc).await }
    });

    let results = try_join_all(tasks).await?;
    let mut tcbs = Vec::new();
    let mut platforms = Vec::new();

    for platform_tcb in results.into_iter().flatten() {
        platforms.push(PlatformPolicy::new(&platform_tcb));
        tcbs.push(platform_tcb);
    }

    Ok((platforms, tcbs))
}
