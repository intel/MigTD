// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use reqwest::Client;

pub mod platform_tcb;
pub mod policy;
pub mod policy_v2;
pub mod qe_identity;

pub(crate) async fn fetch_data_from_url(url: &str) -> Result<(u32, Vec<u8>)> {
    let client = Client::new();
    let response = client.get(url).send().await?;
    let status = response.status().as_u16() as u32;
    let data = response.bytes().await?.to_vec();
    Ok((status, data))
}
