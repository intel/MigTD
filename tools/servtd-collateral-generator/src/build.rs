// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::value::RawValue;
use std::{fs, path::Path};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServtdCollateral<'a> {
    major_version: u32,
    minor_version: u32,
    servtd_identity: &'a RawValue,
    servtd_identity_issuer_chain: String,
    servtd_tcb_mapping: &'a RawValue,
    servtd_tcb_mapping_issuer_chain: String,
}

pub fn build_servtd_collateral(
    identity_path: &Path,
    identity_chain_path: &Path,
    mapping_path: &Path,
    mapping_chain_path: &Path,
) -> Result<Vec<u8>> {
    let identity_bytes = read_file(identity_path)?;
    let mapping_bytes = read_file(mapping_path)?;
    let identity_val: &RawValue = serde_json::from_slice(&identity_bytes)
        .context("Failed to parse identity JSON (expected signed identity JSON)")?;
    let mapping_val: &RawValue = serde_json::from_slice(&mapping_bytes)
        .context("Failed to parse mapping JSON (expected signed mapping JSON)")?;

    let identity_chain = String::from_utf8(read_file(identity_chain_path)?)
        .context("Identity issuer chain not UTF-8")?;
    let mapping_chain = String::from_utf8(read_file(mapping_chain_path)?)
        .context("Mapping issuer chain not UTF-8")?;

    let servtd_collateral = ServtdCollateral {
        major_version: 1,
        minor_version: 0,
        servtd_identity: identity_val,
        servtd_identity_issuer_chain: identity_chain,
        servtd_tcb_mapping: mapping_val,
        servtd_tcb_mapping_issuer_chain: mapping_chain,
    };

    Ok(serde_json::to_vec(&servtd_collateral)?)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read {}", path.display()))
}
