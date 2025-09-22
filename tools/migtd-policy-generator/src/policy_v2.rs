// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Context, Result};
use serde_json::{self, Value};
use std::{fs, path::Path};

pub fn build_v2_policy_data(
    base_policy_data: &Path,
    collaterals: &Path,
    servtd_collateral: &Path,
) -> Result<Vec<u8>> {
    let policy_data_bytes = read_file(base_policy_data)?;
    let collateral_bytes = read_file(collaterals)?;
    let servtd_collateral_bytes = read_file(servtd_collateral)?;

    let mut base: Value = serde_json::from_slice(&policy_data_bytes)
        .with_context(|| "Failed to parse base policy JSON")?;
    if !base.is_object() {
        return Err(anyhow!("Base policy JSON must be a JSON object"));
    }
    let collaterals_val: Value = serde_json::from_slice(&collateral_bytes)
        .with_context(|| "Failed to parse collaterals JSON")?;
    let servtd_val: Value = serde_json::from_slice(&servtd_collateral_bytes)
        .with_context(|| "Failed to parse servtd_collaterals JSON")?;

    if let Some(map) = base.as_object_mut() {
        map.insert("collaterals".to_string(), collaterals_val);
        map.insert("servtdCollateral".to_string(), servtd_val);
    }

    let out = serde_json::to_vec(&base)?;
    Ok(out)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read {}", path.display()))
}
