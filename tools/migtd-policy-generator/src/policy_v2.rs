// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Context, Result};
use serde_json::{self, Value};
use std::{fs, path::Path};

pub fn build_v2_policy_data(
    base_policy_data: &Path,
    collaterals: &Path,
    servtd_collateral: Option<&Path>,
    servtd_crl: Option<&Path>,
) -> Result<Vec<u8>> {
    let policy_data_bytes = read_file(base_policy_data)?;
    let collateral_bytes = read_file(collaterals)?;

    let mut base: Value = serde_json::from_slice(&policy_data_bytes)
        .with_context(|| "Failed to parse base policy JSON")?;
    if !base.is_object() {
        return Err(anyhow!("Base policy JSON must be a JSON object"));
    }
    let collaterals_val: Value = serde_json::from_slice(&collateral_bytes)
        .with_context(|| "Failed to parse collaterals JSON")?;

    if let Some(map) = base.as_object_mut() {
        map.insert("collaterals".to_string(), collaterals_val);
        // Insert `servtdCollateral` only when provided. Omitting it yields a
        // CoRIM-only policy; MigTD then resolves servtd lookups through the
        // separately-enrolled CoRIM.
        if let Some(servtd_path) = servtd_collateral {
            let servtd_collateral_bytes = read_file(servtd_path)?;
            let servtd_val: Value = serde_json::from_slice(&servtd_collateral_bytes)
                .with_context(|| "Failed to parse servtd_collaterals JSON")?;
            map.insert("servtdCollateral".to_string(), servtd_val);
        }
        if let Some(servtd_crl_path) = servtd_crl {
            let servtd_crl = String::from_utf8(read_file(servtd_crl_path)?)
                .with_context(|| "servtd CRL is not UTF-8 PEM")?;
            map.insert("servtdCrl".to_string(), Value::String(servtd_crl));
        }
    }

    let out = serde_json::to_vec(&base)?;
    Ok(out)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read {}", path.display()))
}
