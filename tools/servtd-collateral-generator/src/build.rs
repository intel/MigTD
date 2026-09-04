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
    servtd_tcb_mapping: &'a RawValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    servtd_tcb_mapping_issuer_chain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    servtd_identity: Option<&'a RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    servtd_identity_issuer_chain: Option<String>,
    servtd_crl: String,
}

pub fn build_servtd_collateral(
    identity_path: Option<&Path>,
    identity_chain_path: Option<&Path>,
    mapping_path: &Path,
    mapping_chain_path: Option<&Path>,
    servtd_crl_path: &Path,
) -> Result<Vec<u8>> {
    let mapping_bytes = read_file(mapping_path)?;
    let mapping_val: &RawValue = serde_json::from_slice(&mapping_bytes)
        .context("Failed to parse mapping JSON (expected signed mapping JSON)")?;

    let mapping_chain = mapping_chain_path
        .map(|path| String::from_utf8(read_file(path)?).context("Mapping issuer chain not UTF-8"))
        .transpose()?;

    // The TD Identity is optional; when present it must come with its chain
    // (enforced at the CLI via clap `requires`).
    let identity_bytes = identity_path.map(read_file).transpose()?;
    let identity_val: Option<&RawValue> = identity_bytes
        .as_deref()
        .map(|b| {
            serde_json::from_slice(b)
                .context("Failed to parse identity JSON (expected signed identity JSON)")
        })
        .transpose()?;
    let identity_chain = identity_chain_path
        .map(|path| String::from_utf8(read_file(path)?).context("Identity issuer chain not UTF-8"))
        .transpose()?;

    let servtd_crl =
        String::from_utf8(read_file(servtd_crl_path)?).context("servTD CRL not UTF-8")?;

    let servtd_collateral = ServtdCollateral {
        major_version: 1,
        minor_version: 0,
        servtd_tcb_mapping: mapping_val,
        servtd_tcb_mapping_issuer_chain: mapping_chain,
        servtd_identity: identity_val,
        servtd_identity_issuer_chain: identity_chain,
        servtd_crl,
    };

    Ok(serde_json::to_vec(&servtd_collateral)?)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collateral_includes_required_crl() {
        let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/templates");
        let bytes = build_servtd_collateral(
            Some(&config.join("td_identity_signed.json")),
            Some(&config.join("policy_issuer_chain.pem")),
            &config.join("tcb_mapping_signed.json"),
            None,
            &config.join("servtd.crl.pem"),
        )
        .unwrap();
        let collateral: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            collateral["servtdCrl"],
            fs::read_to_string(config.join("servtd.crl.pem")).unwrap()
        );
    }
}
