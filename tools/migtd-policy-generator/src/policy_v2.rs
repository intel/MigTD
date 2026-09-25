// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Context, Result};
use serde_json::{self, Map, Value};
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
    let map = base
        .as_object_mut()
        .ok_or_else(|| anyhow!("Base policy JSON must be a JSON object"))?;
    let collaterals_val: Value = serde_json::from_slice(&collateral_bytes)
        .with_context(|| "Failed to parse collaterals JSON")?;
    map.insert("collaterals".to_string(), collaterals_val);

    let servtd_collateral = servtd_collateral
        .map(|path| {
            serde_json::from_slice(&read_file(path)?)
                .with_context(|| "Failed to parse servtd_collaterals JSON")
        })
        .transpose()?;
    let servtd_crl = servtd_crl
        .map(|path| {
            String::from_utf8(read_file(path)?).with_context(|| "servtd CRL is not UTF-8 PEM")
        })
        .transpose()?;
    merge_servtd_collateral(map, servtd_collateral, servtd_crl)?;

    let out = serde_json::to_vec(&base)?;
    Ok(out)
}

fn merge_servtd_collateral(
    map: &mut Map<String, Value>,
    servtd_collateral: Option<Value>,
    servtd_crl: Option<String>,
) -> Result<()> {
    let removed = match servtd_collateral {
        Some(collateral) => {
            map.insert("servtdCollateral".to_string(), collateral);
            None
        }
        None => map.remove("servtdCollateral"),
    };
    if let Some(crl) = servtd_crl {
        map.insert("servtdCrl".to_string(), Value::String(crl));
    } else if map
        .get("servtdCrl")
        .filter(|value| !value.is_null())
        .is_none()
    {
        if let Some(crl) = removed.as_ref().and_then(|value| value.get("servtdCrl")) {
            map.insert("servtdCrl".to_string(), crl.clone());
        }
    }

    let top_level = map.get("servtdCrl").filter(|value| !value.is_null());
    let nested = map
        .get("servtdCollateral")
        .and_then(|value| value.get("servtdCrl"))
        .filter(|value| !value.is_null());
    let crl = match (top_level, nested) {
        (Some(top), Some(nested)) if top != nested => {
            return Err(anyhow!("Top-level and nested servtdCrl values differ"));
        }
        (Some(crl), _) | (_, Some(crl)) => crl,
        (None, None) => {
            return Err(anyhow!(
                "A numbered servtd CRL is required; supply --servtd-crl or retain one in the policy data or supplied servtd collateral"
            ));
        }
    };
    let crl = crl
        .as_str()
        .ok_or_else(|| anyhow!("servtdCrl must be a PEM string"))?;
    crypto::crl::get_crl_number(crl.as_bytes())
        .map_err(|error| anyhow!("servtdCrl must be a valid numbered PEM CRL: {error:?}"))?;
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CRL: &str = include_str!("../../../src/crypto/test/crl/empty.crl.pem");
    const OTHER_CRL: &str = include_str!("../../../src/crypto/test/crl/root_empty.crl.pem");

    fn merge(mut base: Value, collateral: Option<Value>, crl: Option<&str>) -> Result<Value> {
        merge_servtd_collateral(
            base.as_object_mut().unwrap(),
            collateral,
            crl.map(str::to_owned),
        )?;
        Ok(base)
    }

    #[test]
    fn omitted_collateral_is_removed_and_its_crl_is_promoted() {
        let result = merge(
            json!({"policy": {"unchanged": true}, "servtdCollateral": {"stale": true, "servtdCrl": CRL}}),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"policy": {"unchanged": true}, "servtdCrl": CRL})
        );
    }

    #[test]
    fn existing_top_level_crl_takes_precedence_over_removed_collateral() {
        let result = merge(
            json!({"servtdCrl": CRL, "servtdCollateral": {"servtdCrl": OTHER_CRL}}),
            None,
            None,
        )
        .unwrap();
        assert_eq!(result, json!({"servtdCrl": CRL}));
    }

    #[test]
    fn explicit_crl_takes_precedence_when_removing_collateral() {
        let result = merge(
            json!({"servtdCrl": OTHER_CRL, "servtdCollateral": {"servtdCrl": OTHER_CRL}}),
            None,
            Some(CRL),
        )
        .unwrap();
        assert_eq!(result, json!({"servtdCrl": CRL}));
    }

    #[test]
    fn null_top_level_crl_does_not_prevent_promotion() {
        let result = merge(
            json!({"servtdCrl": null, "servtdCollateral": {"servtdCrl": CRL}}),
            None,
            None,
        )
        .unwrap();
        assert_eq!(result, json!({"servtdCrl": CRL}));
    }

    #[test]
    fn missing_or_invalid_crl_is_rejected() {
        for base in [
            json!({}),
            json!({"servtdCrl": null}),
            json!({"servtdCollateral": {"stale": true}}),
            json!({"servtdCollateral": {"servtdCrl": ""}}),
            json!({"servtdCrl": 7}),
            json!({"servtdCrl": "not a CRL"}),
        ] {
            assert!(merge(base, None, None).is_err());
        }
    }

    #[test]
    fn supplied_json_collateral_and_its_crl_are_preserved() {
        let collateral = json!({"servtdTcbMapping": {"current": true}, "servtdCrl": CRL});
        let result = merge(
            json!({"servtdCollateral": {"stale": true}}),
            Some(collateral.clone()),
            None,
        )
        .unwrap();
        assert_eq!(result, json!({"servtdCollateral": collateral}));
    }

    #[test]
    fn json_collateral_can_use_the_top_level_crl() {
        let collateral = json!({"servtdTcbMapping": {"current": true}});
        let result = merge(json!({}), Some(collateral.clone()), Some(CRL)).unwrap();
        assert_eq!(
            result,
            json!({"servtdCollateral": collateral, "servtdCrl": CRL})
        );
    }

    #[test]
    fn retained_conflicting_crls_are_rejected() {
        assert!(merge(
            json!({"servtdCrl": OTHER_CRL}),
            Some(json!({"servtdCrl": CRL})),
            None,
        )
        .is_err());
    }
}
