// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Policy v2 measurement primitives for signer-anchored one-hash endorsements.
//!
//! The runtime and `migtd-hash` share these helpers to produce identical
//! measurements.
//!
//! ## RTMR2 policy measurement
//!
//! RTMR2 (`mr_index = 0x3`) is extended **once** with the canonical JSON bytes
//! of `policyData` with `servtdCollateral.servtdTcbMapping` removed.
//!
//! The mapping remains updateable after the IGVM is published. Every other
//! `policyData` field is bound into RTMR2.
//!
//! ## Canonicalization
//!
//! Canonicalization is implemented manually by [`canonical_value_bytes`] and
//! does **not** rely on `serde_json::to_vec`'s ordering, because other crates
//! in this workspace enable `serde_json/preserve_order` to preserve insertion
//! order.
//!
//! ## RTMR1 signer anchor
//!
//! [`compute_signer_anchor`] returns:
//!
//! `A = SHA384("MIGTD-RTMR1-ANCHOR-V1" || 0x00 || R || 0x00 || S)`,
//!
//! `R = SHA384(DER(root_cert))`, `S = SHA384(DER(leaf_cert.tbsCertificate.subject))`.
//! RTMR1 is extended with `A`.
//!
//! ## `tdinfo_hash` = `init_servtd_info_hash`
//!
//! Production MigTDs use `servtd_attr == 0`, so the mapping stores
//! `SHA384(TDINFO)` for direct lookup.

use alloc::{string::String, vec::Vec};
use crypto::{
    extract_leaf_subject_der_from_chain_pem, hash::digest_sha384,
    split_chain_pem_to_leaf_and_root_der, SHA384_DIGEST_SIZE,
};
use serde_json::Value;

use crate::PolicyError;

/// Domain-separation tag for the RTMR1 signer anchor.
pub const SIGNER_ANCHOR_DOMAIN_TAG: &[u8] = b"MIGTD-RTMR1-ANCHOR-V1";

/// Single byte separator (`0x00`) between domain tag, R, and S.
const SIGNER_ANCHOR_SEPARATOR: u8 = 0x00;

// Canonicalization

/// Append canonical JSON: sorted object keys, no whitespace, and unchanged
/// array order.
fn canonical_value_bytes_into(v: &Value, out: &mut Vec<u8>) -> Result<(), PolicyError> {
    match v {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // Reuse serde_json's string escaping without relying on map order.
                let key_bytes = serde_json::to_vec(&Value::String((*k).clone()))
                    .map_err(|_| PolicyError::InvalidPolicy)?;
                out.extend_from_slice(&key_bytes);
                out.push(b':');
                canonical_value_bytes_into(map.get(*k).ok_or(PolicyError::InvalidPolicy)?, out)?;
            }
            out.push(b'}');
        }
        Value::Array(arr) => {
            out.push(b'[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_value_bytes_into(e, out)?;
            }
            out.push(b']');
        }
        other => {
            let scalar_bytes = serde_json::to_vec(other).map_err(|_| PolicyError::InvalidPolicy)?;
            out.extend_from_slice(&scalar_bytes);
        }
    }
    Ok(())
}

/// Return canonical JSON bytes for `v`.
pub fn canonical_value_bytes(v: &Value) -> Result<Vec<u8>, PolicyError> {
    let mut out = Vec::new();
    canonical_value_bytes_into(v, &mut out)?;
    Ok(out)
}

// policyData extraction (single redacted extend)

/// Parse a bare `policyData` object or extract it from a signed wrapper.
fn parse_policy_data(policy_input: &[u8]) -> Result<Value, PolicyError> {
    let top: Value =
        serde_json::from_slice(policy_input).map_err(|_| PolicyError::InvalidPolicy)?;

    let policy_data = match top.get("policyData") {
        Some(v) => v.clone(),
        None => top,
    };

    if !policy_data.is_object() {
        return Err(PolicyError::InvalidPolicy);
    }
    Ok(policy_data)
}

/// Canonical JSON bytes of `policyData` with `servtdCollateral.servtdTcbMapping`
/// removed, including the outer `{` / `}`.
///
/// A direct `servtdTcbMapping` is required so schema changes fail instead of
/// silently altering the measurement.
pub fn extract_canonical_policy_data_bytes(policy_input: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let mut policy_data = parse_policy_data(policy_input)?;

    let coll = policy_data
        .get_mut("servtdCollateral")
        .and_then(|v| v.as_object_mut())
        .ok_or(PolicyError::InvalidPolicy)?;

    if coll.remove("servtdTcbMapping").is_none() {
        return Err(PolicyError::InvalidPolicy);
    }

    canonical_value_bytes(&policy_data)
}

/// Compute the RTMR1 signer anchor.
///
/// `A = SHA384(SIGNER_ANCHOR_DOMAIN_TAG || 0x00 || R || 0x00 || S)`
///
/// where `R = SHA384(DER(root_cert))` and `S = SHA384(DER(leaf_subject))`.
/// `0x00` is a single zero byte separator.
pub fn compute_signer_anchor(
    root_der: &[u8],
    leaf_subject_der: &[u8],
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    let r = digest_sha384(root_der).map_err(|_| PolicyError::HashCalculation)?;
    let s = digest_sha384(leaf_subject_der).map_err(|_| PolicyError::HashCalculation)?;

    let mut buf = Vec::with_capacity(SIGNER_ANCHOR_DOMAIN_TAG.len() + 1 + r.len() + 1 + s.len());
    buf.extend_from_slice(SIGNER_ANCHOR_DOMAIN_TAG);
    buf.push(SIGNER_ANCHOR_SEPARATOR);
    buf.extend_from_slice(&r);
    buf.push(SIGNER_ANCHOR_SEPARATOR);
    buf.extend_from_slice(&s);

    let digest = digest_sha384(&buf).map_err(|_| PolicyError::HashCalculation)?;
    let mut out = [0u8; SHA384_DIGEST_SIZE];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Compute the signer anchor from a leaf-first PEM certificate chain.
pub fn compute_signer_anchor_from_chain_pem(
    chain_pem: &[u8],
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    let (_leaf_der, root_der) =
        split_chain_pem_to_leaf_and_root_der(chain_pem).map_err(|_| PolicyError::InvalidPolicy)?;
    let leaf_subject = extract_leaf_subject_der_from_chain_pem(chain_pem)
        .map_err(|_| PolicyError::InvalidPolicy)?;
    compute_signer_anchor(&root_der, &leaf_subject)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_anchor_is_stable_for_fixed_inputs() {
        let root = b"the-root-DER-placeholder";
        let subject = b"CN=MigTD Info Issuer";
        let a = compute_signer_anchor(root, subject).unwrap();
        let a2 = compute_signer_anchor(root, subject).unwrap();
        assert_eq!(a, a2);

        let r = digest_sha384(root).unwrap();
        let s = digest_sha384(subject).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(SIGNER_ANCHOR_DOMAIN_TAG);
        buf.push(0u8);
        buf.extend_from_slice(&r);
        buf.push(0u8);
        buf.extend_from_slice(&s);
        let expected = digest_sha384(&buf).unwrap();
        assert_eq!(&a[..], expected.as_slice());
    }

    #[test]
    fn signer_anchor_changes_with_root_or_subject() {
        let a = compute_signer_anchor(b"root1", b"subj1").unwrap();
        let b = compute_signer_anchor(b"root2", b"subj1").unwrap();
        let c = compute_signer_anchor(b"root1", b"subj2").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    // Canonicalization

    #[test]
    fn canonical_value_sorts_keys_at_every_level() {
        let a: Value =
            serde_json::from_str(r#"{"b":{"y":2,"x":1},"a":[{"c":3,"b":2,"a":1}]}"#).unwrap();
        let b: Value =
            serde_json::from_str(r#"{"a":[{"a":1,"b":2,"c":3}],"b":{"x":1,"y":2}}"#).unwrap();
        let out_a = canonical_value_bytes(&a).unwrap();
        let out_b = canonical_value_bytes(&b).unwrap();
        assert_eq!(out_a, out_b);
        assert_eq!(&out_a, br#"{"a":[{"a":1,"b":2,"c":3}],"b":{"x":1,"y":2}}"#);
    }

    #[test]
    fn canonical_value_preserves_array_order() {
        let v: Value = serde_json::from_str(r#"[3,1,2]"#).unwrap();
        assert_eq!(canonical_value_bytes(&v).unwrap(), b"[3,1,2]");
    }

    #[test]
    fn canonical_value_emits_no_whitespace() {
        let v: Value = serde_json::from_str("{\n  \"a\" : 1 ,\n  \"b\" : [ 2 , 3 ]\n}").unwrap();
        assert_eq!(canonical_value_bytes(&v).unwrap(), br#"{"a":1,"b":[2,3]}"#);
    }

    // Policy data extraction

    /// Sample containing measured identity data and a redacted TCB mapping.
    fn sample_bare_policy_data() -> &'static str {
        r#"{"id":"X-uuid","version":"2.0","policySvn":7,"policy":[{"global":{"tcb":{"tcbDate":{"reference":"2023","operation":"ge"}}}},{"servtd":{"x":1}}],"collaterals":{"majorVersion":1,"minorVersion":0,"teeType":129},"servtdCollateral":{"majorVersion":1,"minorVersion":0,"servtdIdentityIssuerChain":"chain","servtdIdentity":{"tdIdentity":{"id":"identity-1","version":1,"tcbLevels":[]},"signature":"deadbeef"},"servtdTcbMappingIssuerChain":"mapping-chain","servtdTcbMapping":{"svnMappings":[{"isvsvn":1}]}}}"#
    }

    fn sample_wrapped_policy() -> alloc::string::String {
        format!(
            r#"{{"policyData":{},"signature":"sig"}}"#,
            sample_bare_policy_data()
        )
    }

    #[test]
    fn extract_returns_outer_braces() {
        let out =
            extract_canonical_policy_data_bytes(sample_bare_policy_data().as_bytes()).unwrap();
        assert_eq!(out.first(), Some(&b'{'));
        assert_eq!(out.last(), Some(&b'}'));
    }

    #[test]
    fn extract_redacts_servtd_tcb_mapping() {
        let a = r#"{"id":"X","version":"2","policySvn":1,"policy":[],"collaterals":{},"servtdCollateral":{"majorVersion":1,"minorVersion":0,"servtdIdentityIssuerChain":"c","servtdIdentity":{"tdIdentity":{"id":"i"},"signature":"aa"},"servtdTcbMappingIssuerChain":"c","servtdTcbMapping":{"svnMappings":[{"isvsvn":1}]}}}"#;
        let b = r#"{"id":"X","version":"2","policySvn":1,"policy":[],"collaterals":{},"servtdCollateral":{"majorVersion":1,"minorVersion":0,"servtdIdentityIssuerChain":"c","servtdIdentity":{"tdIdentity":{"id":"i"},"signature":"aa"},"servtdTcbMappingIssuerChain":"c","servtdTcbMapping":{"svnMappings":[{"isvsvn":99},{"isvsvn":100}]}}}"#;
        let out_a = extract_canonical_policy_data_bytes(a.as_bytes()).unwrap();
        let out_b = extract_canonical_policy_data_bytes(b.as_bytes()).unwrap();
        assert_eq!(out_a, out_b);
        assert!(!out_a
            .windows(b"svnMappings".len())
            .any(|w| w == b"svnMappings"));
    }

    #[test]
    fn extract_redacts_only_servtd_tcb_mapping() {
        let a = r#"{"servtdCollateral":{"servtdIdentity":{"tdIdentity":{"id":"i1"},"signature":"aa"},"servtdTcbMapping":{}}}"#;
        let b = r#"{"servtdCollateral":{"servtdIdentity":{"tdIdentity":{"id":"i1"},"signature":"bb"},"servtdTcbMapping":{}}}"#;
        let out_a = extract_canonical_policy_data_bytes(a.as_bytes()).unwrap();
        let out_b = extract_canonical_policy_data_bytes(b.as_bytes()).unwrap();
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn extract_protects_issuer_chains() {
        let a = r#"{"servtdCollateral":{"servtdIdentityIssuerChain":"chain-A","servtdTcbMappingIssuerChain":"chain-A","servtdTcbMapping":{}}}"#;
        let b = r#"{"servtdCollateral":{"servtdIdentityIssuerChain":"chain-B","servtdTcbMappingIssuerChain":"chain-A","servtdTcbMapping":{}}}"#;
        let c = r#"{"servtdCollateral":{"servtdIdentityIssuerChain":"chain-A","servtdTcbMappingIssuerChain":"chain-B","servtdTcbMapping":{}}}"#;
        let out_a = extract_canonical_policy_data_bytes(a.as_bytes()).unwrap();
        let out_b = extract_canonical_policy_data_bytes(b.as_bytes()).unwrap();
        let out_c = extract_canonical_policy_data_bytes(c.as_bytes()).unwrap();
        assert_ne!(out_a, out_b);
        assert_ne!(out_a, out_c);
        assert_ne!(out_b, out_c);
    }

    #[test]
    fn extract_accepts_signed_wrapper_and_matches_bare() {
        let bare = sample_bare_policy_data();
        let wrapped = sample_wrapped_policy();
        let out_bare = extract_canonical_policy_data_bytes(bare.as_bytes()).unwrap();
        let out_wrapped = extract_canonical_policy_data_bytes(wrapped.as_bytes()).unwrap();
        assert_eq!(out_bare, out_wrapped);
    }

    #[test]
    fn extract_is_canonical_across_key_order() {
        let order_a = r#"{"version":"2.0","id":"X","policySvn":7,"policy":[{"b":2,"a":1}],"collaterals":{"teeType":129,"majorVersion":1,"minorVersion":0},"servtdCollateral":{"servtdIdentity":{"tdIdentity":{"version":1,"id":"i"},"signature":"aa"},"servtdTcbMapping":{"x":1}}}"#;
        let order_b = r#"{"policy":[{"a":1,"b":2}],"id":"X","policySvn":7,"version":"2.0","servtdCollateral":{"servtdTcbMapping":{"x":1},"servtdIdentity":{"signature":"aa","tdIdentity":{"id":"i","version":1}}},"collaterals":{"minorVersion":0,"majorVersion":1,"teeType":129}}"#;
        let out_a = extract_canonical_policy_data_bytes(order_a.as_bytes()).unwrap();
        let out_b = extract_canonical_policy_data_bytes(order_b.as_bytes()).unwrap();
        assert_eq!(out_a, out_b);
    }

    #[test]
    fn extract_rejects_non_object_top_level() {
        assert!(extract_canonical_policy_data_bytes(b"\"just-a-string\"").is_err());
        assert!(extract_canonical_policy_data_bytes(b"[]").is_err());
        assert!(extract_canonical_policy_data_bytes(b"null").is_err());
        assert!(extract_canonical_policy_data_bytes(b"42").is_err());
    }

    #[test]
    fn extract_rejects_malformed_json() {
        assert!(extract_canonical_policy_data_bytes(b"{not-json").is_err());
    }

    #[test]
    fn extract_rejects_missing_servtd_collateral() {
        let input = br#"{"version":"2.0","id":"X","policySvn":1,"policy":[],"collaterals":{}}"#;
        assert!(extract_canonical_policy_data_bytes(input).is_err());
    }

    #[test]
    fn extract_rejects_non_object_servtd_collateral() {
        for shape in [
            br#"{"servtdCollateral":null}"#.as_slice(),
            br#"{"servtdCollateral":"a-string"}"#.as_slice(),
            br#"{"servtdCollateral":[]}"#.as_slice(),
            br#"{"servtdCollateral":42}"#.as_slice(),
        ] {
            assert!(
                extract_canonical_policy_data_bytes(shape).is_err(),
                "expected error for shape: {:?}",
                core::str::from_utf8(shape).unwrap()
            );
        }
    }

    #[test]
    fn extract_rejects_servtd_collateral_without_tcb_mapping() {
        let input = br#"{"servtdCollateral":{"a":1}}"#;
        assert!(extract_canonical_policy_data_bytes(input).is_err());

        let input2 = br#"{"servtdCollateral":{"majorVersion":1,"servtdIdentity":{"tdIdentity":{"id":"i"},"signature":"aa"}}}"#;
        assert!(extract_canonical_policy_data_bytes(input2).is_err());
    }

    #[test]
    fn extract_empty_tcb_mapping_object_is_equivalent_to_post_redaction() {
        // Pre-final and signed mappings are equivalent after redaction.
        let pre_final = r#"{"servtdCollateral":{"majorVersion":1,"servtdIdentity":{"tdIdentity":{"id":"i"},"signature":"aa"},"servtdTcbMapping":{}}}"#;
        let final_pol = r#"{"servtdCollateral":{"majorVersion":1,"servtdIdentity":{"tdIdentity":{"id":"i"},"signature":"aa"},"servtdTcbMapping":{"svnMappings":[{"isvsvn":7,"tdMeasurements":{"tdinfo_hash":"deadbeef"}}],"signature":"bb"}}}"#;
        let out_pre = extract_canonical_policy_data_bytes(pre_final.as_bytes()).unwrap();
        let out_final = extract_canonical_policy_data_bytes(final_pol.as_bytes()).unwrap();
        assert_eq!(out_pre, out_final);
    }

    #[test]
    fn extract_measures_forward_and_backward_policy() {
        let with_fwd_bwd = r#"{"policy":[],"forwardPolicy":[{"deny":"all"}],"backwardPolicy":[{"deny":"all"}],"servtdCollateral":{"servtdTcbMapping":{}}}"#;
        let without = r#"{"policy":[],"servtdCollateral":{"servtdTcbMapping":{}}}"#;
        let out_with = extract_canonical_policy_data_bytes(with_fwd_bwd.as_bytes()).unwrap();
        let out_without = extract_canonical_policy_data_bytes(without.as_bytes()).unwrap();
        assert_ne!(out_with, out_without);
    }

    #[test]
    fn extract_sample_policy_canonical_bytes() {
        let out =
            extract_canonical_policy_data_bytes(sample_bare_policy_data().as_bytes()).unwrap();
        let expected = br#"{"collaterals":{"majorVersion":1,"minorVersion":0,"teeType":129},"id":"X-uuid","policy":[{"global":{"tcb":{"tcbDate":{"operation":"ge","reference":"2023"}}}},{"servtd":{"x":1}}],"policySvn":7,"servtdCollateral":{"majorVersion":1,"minorVersion":0,"servtdIdentity":{"signature":"deadbeef","tdIdentity":{"id":"identity-1","tcbLevels":[],"version":1}},"servtdIdentityIssuerChain":"chain","servtdTcbMappingIssuerChain":"mapping-chain"},"version":"2.0"}"#;
        assert_eq!(&out, expected);
    }

    // Redaction completeness

    /// Record every dotted path whose final object key matches `target`.
    fn collect_key_paths(
        v: &Value,
        target: &str,
        current: &mut alloc::string::String,
        out: &mut Vec<alloc::string::String>,
    ) {
        match v {
            Value::Object(map) => {
                for (k, child) in map.iter() {
                    let prev_len = current.len();
                    if !current.is_empty() {
                        current.push('.');
                    }
                    current.push_str(k);
                    if k == target {
                        out.push(current.clone());
                    }
                    collect_key_paths(child, target, current, out);
                    current.truncate(prev_len);
                }
            }
            Value::Array(arr) => {
                for (i, e) in arr.iter().enumerate() {
                    let prev_len = current.len();
                    current.push_str(&format!("[{}]", i));
                    collect_key_paths(e, target, current, out);
                    current.truncate(prev_len);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn extract_input_has_servtd_tcb_mapping_only_at_expected_path() {
        let v: Value = serde_json::from_str(sample_bare_policy_data()).unwrap();
        let mut paths = Vec::new();
        let mut cur = alloc::string::String::new();
        collect_key_paths(&v, "servtdTcbMapping", &mut cur, &mut paths);
        assert_eq!(
            paths.len(),
            1,
            "servtdTcbMapping must appear exactly once in the sample; found at: {:?}",
            paths
        );
        assert_eq!(paths[0], "servtdCollateral.servtdTcbMapping");
    }

    #[test]
    fn extract_canonical_bytes_do_not_contain_field_name() {
        let out =
            extract_canonical_policy_data_bytes(sample_bare_policy_data().as_bytes()).unwrap();
        let needle = b"\"servtdTcbMapping\"";
        assert!(
            !out.windows(needle.len()).any(|w| w == needle),
            "canonical output contained redacted field name: {}",
            core::str::from_utf8(&out).unwrap_or("<non-utf8>")
        );
        let inner_needle = b"\"svnMappings\"";
        assert!(
            !out.windows(inner_needle.len()).any(|w| w == inner_needle),
            "canonical output contained inner mapping key: {}",
            core::str::from_utf8(&out).unwrap_or("<non-utf8>")
        );
    }
}
