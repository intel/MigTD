// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Policy v2 measurement primitives for one-hash TCB mappings.
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
//! `compute_signer_anchor` returns the 48-byte value `A` where
//! `A = SHA384(tag || 0x00 || R || 0x00 || DN || 0x00 || SAN || 0x00 || EKU_OID)`,
//! where `tag = "MIGTD-RTMR1-ANCHOR-V2"`, `R = SHA384(DER(root_cert))`,
//! `DN = SHA384(DER(leaf Subject Distinguished Name))`, and
//! `SAN = SHA384(0x00)` when the leaf has no Subject Alternative Name extension,
//! or `SHA384(0x01 || DER(GeneralNames))` when it does.
//! `EKU_OID` is the DER-encoded, dedicated signer-purpose EKU from the leaf.
//! Names are bound byte-for-byte, without normalization or SAN reordering.
//! The event-log writer hashes `A` and extends RTMR1 with `SHA384(A)`.
//!
//! ## `tdinfo_hash` = `init_servtd_info_hash`
//!
//! Production MigTDs use `servtd_attr == 0`, so the mapping stores
//! `SHA384(TDINFO)` for direct lookup.

use alloc::{string::String, vec::Vec};
use crypto::{
    extract_leaf_eku_oid_der_from_chain_pem, extract_leaf_identity_from_chain_pem,
    hash::digest_sha384, split_chain_pem_to_leaf_and_root_der, LeafIdentity, SHA384_DIGEST_SIZE,
};
use serde_json::Value;

use crate::PolicyError;

pub const SIGNER_ANCHOR_DOMAIN_TAG: &[u8] = b"MIGTD-RTMR1-ANCHOR-V2";

/// Single byte separator (`0x00`) between anchor components.
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

    // Redact the servtd collateral sub-fields when a `servtdCollateral` object
    // is present. A CoRIM-only policy omits `servtdCollateral` entirely; there
    // is then nothing to redact and the whole `policyData` is measured as-is.
    match policy_data.get_mut("servtdCollateral") {
        None => {}
        Some(value) => {
            let coll = value.as_object_mut().ok_or(PolicyError::InvalidPolicy)?;

            if coll.remove("servtdTcbMapping").is_none() {
                return Err(PolicyError::InvalidPolicy);
            }

            // Also redact `servtdTcbMappingIssuerChain`: it is already measured
            // into RTMR1 (the signer anchor), so measuring it again here would
            // be redundant AND would re-couple leaf/intermediate-CA rotation of
            // the TCB-mapping signer to `tdinfo_hash`.
            //
            // Non-strict (remove if present): the security binding does not rest
            // on this redaction: `RawPolicyData::verify` separately requires the
            // chain that verifies `servtdTcbMapping` to hash to the RTMR1 signer
            // anchor, so a swapped/absent chain fails closed there.
            coll.remove("servtdTcbMappingIssuerChain");
        }
    }

    canonical_value_bytes(&policy_data)
}

/// Compute the RTMR1 signer anchor `A` from the root, leaf identity, and purpose.
///
/// `A = SHA384(tag || 0x00 || R || 0x00 || DN || 0x00 || SAN || 0x00 || EKU_OID)`
///
/// `R` and `DN` hash the root certificate DER and leaf Subject DN DER.
/// `SAN` hashes `0x00` for absence or `0x01 || DER(GeneralNames)` for presence.
/// `EKU_OID` is the DER-encoded, dedicated signer-purpose OID.
pub fn compute_signer_anchor(
    root_der: &[u8],
    leaf_identity: &LeafIdentity,
    leaf_eku_oid_der: &[u8],
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    let r = digest_sha384(root_der).map_err(|_| PolicyError::HashCalculation)?;
    let dn =
        digest_sha384(&leaf_identity.subject_dn_der).map_err(|_| PolicyError::HashCalculation)?;
    let mut san_input = Vec::new();
    match &leaf_identity.subject_alt_name_der {
        Some(der) => {
            san_input.push(1);
            san_input.extend_from_slice(der);
        }
        None => san_input.push(0),
    }
    let san = digest_sha384(&san_input).map_err(|_| PolicyError::HashCalculation)?;

    let mut buf = Vec::with_capacity(
        SIGNER_ANCHOR_DOMAIN_TAG.len()
            + 4
            + r.len()
            + dn.len()
            + san.len()
            + leaf_eku_oid_der.len(),
    );
    buf.extend_from_slice(SIGNER_ANCHOR_DOMAIN_TAG);
    buf.push(SIGNER_ANCHOR_SEPARATOR);
    buf.extend_from_slice(&r);
    buf.push(SIGNER_ANCHOR_SEPARATOR);
    buf.extend_from_slice(&dn);
    buf.push(SIGNER_ANCHOR_SEPARATOR);
    buf.extend_from_slice(&san);
    buf.push(SIGNER_ANCHOR_SEPARATOR);
    buf.extend_from_slice(leaf_eku_oid_der);

    let digest = digest_sha384(&buf).map_err(|_| PolicyError::HashCalculation)?;
    let mut out = [0u8; SHA384_DIGEST_SIZE];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Compute the RTMR1 signer anchor directly from a PEM cert chain (leaf-first).
///
/// Bind the root certificate, leaf Subject DN, optional SAN, and single
/// dedicated EKU using the same identity extraction as peer validation.
pub fn compute_signer_anchor_from_chain_pem(
    chain_pem: &[u8],
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    let (_, root_der) =
        split_chain_pem_to_leaf_and_root_der(chain_pem).map_err(|_| PolicyError::InvalidPolicy)?;
    let leaf_eku_oid = extract_leaf_eku_oid_der_from_chain_pem(chain_pem)
        .map_err(|_| PolicyError::InvalidPolicy)?;
    let leaf_identity =
        extract_leaf_identity_from_chain_pem(chain_pem).map_err(|_| PolicyError::InvalidPolicy)?;
    compute_signer_anchor(&root_der, &leaf_identity, &leaf_eku_oid)
}

/// Resolve a signer anchor from either representation carried in the CFV /
/// exchanged with a peer:
///
/// * a **precomputed 48-byte anchor** (exactly `SHA384_DIGEST_SIZE` bytes) —
///   returned as-is (the CoRIM-only enrollment form, which does not carry a
///   full PEM), or
/// * a **PEM issuer chain** (leaf-first) — the anchor is derived via
///   [`compute_signer_anchor_from_chain_pem`] (the legacy JSON form).
///
/// This lets the runtime accept either enrollment/exchange form and bind the
/// same RTMR1 anchor. A PEM is never 48 bytes, so the discriminator is
/// unambiguous.
pub fn resolve_signer_anchor(input: &[u8]) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    if input.len() == SHA384_DIGEST_SIZE {
        let mut anchor = [0u8; SHA384_DIGEST_SIZE];
        anchor.copy_from_slice(input);
        Ok(anchor)
    } else {
        compute_signer_anchor_from_chain_pem(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(subject_dn: &[u8], san: Option<&[u8]>) -> LeafIdentity {
        LeafIdentity {
            subject_dn_der: subject_dn.to_vec(),
            subject_alt_name_der: san.map(|value| value.to_vec()),
        }
    }

    #[test]
    fn signer_anchor_matches_fixed_vector() {
        let expected = [
            0x7b, 0x1b, 0x3c, 0x58, 0xbf, 0x03, 0x15, 0x83, 0xb3, 0x75, 0x6c, 0xf3, 0xe7, 0x69,
            0x6f, 0x63, 0x1b, 0xcd, 0x6f, 0x1e, 0x35, 0x90, 0x0f, 0xd5, 0xd7, 0xe3, 0xf5, 0x65,
            0x9c, 0xa9, 0xc3, 0xc5, 0x5c, 0xf4, 0xbf, 0x0f, 0x51, 0x68, 0xe9, 0xf6, 0xc4, 0xd0,
            0x61, 0x6b, 0x53, 0xb5, 0x96, 0xc4,
        ];
        assert_eq!(
            compute_signer_anchor(
                b"root DER",
                &identity(b"leaf Subject DN DER", None),
                b"\x06\x0a\x2b\x06\x01\x04\x01\x81\xfd\x59\x01\x01"
            )
            .unwrap(),
            expected
        );
    }

    #[test]
    fn signer_anchor_with_san_matches_fixed_vector() {
        let expected = [
            0x1c, 0xa4, 0x12, 0xf8, 0x2e, 0xdb, 0x45, 0x88, 0xb8, 0x1f, 0x84, 0x6f, 0x10, 0x5e,
            0xf7, 0x7e, 0x08, 0xab, 0x83, 0x45, 0xe7, 0xf7, 0xd7, 0x0b, 0x39, 0xdf, 0x10, 0x70,
            0x5b, 0x66, 0xcb, 0xed, 0x46, 0xcd, 0x3e, 0xc6, 0xec, 0xb7, 0xe2, 0x7e, 0xe0, 0x30,
            0x00, 0x83, 0x39, 0xc0, 0x9a, 0xb1,
        ];
        assert_eq!(
            compute_signer_anchor(
                b"root DER",
                &identity(
                    b"leaf Subject DN DER",
                    Some(b"\x30\x0f\x82\x0dmigtd.example")
                ),
                b"\x06\x0a\x2b\x06\x01\x04\x01\x81\xfd\x59\x01\x01",
            )
            .unwrap(),
            expected
        );
    }

    #[test]
    fn signer_anchor_from_pem_matches_fixed_vector() {
        let chain = include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        let expected = [
            0xac, 0x30, 0x8e, 0x48, 0x2c, 0xa5, 0xeb, 0x78, 0x71, 0x03, 0x4d, 0x6b, 0x7f, 0xce,
            0xe2, 0xf3, 0xa2, 0x94, 0x27, 0x25, 0x0d, 0xaa, 0xfd, 0xa0, 0x9e, 0x0b, 0x81, 0xb9,
            0xe1, 0xf8, 0x19, 0x46, 0xe4, 0xb7, 0xf1, 0xaf, 0xf1, 0xb2, 0xdf, 0xec, 0x18, 0x45,
            0x4a, 0x42, 0xe3, 0x9c, 0x21, 0x69,
        ];
        assert_eq!(
            compute_signer_anchor_from_chain_pem(chain).unwrap(),
            expected
        );
    }

    #[test]
    fn signer_anchor_changes_with_root_identity_or_eku() {
        let leaf = identity(b"subject1", Some(b"san1"));
        let original = compute_signer_anchor(b"root1", &leaf, b"\x06\x02\x2a\x03").unwrap();
        for changed in [
            compute_signer_anchor(b"root2", &leaf, b"\x06\x02\x2a\x03"),
            compute_signer_anchor(b"root1", &leaf, b"\x06\x02\x2a\x04"),
            compute_signer_anchor(
                b"root1",
                &identity(b"subject2", Some(b"san1")),
                b"\x06\x02\x2a\x03",
            ),
            compute_signer_anchor(
                b"root1",
                &identity(b"subject1", Some(b"san2")),
                b"\x06\x02\x2a\x03",
            ),
            compute_signer_anchor(b"root1", &identity(b"subject1", None), b"\x06\x02\x2a\x03"),
        ] {
            assert_ne!(original, changed.unwrap());
        }
    }

    #[test]
    fn signer_anchor_distinguishes_absent_and_present_empty_san() {
        let absent =
            compute_signer_anchor(b"root", &identity(b"subject", None), b"\x06\x02\x2a\x03")
                .unwrap();
        let present = compute_signer_anchor(
            b"root",
            &identity(b"subject", Some(b"")),
            b"\x06\x02\x2a\x03",
        )
        .unwrap();
        assert_ne!(absent, present);
    }

    #[test]
    fn signer_anchor_preserves_key_rotation_with_stable_identity_and_eku() {
        let a = compute_signer_anchor_from_chain_pem(include_bytes!(
            "../../../crypto/test/eku/signer_identity_a.pem"
        ))
        .unwrap();
        let rotated = compute_signer_anchor_from_chain_pem(include_bytes!(
            "../../../crypto/test/eku/signer_identity_rotated.pem"
        ))
        .unwrap();

        assert_eq!(a, rotated);
        for changed in [
            include_bytes!("../../../crypto/test/eku/signer_subject_mismatch.pem").as_slice(),
            include_bytes!("../../../crypto/test/eku/signer_san_mismatch.pem").as_slice(),
            include_bytes!("../../../crypto/test/eku/signer_identity_other_eku.pem").as_slice(),
        ] {
            assert_ne!(a, compute_signer_anchor_from_chain_pem(changed).unwrap());
        }
    }

    #[test]
    fn signer_anchor_from_chain_requires_single_dedicated_eku() {
        for chain in [
            include_bytes!("../../../crypto/test/eku/signer_no_eku.pem").as_slice(),
            include_bytes!("../../../crypto/test/eku/signer_multiple_eku.pem").as_slice(),
            include_bytes!("../../../crypto/test/eku/signer_any_eku.pem").as_slice(),
        ] {
            assert!(compute_signer_anchor_from_chain_pem(chain).is_err());
        }
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
        r#"{"id":"X-uuid","version":"2.0","policySvn":7,"policy":[{"global":{"tcb":{"tcbDate":{"reference":"2023","operation":"ge"}}}},{"servtd":{"x":1}}],"collaterals":{"majorVersion":1,"minorVersion":0,"teeType":129},"servtdCollateral":{"majorVersion":1,"minorVersion":0,"servtdIdentityIssuerChain":"chain","servtdIdentity":{"tdIdentity":{"id":"identity-1","version":1,"tcbLevels":[]},"signature":"deadbeef"},"servtdTcbMapping":{"svnMappings":[{"isvsvn":1}]}}}"#
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
        let a = r#"{"id":"X","version":"2","policySvn":1,"policy":[],"collaterals":{},"servtdCollateral":{"majorVersion":1,"minorVersion":0,"servtdIdentityIssuerChain":"c","servtdIdentity":{"tdIdentity":{"id":"i"},"signature":"aa"},"servtdTcbMapping":{"svnMappings":[{"isvsvn":1}]}}}"#;
        let b = r#"{"id":"X","version":"2","policySvn":1,"policy":[],"collaterals":{},"servtdCollateral":{"majorVersion":1,"minorVersion":0,"servtdIdentityIssuerChain":"c","servtdIdentity":{"tdIdentity":{"id":"i"},"signature":"aa"},"servtdTcbMapping":{"svnMappings":[{"isvsvn":99},{"isvsvn":100}]}}}"#;
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
    fn extract_protects_identity_issuer_chain() {
        let a =
            r#"{"servtdCollateral":{"servtdIdentityIssuerChain":"chain-A","servtdTcbMapping":{}}}"#;
        let b =
            r#"{"servtdCollateral":{"servtdIdentityIssuerChain":"chain-B","servtdTcbMapping":{}}}"#;
        let out_a = extract_canonical_policy_data_bytes(a.as_bytes()).unwrap();
        let out_b = extract_canonical_policy_data_bytes(b.as_bytes()).unwrap();
        assert_ne!(out_a, out_b);
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
    fn extract_allows_missing_servtd_collateral() {
        // CoRIM-only policies omit `servtdCollateral` entirely: there is nothing
        // to redact, so the whole `policyData` is measured as-is (Ok). The
        // servtd endorsement is delivered as a separately-enrolled CoRIM.
        let input = br#"{"version":"2.0","id":"X","policySvn":1,"policy":[],"collaterals":{}}"#;
        assert!(extract_canonical_policy_data_bytes(input).is_ok());
    }

    #[test]
    fn extract_measures_top_level_servtd_crl() {
        let empty = br#"{"version":"2.0","id":"X","servtdCrl":"empty"}"#;
        let revoked = br#"{"version":"2.0","id":"X","servtdCrl":"revoked"}"#;
        let out_empty = extract_canonical_policy_data_bytes(empty).unwrap();
        let out_revoked = extract_canonical_policy_data_bytes(revoked).unwrap();
        assert_ne!(out_empty, out_revoked);
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
        let expected = br#"{"collaterals":{"majorVersion":1,"minorVersion":0,"teeType":129},"id":"X-uuid","policy":[{"global":{"tcb":{"tcbDate":{"operation":"ge","reference":"2023"}}}},{"servtd":{"x":1}}],"policySvn":7,"servtdCollateral":{"majorVersion":1,"minorVersion":0,"servtdIdentity":{"signature":"deadbeef","tdIdentity":{"id":"identity-1","tcbLevels":[],"version":1}},"servtdIdentityIssuerChain":"chain"},"version":"2.0"}"#;
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
