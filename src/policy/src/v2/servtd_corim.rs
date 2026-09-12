// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! CoRIM-based hash endorsement: decodes the signed TCB-mapping CoRIM generated
//! during a MigTD production release (referred to as the "producer" below) and
//! resolves a `tdinfo_hash` to a [`ServtdLookup`] (the MigTD ISV SVN). This is
//! the only alternative to the legacy JSON collateral; the legacy path stays
//! unchanged from the one-hash redesign.
//!
//! # One document
//!
//! The producer emits a single signed **TCB Mapping CoRIM**
//! (`SERVTD_INFO_HASH -> isvsvn`), which MigTD carries in its CFV. Each
//! authorized release contributes two triples in the shared `migration-td`
//! environment (`class = { vendor: "Intel", model: "TDX" }`,
//! `instance = #6.560("migration-td")`):
//!
//! * a `reference-triple` whose single `MeasurementMap.mval.digests[0]` is
//!   the ServTD info hash (authenticity), and
//! * a `conditional-endorsement-series` (CES) triple whose series record
//!   *selects* on that digest and *adds* `mval.svn = ExactValue(svn)`.
//!
//! The hash -> svn lookup is driven by the CES triples. An optional JSON TD
//! Identity can then supply `tcb_date` / `tcb_status` for that SVN. A CoRIM
//! lookup miss never falls back to the JSON TCB mapping.
//!
//! # `no_std`
//!
//! Built `#![no_std]` in MigTD; decode uses
//! [`corim::validate::decode_and_validate_at`] (the `_at` variant) so no
//! `SystemTime` is touched.
//!
//! # Signature verification
//!
//! [`ServtdCorim::decode_signed`] verifies the surrounding `COSE_Sign1`
//! envelope: it checks the ES384 signature against the embedded RFC 9360
//! `x5chain` (via the `crypto` crate) and binds the chain's trust anchor to
//! the RTMR1-measured policy signer anchor ([`compute_signer_anchor`]), so a
//! CoRIM is only trusted when signed by the same root-of-trust the firmware
//! measured from the CFV policy issuer chain. [`ServtdCorim::decode`] takes
//! already-verified inner payload bytes and performs decode + match only.

use alloc::{collections::BTreeMap, vec::Vec};
use core::convert::TryFrom;

use corim::{
    types::{
        comid::ComidTag,
        environment::EnvironmentMap,
        measurement::{MeasurementMap, SvnChoice},
        signed::{decode_signed_corim, CoseAlgorithm, CwtClaims},
    },
    validate::decode_and_validate_at,
};

use crypto::SHA384_DIGEST_SIZE;

use crate::{
    v2::{compute_signer_anchor, ServtdLookup},
    PolicyError,
};

// ---- MigTD CoRIM wire-format constants -----------------------------------

/// Component class for the TCB Mapping: `class = { vendor: "Intel",
/// model: "TDX" }` (no `class-id`). The producer switched from a shared
/// class-id UUID to this vendor/model class.
pub const CLASS_VENDOR: &str = "Intel";
/// See [`CLASS_VENDOR`].
pub const CLASS_MODEL: &str = "TDX";

/// Instance bytes for the TCB Mapping environment
/// (`environment.instance = #6.560("migration-td")`).
pub const MIGRATION_TD_INSTANCE_BYTES: &[u8] = b"migration-td";

/// Decoded CoRIM servtd collateral: the TCB Mapping document (hash -> svn).
pub struct ServtdCorim {
    /// CoMID tags from the TCB Mapping CoRIM (digest-selecting CES).
    tcb_mapping: Vec<ComidTag>,
    svn_mappings: BTreeMap<Vec<u8>, u16>,
    /// Verified leaf-first COSE `x5chain`, retained so callers can apply the
    /// locally authoritative servTD CRL after signature/anchor verification.
    signer_chain: Option<Vec<Vec<u8>>>,
}

impl ServtdCorim {
    /// Decode the TCB Mapping CoRIM blob (CBOR, `#6.501` unsigned wrapper) and
    /// validate its structure, reference/CES pairing, and hash-to-SVN consistency.
    /// `now_epoch_secs` evaluates any embedded validity windows.
    ///
    /// Signature verification of the surrounding `COSE_Sign1` envelope is the
    /// caller's responsibility; this input is the inner payload bytes.
    pub fn decode(tcb_mapping_cbor: &[u8], now_epoch_secs: i64) -> Result<Self, PolicyError> {
        let (_c1, tcb_mapping) = decode_and_validate_at(tcb_mapping_cbor, now_epoch_secs)
            .map_err(|_| PolicyError::InvalidServtdTcbMapping)?;
        let svn_mappings = validated_svn_mappings(&tcb_mapping)?;
        Ok(Self {
            tcb_mapping,
            svn_mappings,
            signer_chain: None,
        })
    }

    /// Decode a signed COSE_Sign1 CoRIM after verifying its ES384 signature,
    /// x5chain, and RTMR1 signer-anchor binding.
    pub fn decode_signed(
        tcb_mapping_cose: &[u8],
        now_epoch_secs: i64,
        expected_signer_anchor: &[u8; SHA384_DIGEST_SIZE],
    ) -> Result<Self, PolicyError> {
        let (tcb_payload, signer_chain) =
            verify_and_extract_payload(tcb_mapping_cose, expected_signer_anchor)
                .map_err(|_| PolicyError::InvalidServtdTcbMapping)?;
        let mut corim = Self::decode(&tcb_payload, now_epoch_secs)?;
        corim.signer_chain = Some(signer_chain);
        Ok(corim)
    }

    /// Apply an authenticated servTD CRL to the verified COSE signer chain.
    ///
    /// The CRL must come from the local measured policy. Peer-supplied CRLs
    /// must never be passed here as authority.
    pub fn verify_signer_chain_not_revoked(&self, servtd_crl: &[u8]) -> Result<(), PolicyError> {
        let signer_chain = self
            .signer_chain
            .as_ref()
            .ok_or(PolicyError::SignatureVerificationFailed)?;
        let signer_chain: Vec<&[u8]> = signer_chain.iter().map(|cert| cert.as_slice()).collect();
        crypto::verify_signer_chain_not_revoked(crypto::SignerChain::Der(&signer_chain), servtd_crl)
            .map_err(|_| PolicyError::SignerRevoked)
    }

    /// Resolve `SERVTD_INFO_HASH -> isvsvn` via the TCB Mapping CES triples.
    ///
    /// The digest is matched by **value** only; the producer currently labels
    /// the 48-byte SHA-384 ServTD info hash with the SHA-256 algorithm id
    /// (see the design-review gap note), so the algorithm field is not
    /// enforced here.
    fn svn_for_hash(&self, hash: &[u8]) -> Option<u16> {
        self.svn_mappings.get(hash).copied()
    }

    /// Number of CoMID tags in the TCB Mapping document. Exposed for
    /// diagnostics.
    pub fn comid_count(&self) -> usize {
        self.tcb_mapping.len()
    }

    /// Resolve the MigTD ISV SVN for the MigTD whose masked `TDINFO_STRUCT`
    /// hashes to `tdinfo_hash` (the 48-byte `init/cur_servtd_info_hash`).
    /// Returns `None` if the hash is not endorsed by this CoRIM.
    pub fn lookup_by_tdinfo_hash(&self, tdinfo_hash: &[u8]) -> Option<ServtdLookup> {
        let isvsvn = self.svn_for_hash(tdinfo_hash)?;
        Some(ServtdLookup {
            isvsvn,
            tcb_date: None,
            tcb_status: None,
        })
    }
}

// ---- COSE_Sign1 envelope + signature verification --------------------------

/// Verify a signed `COSE_Sign1-corim` (`#6.18`) and return its attached CoRIM
/// payload bytes (`bstr .cbor #6.501(corim-map)`) plus the verified `x5chain`.
///
/// The signature and RTMR1-anchor checks are performed before any byte is
/// returned. The caller retains the returned chain and applies the locally
/// authoritative servTD CRL before trusting the CoRIM:
/// 1. Parse the COSE envelope; require an **attached** payload.
/// 2. Require the protected `alg` to be ES384/ESP384 (ECDSA-P384/SHA-384) and
///    an RFC 9360 `x5chain` to be present.
/// 3. Verify the x5chain integrity and the COSE signature over the
///    `Sig_structure1` TBS (delegated to the `crypto` crate).
/// 4. Bind the chain's `(root, leaf-subject)` to `expected_signer_anchor` —
///    the RTMR1-measured policy signer anchor — so the CoRIM signer is the
///    same root-of-trust the firmware measured from the CFV. A mismatch is
///    fatal (fail-closed).
fn verify_and_extract_payload(
    cose: &[u8],
    expected_signer_anchor: &[u8; SHA384_DIGEST_SIZE],
) -> Result<(Vec<u8>, Vec<Vec<u8>>), PolicyError> {
    let envelope =
        decode_signed_corim(cose).map_err(|_| PolicyError::SignatureVerificationFailed)?;

    if has_cwt_time_claims(envelope.protected.cwt_claims.as_ref()) {
        return Err(PolicyError::SignatureVerificationFailed);
    }

    // Only ECDSA-P384/SHA-384 is supported by the crypto crate. Accept both
    // the deprecated polymorphic ES384 (-35, what the producer emits today)
    // and its fully-specified RFC 9864 replacement ESP384 (-51).
    match envelope.protected.alg {
        CoseAlgorithm::Es384 | CoseAlgorithm::Esp384 => {}
        _ => return Err(PolicyError::SignatureVerificationFailed),
    }

    let x5chain = envelope
        .protected
        .x5chain
        .as_ref()
        .ok_or(PolicyError::SignatureVerificationFailed)?;
    let certs = x5chain.certs();

    let tbs = envelope
        .to_be_signed(&[])
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    let (root_der, leaf_subject_der) =
        crypto::verify_cose_sign1_es384_x5chain(&certs, &tbs, &envelope.signature)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    let anchor = compute_signer_anchor(&root_der, &leaf_subject_der)?;
    if anchor != *expected_signer_anchor {
        return Err(PolicyError::SignatureVerificationFailed);
    }

    let payload = envelope
        .payload
        .ok_or(PolicyError::SignatureVerificationFailed)?;
    let signer_chain = certs.iter().map(|cert| cert.to_vec()).collect();
    Ok((payload, signer_chain))
}

fn has_cwt_time_claims(claims: Option<&CwtClaims>) -> bool {
    matches!(claims, Some(claims) if claims.nbf.is_some() || claims.exp.is_some())
}

// ---- Environment matching --------------------------------------------------

/// Return whether both class and instance identify the migration-TD environment.
fn is_migration_td_environment(env: &EnvironmentMap) -> bool {
    use corim::types::common::InstanceIdChoice;

    let class_ok = env
        .class
        .as_ref()
        .map(|c| {
            c.vendor.as_deref() == Some(CLASS_VENDOR) && c.model.as_deref() == Some(CLASS_MODEL)
        })
        .unwrap_or(false);

    let instance_ok = matches!(
        env.instance.as_ref(),
        Some(InstanceIdChoice::Bytes(b)) if b.as_slice() == MIGRATION_TD_INSTANCE_BYTES
    );

    class_ok && instance_ok
}

// ---- TCB Mapping (CES) helpers --------------------------------------------

fn validated_svn_mappings(comids: &[ComidTag]) -> Result<BTreeMap<Vec<u8>, u16>, PolicyError> {
    let mut references: BTreeMap<&[u8], Vec<&EnvironmentMap>> = BTreeMap::new();
    for comid in comids {
        for reference in comid.triples.reference_triples.iter().flatten() {
            if !is_migration_td_environment(reference.environment()) {
                continue;
            }
            for hash in reference.measurements().iter().filter_map(digest_value) {
                references
                    .entry(hash)
                    .or_default()
                    .push(reference.environment());
            }
        }
    }

    let mut mappings = BTreeMap::new();
    for comid in comids {
        for ces in comid
            .triples
            .conditional_endorsement_series
            .iter()
            .flatten()
        {
            let environment = &ces.condition().environment;
            if !is_migration_td_environment(environment) {
                continue;
            }
            for record in ces.series() {
                let hash = record
                    .selection()
                    .first()
                    .and_then(digest_value)
                    .ok_or(PolicyError::InvalidServtdTcbMapping)?;
                if hash.len() != SHA384_DIGEST_SIZE
                    || !references
                        .get(hash)
                        .is_some_and(|environments| environments.contains(&environment))
                {
                    return Err(PolicyError::InvalidServtdTcbMapping);
                }
                let svn = record
                    .addition()
                    .first()
                    .and_then(svn_exact)
                    .and_then(|svn| u16::try_from(svn).ok())
                    .ok_or(PolicyError::InvalidServtdTcbMapping)?;
                if let Some(previous) = mappings.insert(hash.to_vec(), svn) {
                    if previous != svn {
                        return Err(PolicyError::InvalidServtdTcbMapping);
                    }
                }
            }
        }
    }
    Ok(mappings)
}

/// First digest value of a measurement (the ServTD info hash).
fn digest_value(m: &MeasurementMap) -> Option<&[u8]> {
    Some(m.mval.digests.as_ref()?.first()?.value())
}

/// The exact SVN carried by a measurement's `mval.svn`, if present.
fn svn_exact(m: &MeasurementMap) -> Option<u64> {
    match m.mval.svn {
        Some(SvnChoice::ExactValue(n)) => Some(n),
        _ => None,
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use alloc::{vec, vec::Vec};
    use corim::{
        builder::{ComidBuilder, CorimBuilder},
        types::{
            common::{InstanceIdChoice, TagIdChoice},
            corim::CorimId,
            environment::{ClassMap, EnvironmentMap},
            measurement::{Digest, MeasurementValuesMap},
            signed::SignedCorimBuilder,
            triples::{
                CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord,
                ReferenceTriple,
            },
        },
    };

    /// Producer's (mislabeled) digest alg id — see the SHA-256/SHA-384 gap.
    const SHA256_ALG: i64 = 1;

    const EMULATION_COSE: &[u8] = include_bytes!("../../test/policy_v2/corim/tcb_mapping.corim");
    const EMULATION_ANCHOR: &[u8; SHA384_DIGEST_SIZE] =
        include_bytes!("../../test/policy_v2/corim/signer_anchor.bin");
    const EMULATION_CRL: &[u8] = include_bytes!("../../test/policy_v2/corim/servtd.crl.pem");
    const EMULATION_HASH: &str =
        "1ADC25055B5188A615FF0A2B4781C0E1F38D4369CA688C775EE321E142FBE4534C14EDE61D9C570967996F6C8E8F5F76";

    #[test]
    fn emulation_fixture_authenticates_the_chain_anchor_and_svn() {
        let chain = include_bytes!("../../test/policy_v2/corim/issuer_chain.pem");
        assert_eq!(
            crate::v2::compute_signer_anchor_from_chain_pem(chain).unwrap(),
            *EMULATION_ANCHOR
        );
        let corim = ServtdCorim::decode_signed(EMULATION_COSE, 0, EMULATION_ANCHOR).unwrap();
        corim
            .verify_signer_chain_not_revoked(EMULATION_CRL)
            .unwrap();
        let hash = crate::v2::hex_string_to_bytes(EMULATION_HASH).unwrap();
        assert_eq!(corim.lookup_by_tdinfo_hash(&hash).unwrap().isvsvn, 1);
    }

    #[test]
    fn emulation_fixture_rejects_wrong_anchors_and_tampered_signatures() {
        let mut wrong_anchor = *EMULATION_ANCHOR;
        wrong_anchor[0] ^= 1;
        assert!(ServtdCorim::decode_signed(EMULATION_COSE, 0, &wrong_anchor).is_err());
        let mut tampered = EMULATION_COSE.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(ServtdCorim::decode_signed(&tampered, 0, EMULATION_ANCHOR).is_err());
    }

    #[test]
    fn emulation_fixture_corim_uses_the_local_revocation_list() {
        let corim = ServtdCorim::decode_signed(EMULATION_COSE, 0, EMULATION_ANCHOR).unwrap();
        let revoked = include_bytes!("../../test/policy_v2/corim/revoked.crl.pem");
        assert!(matches!(
            corim.verify_signer_chain_not_revoked(revoked),
            Err(PolicyError::SignerRevoked)
        ));
    }

    #[test]
    fn emulation_fixture_supports_direct_anchor_and_optional_json_identity() {
        let mut value: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../test/policy_v2/policy_v2.json")).unwrap();
        value["policyData"]["servtdCollateral"] = serde_json::from_slice(include_bytes!(
            "../../test/policy_v2/corim/servtd_collateral.json"
        ))
        .unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        let raw = crate::v2::RawPolicyData::deserialize_from_json(&bytes).unwrap();
        let mut policy = raw.verify(EMULATION_ANCHOR).unwrap();
        policy
            .attach_verified_peer_servtd_corim(EMULATION_COSE)
            .unwrap();
        policy
            .verify_signer_chains_not_revoked(EMULATION_CRL)
            .unwrap();
        let hash = crate::v2::hex_string_to_bytes(EMULATION_HASH).unwrap();
        let lookup = policy.servtd_lookup_by_tdinfo_hash(&hash).unwrap();
        assert_eq!(lookup.isvsvn, 1);
        assert_eq!(lookup.tcb_status.as_deref(), Some("UpToDate"));
        assert_eq!(lookup.tcb_date.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    fn class() -> ClassMap {
        ClassMap {
            class_id: None,
            vendor: Some(CLASS_VENDOR.into()),
            model: Some(CLASS_MODEL.into()),
            layer: None,
            index: None,
        }
    }

    fn migration_td_env() -> EnvironmentMap {
        EnvironmentMap {
            class: Some(class()),
            instance: Some(InstanceIdChoice::Bytes(
                MIGRATION_TD_INSTANCE_BYTES.to_vec(),
            )),
            group: None,
        }
    }

    fn ref_triple(hash: &[u8]) -> ReferenceTriple {
        ReferenceTriple::new(
            migration_td_env(),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    digests: Some(vec![Digest::new(SHA256_ALG, hash.to_vec())]),
                    ..MeasurementValuesMap::new()
                },
                authorized_by: None,
            }],
        )
    }

    fn ces_triple(hash: &[u8], svn: u16) -> ConditionalEndorsementSeriesTriple {
        let condition = CesCondition {
            environment: migration_td_env(),
            claims_list: Vec::new(),
            authorized_by: None,
        };
        let selection = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(SHA256_ALG, hash.to_vec())]),
                ..MeasurementValuesMap::new()
            },
            authorized_by: None,
        };
        let addition = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(svn as u64)),
                ..MeasurementValuesMap::new()
            },
            authorized_by: None,
        };
        ConditionalEndorsementSeriesTriple::new(
            condition,
            vec![ConditionalSeriesRecord::new(
                vec![selection],
                vec![addition],
            )],
        )
    }

    /// Build a TCB Mapping CoRIM mirroring `TcbMappingCorim::add_release`:
    /// a reference-triple plus a CES triple per `(hash, svn)`.
    pub(crate) fn build_tcb_mapping(entries: &[(Vec<u8>, u16)]) -> Vec<u8> {
        let mut comid = ComidBuilder::new(TagIdChoice::Text("migtd-tcb-mapping".into()));
        for (hash, svn) in entries {
            comid = comid.add_reference_triple(ref_triple(hash));
            comid = comid.add_conditional_endorsement_series(ces_triple(hash, *svn));
        }
        build_corim(vec![comid.build().expect("build tcb-mapping comid")])
    }

    fn build_corim(comids: Vec<ComidTag>) -> Vec<u8> {
        let mut builder = CorimBuilder::new(CorimId::Text("migtd-tcb-mapping".into()));
        for comid in comids {
            builder = builder.add_comid_tag(comid).expect("attach comid");
        }
        builder.build_bytes().expect("encode corim")
    }

    fn hash(byte: u8) -> Vec<u8> {
        vec![byte; 48]
    }

    #[test]
    fn hash_lookup_resolves_svn() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5), (hash(0xBB), 7)]);
        let provider = ServtdCorim::decode(&tcb, 0).expect("decode");
        assert_eq!(provider.comid_count(), 1);

        let hit = provider.lookup_by_tdinfo_hash(&hash(0xAA)).expect("match");
        assert_eq!(hit.isvsvn, 5);

        let hit2 = provider.lookup_by_tdinfo_hash(&hash(0xBB)).expect("match");
        assert_eq!(hit2.isvsvn, 7);
    }

    #[test]
    fn unknown_hash_misses() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5)]);
        let provider = ServtdCorim::decode(&tcb, 0).expect("decode");
        assert!(provider.lookup_by_tdinfo_hash(&hash(0xCC)).is_none());
    }

    #[test]
    fn wrong_length_hash_misses() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5)]);
        let provider = ServtdCorim::decode(&tcb, 0).expect("decode");
        assert!(provider.lookup_by_tdinfo_hash(&[0xAA; 32]).is_none());
    }

    #[test]
    fn missing_reference_is_rejected() {
        let comid = ComidBuilder::new(TagIdChoice::Text("missing-reference".into()))
            .add_conditional_endorsement_series(ces_triple(&hash(0xAA), 5))
            .build()
            .unwrap();
        assert!(matches!(
            ServtdCorim::decode(&build_corim(vec![comid]), 0),
            Err(PolicyError::InvalidServtdTcbMapping)
        ));
    }

    #[test]
    fn reference_must_match_the_selected_hash() {
        let comid = ComidBuilder::new(TagIdChoice::Text("different-hash".into()))
            .add_reference_triple(ref_triple(&hash(0xAA)))
            .add_conditional_endorsement_series(ces_triple(&hash(0xBB), 5))
            .build()
            .unwrap();
        assert!(matches!(
            ServtdCorim::decode(&build_corim(vec![comid]), 0),
            Err(PolicyError::InvalidServtdTcbMapping)
        ));
    }

    #[test]
    fn reference_must_match_the_ces_environment() {
        let mut reference = ref_triple(&hash(0xAA));
        reference.0.class.as_mut().unwrap().index = Some(1);
        let comid = ComidBuilder::new(TagIdChoice::Text("different-environment".into()))
            .add_reference_triple(reference)
            .add_conditional_endorsement_series(ces_triple(&hash(0xAA), 5))
            .build()
            .unwrap();
        assert!(matches!(
            ServtdCorim::decode(&build_corim(vec![comid]), 0),
            Err(PolicyError::InvalidServtdTcbMapping)
        ));
    }

    #[test]
    fn identical_duplicate_mappings_are_accepted() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5), (hash(0xAA), 5)]);
        let provider = ServtdCorim::decode(&tcb, 0).unwrap();
        assert_eq!(
            provider.lookup_by_tdinfo_hash(&hash(0xAA)).unwrap().isvsvn,
            5
        );
    }

    #[test]
    fn conflicting_duplicate_mappings_are_rejected_in_either_order() {
        for (first, second) in [(5, 7), (7, 5)] {
            let tcb = build_tcb_mapping(&[(hash(0xAA), first), (hash(0xAA), second)]);
            assert!(matches!(
                ServtdCorim::decode(&tcb, 0),
                Err(PolicyError::InvalidServtdTcbMapping)
            ));
        }
    }

    #[test]
    fn conflicting_mappings_across_comids_are_rejected() {
        let comids = [("first", 5), ("second", 7)]
            .iter()
            .copied()
            .map(|(id, svn)| {
                ComidBuilder::new(TagIdChoice::Text(id.into()))
                    .add_reference_triple(ref_triple(&hash(0xAA)))
                    .add_conditional_endorsement_series(ces_triple(&hash(0xAA), svn))
                    .build()
                    .unwrap()
            })
            .collect();
        assert!(matches!(
            ServtdCorim::decode(&build_corim(comids), 0),
            Err(PolicyError::InvalidServtdTcbMapping)
        ));
    }

    #[test]
    fn rejects_cwt_nbf_and_exp_claims() {
        assert!(!has_cwt_time_claims(Some(&CwtClaims::new("test-signer"))));
        assert!(has_cwt_time_claims(Some(
            &CwtClaims::new("test-signer").with_nbf(1)
        )));
        assert!(has_cwt_time_claims(Some(
            &CwtClaims::new("test-signer").with_exp(-1)
        )));

        let payload = build_tcb_mapping(&[(hash(0xAA), 5)]);
        let claims = CwtClaims::new("test-signer").with_nbf(1).with_exp(-1);
        let cose = SignedCorimBuilder::new(CoseAlgorithm::Es384, payload)
            .set_cwt_claims(claims)
            .build_with_signature(vec![0; 96])
            .expect("build signed CoRIM");
        assert!(matches!(
            verify_and_extract_payload(&cose, &[0; SHA384_DIGEST_SIZE]),
            Err(PolicyError::SignatureVerificationFailed)
        ));
    }
}
