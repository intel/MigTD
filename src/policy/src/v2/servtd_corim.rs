// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! CoRIM-based hash endorsement: decodes the signed TCB-mapping CoRIM generated
//! during a MigTD production release (referred to as the "producer" below) and
//! resolves a `tdinfo_hash` to a [`ServtdLookup`] (the MigTD ISV SVN).
//!
//! # One document
//!
//! The producer emits a single signed **TCB Mapping CoRIM**
//! (`SERVTD_INFO_HASH -> isvsvn`), which MigTD carries in its CFV. Each
//! authorized release is represented by two `conditional-endorsements`
//! triples in the generic
//! `class = { vendor: "Intel", model: "TDX" }` environment, without an instance:
//!
//! * `tdx_init_server_td_hash` -> `tdx_init_server_td_svn`, and
//! * `tdx_curr_server_td_hash` -> `tdx_curr_server_td_svn`.
//!
//! The measurement that carries the digest may also carry the `SERVTD_ATTR`
//! mask the hash was computed with, as `mval.raw-value` (key 4): `#6.560` of
//! 8 bytes, little endian; absent means 0. An entry is identified by `(hash, attr)`.
//!
//! Each triple has exactly one condition and endorsement, each with one
//! measurement. Hashes must be SHA-384 (algorithm 7, 48 bytes); SVNs must be
//! exact `u16` values. No additional environment qualifiers, measurement
//! values, or authorization constraints are supported. Both phases must
//! endorse identical `(hash, attr)`-to-SVN maps: the lookup API is phase-independent,
//! so accepting a phase-only endorsement would broaden its authority.
//!
//! Instance-qualified reference/CES mappings remain supported; their reference
//! and selection must match both hash and attribute. Validated mappings populate
//! a shared lookup cache. Conflicting SVN assignments for the same hash are
//! rejected across all attributes, mappings, and CoMIDs. An optional JSON TD
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
//! `x5chain` (via the `crypto` crate) and binds the root certificate, full leaf
//! Subject DN, and dedicated EKU to the RTMR1-measured signer anchor
//! ([`compute_signer_anchor`]). The anchor is enrolled directly or derived from
//! the CFV policy issuer chain.
//! [`ServtdCorim::decode`] takes already-verified inner payload bytes and
//! performs decode + match only.

use alloc::{collections::BTreeMap, vec::Vec};
use core::convert::{TryFrom, TryInto};

use corim::{
    types::{
        comid::ComidTag,
        common::MeasuredElement,
        environment::{ClassMap, EnvironmentMap},
        measurement::{MeasurementMap, MeasurementValuesMap, RawValueChoice, SvnChoice},
        signed::{decode_signed_corim, CoseAlgorithm, CwtClaims},
    },
    validate::decode_and_validate_at,
};

use crypto::SHA384_DIGEST_SIZE;

use crate::{
    v2::{compute_signer_anchor, is_valid_servtd_attr, ServtdLookup},
    PolicyError,
};

// ---- MigTD CoRIM wire-format constants -----------------------------------

/// Component class for the TCB Mapping: `class = { vendor: "Intel",
/// model: "TDX" }` (no `class-id`).
pub const CLASS_VENDOR: &str = "Intel";
/// See [`CLASS_VENDOR`].
pub const CLASS_MODEL: &str = "TDX";

/// Instance selector for instance-qualified mappings
/// (`environment.instance = #6.560("migration-td")`).
pub const MIGRATION_TD_INSTANCE_BYTES: &[u8] = b"migration-td";

const INIT_HASH_KEY: &str = "tdx_init_server_td_hash";
const CURRENT_HASH_KEY: &str = "tdx_curr_server_td_hash";
const INIT_SVN_KEY: &str = "tdx_init_server_td_svn";
const CURRENT_SVN_KEY: &str = "tdx_curr_server_td_svn";
const SHA384_ALG: i64 = 7;

/// Decoded CoRIM servtd collateral: the TCB Mapping document (hash -> svn).
pub struct ServtdCorim {
    /// CoMID tags from the TCB Mapping CoRIM.
    tcb_mapping: Vec<ComidTag>,
    /// `(SERVTD_INFO_HASH, SERVTD_ATTR) -> isvsvn`.
    svn_mappings: BTreeMap<(Vec<u8>, u64), u16>,
    /// Verified leaf-first COSE `x5chain`, retained so callers can apply the
    /// locally authoritative servTD CRL after signature/anchor verification.
    signer_chain: Option<Vec<Vec<u8>>>,
}

impl ServtdCorim {
    /// Decode the TCB Mapping CoRIM blob (CBOR, `#6.501` unsigned wrapper) and
    /// validate its structure, mapping constraints, initial/current phase
    /// equivalence, and hash-to-SVN consistency.
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

    fn signer_chain_refs(&self) -> Result<Vec<&[u8]>, PolicyError> {
        let signer_chain = self
            .signer_chain
            .as_ref()
            .ok_or(PolicyError::SignatureVerificationFailed)?;
        Ok(signer_chain.iter().map(|cert| cert.as_slice()).collect())
    }

    /// Authenticate delivered CRL metadata without using its revocation entries.
    pub fn verify_signer_crl(&self, servtd_crl: &[u8]) -> Result<(), PolicyError> {
        crypto::verify_signer_crl(
            crypto::SignerChain::Der(&self.signer_chain_refs()?),
            servtd_crl,
        )
        .map_err(|_| PolicyError::SignerRevoked)
    }

    /// Apply an authenticated servTD CRL to the verified COSE signing leaf.
    ///
    /// The CRL must come from the local measured policy. Peer-supplied CRLs
    /// must never be passed here as authority.
    pub fn verify_signer_chain_not_revoked(&self, servtd_crl: &[u8]) -> Result<(), PolicyError> {
        let signer_chain = self.signer_chain_refs()?;
        crypto::verify_signer_chain_not_revoked(crypto::SignerChain::Der(&signer_chain), servtd_crl)
            .map_err(|_| PolicyError::SignerRevoked)
    }

    /// Resolve `(SERVTD_INFO_HASH, SERVTD_ATTR) -> isvsvn` via validated mappings.
    /// Named mappings require identical initial/current coverage.
    fn svn_for_hash(&self, hash: &[u8], servtd_attr: u64) -> Option<u16> {
        self.svn_mappings
            .get(&(hash.to_vec(), servtd_attr))
            .copied()
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
        self.lookup_by_servtd_info_hash(tdinfo_hash, 0)
    }

    /// Resolve the MigTD ISV SVN for a `SERVTD_INFO_HASH` computed with the
    /// `servtd_attr` mask. Returns `None` if `(hash, servtd_attr)` is not
    /// endorsed by this CoRIM.
    pub fn lookup_by_servtd_info_hash(
        &self,
        servtd_info_hash: &[u8],
        servtd_attr: u64,
    ) -> Option<ServtdLookup> {
        let isvsvn = self.svn_for_hash(servtd_info_hash, servtd_attr)?;
        Some(ServtdLookup {
            isvsvn,
            servtd_attr,
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
/// 4. Bind the root, leaf Subject DN, and each asserted dedicated EKU to
///    `expected_signer_anchor` — the RTMR1-measured signer anchor. For each
///    asserted purpose, recompute it using the root DER and full Subject DN DER.
///    One purpose must reproduce the measured value; otherwise verification
///    fails closed.
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

    let signer = crypto::verify_cose_sign1_es384_x5chain(&certs, &tbs, &envelope.signature)
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    // Anchor-first match: the signer leaf may assert the dedicated MigTD
    // policy-signer purpose alongside unrelated EKUs (e.g. a code-signing OID).
    // Recompute the signer anchor for each asserted purpose and accept iff one
    // reproduces the RTMR1-measured `expected_signer_anchor` under the presented
    // root and leaf Subject DN. This binds identity and purpose without
    // the firmware hard-coding which EKU OID identifies the signer.
    let mut anchor_matches = false;
    for leaf_eku_oid_der in &signer.leaf_eku_oids_der {
        if compute_signer_anchor(&signer.root_der, &signer.leaf_identity, leaf_eku_oid_der)?
            == *expected_signer_anchor
        {
            anchor_matches = true;
            break;
        }
    }
    if !anchor_matches {
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

// ---- TCB Mapping helpers --------------------------------------------------

fn validated_svn_mappings(
    comids: &[ComidTag],
) -> Result<BTreeMap<(Vec<u8>, u64), u16>, PolicyError> {
    let mut references: BTreeMap<(&[u8], u64), Vec<&EnvironmentMap>> = BTreeMap::new();
    for comid in comids {
        for reference in comid.triples.reference_triples.iter().flatten() {
            if !is_migration_td_environment(reference.environment()) {
                continue;
            }
            for measurement in reference.measurements() {
                if let Some(key) = measurement_key(measurement)? {
                    references
                        .entry(key)
                        .or_default()
                        .push(reference.environment());
                }
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
                let (hash, attr) = record
                    .selection()
                    .first()
                    .map(measurement_key)
                    .transpose()?
                    .flatten()
                    .ok_or(PolicyError::InvalidServtdTcbMapping)?;
                if hash.len() != SHA384_DIGEST_SIZE
                    || !references
                        .get(&(hash, attr))
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
                insert_svn_mapping(&mut mappings, hash, attr, svn)?;
            }
        }
    }
    for ((hash, attr), svn) in validated_conditional_svn_mappings(comids)? {
        insert_svn_mapping(&mut mappings, &hash, attr, svn)?;
    }
    // The same hash must resolve to one SVN whatever mask the peer claims.
    let mut by_hash: BTreeMap<&[u8], u16> = BTreeMap::new();
    for ((hash, _), svn) in &mappings {
        if by_hash
            .insert(hash.as_slice(), *svn)
            .is_some_and(|prev| prev != *svn)
        {
            return Err(PolicyError::InvalidServtdTcbMapping);
        }
    }
    Ok(mappings)
}

/// `SERVTD_ATTR` of a measurement: 0 when it has no `raw-value`, otherwise the
/// 8-byte little-endian `#6.560` raw value. A masked raw value, any other
/// length, or an unsupported mask bit is an error.
fn servtd_attr_of(m: &MeasurementMap) -> Result<u64, PolicyError> {
    match &m.mval.raw_value {
        None => Ok(0),
        Some(RawValueChoice::Bytes(bytes)) => {
            let attr = u64::from_le_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| PolicyError::InvalidServtdTcbMapping)?,
            );
            if is_valid_servtd_attr(attr) {
                Ok(attr)
            } else {
                Err(PolicyError::InvalidServtdTcbMapping)
            }
        }
        Some(_) => Err(PolicyError::InvalidServtdTcbMapping),
    }
}

/// `(SERVTD_INFO_HASH, SERVTD_ATTR)` identified by a measurement, if it has a
/// digest.
fn measurement_key(m: &MeasurementMap) -> Result<Option<(&[u8], u64)>, PolicyError> {
    match digest_value(m) {
        Some(hash) => Ok(Some((hash, servtd_attr_of(m)?))),
        None => Ok(None),
    }
}

fn insert_svn_mapping(
    mappings: &mut BTreeMap<(Vec<u8>, u64), u16>,
    hash: &[u8],
    attr: u64,
    svn: u16,
) -> Result<(), PolicyError> {
    if let Some(previous) = mappings.insert((hash.to_vec(), attr), svn) {
        if previous != svn {
            return Err(PolicyError::InvalidServtdTcbMapping);
        }
    }
    Ok(())
}

fn validated_conditional_svn_mappings(
    comids: &[ComidTag],
) -> Result<BTreeMap<(Vec<u8>, u64), u16>, PolicyError> {
    let environment = EnvironmentMap {
        class: Some(ClassMap::new(CLASS_VENDOR, CLASS_MODEL)),
        instance: None,
        group: None,
    };
    let mut initial = BTreeMap::new();
    let mut current = BTreeMap::new();
    for triple in comids
        .iter()
        .flat_map(|comid| comid.triples.conditional_endorsement.iter().flatten())
    {
        let ([condition], [endorsement]) = (triple.0.as_slice(), triple.1.as_slice()) else {
            return Err(PolicyError::InvalidServtdTcbMapping);
        };
        let ([selection], [addition]) = (condition.1.as_slice(), endorsement.1.as_slice()) else {
            return Err(PolicyError::InvalidServtdTcbMapping);
        };
        if condition.0 != environment
            || endorsement.0 != environment
            || selection.authorized_by.is_some()
            || addition.authorized_by.is_some()
        {
            return Err(PolicyError::InvalidServtdTcbMapping);
        }
        let (mappings, svn_key) = match selection.mkey.as_ref() {
            Some(MeasuredElement::Text(key)) if key == INIT_HASH_KEY => {
                (&mut initial, INIT_SVN_KEY)
            }
            Some(MeasuredElement::Text(key)) if key == CURRENT_HASH_KEY => {
                (&mut current, CURRENT_SVN_KEY)
            }
            _ => return Err(PolicyError::InvalidServtdTcbMapping),
        };
        if !matches!(addition.mkey.as_ref(), Some(MeasuredElement::Text(key)) if key == svn_key)
            || selection.mval
                != (MeasurementValuesMap {
                    digests: selection.mval.digests.clone(),
                    raw_value: selection.mval.raw_value.clone(),
                    ..MeasurementValuesMap::new()
                })
            || addition.mval
                != (MeasurementValuesMap {
                    svn: addition.mval.svn.clone(),
                    ..MeasurementValuesMap::new()
                })
        {
            return Err(PolicyError::InvalidServtdTcbMapping);
        }
        let Some([digest]) = selection.mval.digests.as_deref() else {
            return Err(PolicyError::InvalidServtdTcbMapping);
        };
        if digest.alg().as_int() != Some(SHA384_ALG) || digest.value().len() != SHA384_DIGEST_SIZE {
            return Err(PolicyError::InvalidServtdTcbMapping);
        }
        let svn = svn_exact(addition)
            .and_then(|svn| u16::try_from(svn).ok())
            .ok_or(PolicyError::InvalidServtdTcbMapping)?;
        insert_svn_mapping(mappings, digest.value(), servtd_attr_of(selection)?, svn)?;
    }
    // Callers use the same lookup for initial and current TDINFO evidence.
    // Do not turn an endorsement for only one phase into an endorsement for both.
    if initial != current {
        return Err(PolicyError::InvalidServtdTcbMapping);
    }
    Ok(initial)
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
    use core::convert::TryInto;
    use corim::{
        builder::{ComidBuilder, CorimBuilder},
        types::{
            common::{ClassIdChoice, GroupIdChoice, InstanceIdChoice, TagIdChoice},
            corim::CorimId,
            environment::{ClassMap, EnvironmentMap},
            measurement::{Digest, MeasurementValuesMap},
            signed::SignedCorimBuilder,
            triples::{
                CesCondition, ConditionalEndorsementSeriesTriple, ConditionalEndorsementTriple,
                ConditionalSeriesRecord, EndorsedTriple, ReferenceTriple,
                StatefulEnvironmentRecord,
            },
        },
    };

    /// Algorithm identifier used by the reference/CES test fixtures.
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

    fn verify_fixture_signature(cose: &[u8]) -> crypto::VerifiedCoseSigner {
        let envelope = decode_signed_corim(cose).unwrap();
        let certs = envelope.protected.x5chain.as_ref().unwrap().certs();
        let tbs = envelope.to_be_signed(&[]).unwrap();
        crypto::verify_cose_sign1_es384_x5chain(&certs, &tbs, &envelope.signature).unwrap()
    }

    #[test]
    fn signed_corim_preserves_identity_across_key_rotation_and_extra_ekus() {
        let original = verify_fixture_signature(EMULATION_COSE);
        for cose in [
            include_bytes!("../../test/policy_v2/corim/tcb_mapping_rotated.corim").as_slice(),
            include_bytes!("../../test/policy_v2/corim/tcb_mapping_multiple_eku.corim").as_slice(),
        ] {
            let signer = verify_fixture_signature(cose);
            assert_eq!(signer.root_der, original.root_der);
            assert_eq!(signer.leaf_identity, original.leaf_identity);
            let corim = ServtdCorim::decode_signed(cose, 0, EMULATION_ANCHOR).unwrap();
            corim
                .verify_signer_chain_not_revoked(EMULATION_CRL)
                .unwrap();
            let hash = crate::v2::hex_string_to_bytes(EMULATION_HASH).unwrap();
            assert_eq!(corim.lookup_by_tdinfo_hash(&hash).unwrap().isvsvn, 1);
        }
    }

    #[test]
    fn signed_corim_accepts_changed_or_absent_san() {
        let original = verify_fixture_signature(EMULATION_COSE);
        assert!(original.leaf_identity.subject_alt_name_der.is_some());
        for cose in [
            include_bytes!("../../test/policy_v2/corim/tcb_mapping_san_mismatch.corim").as_slice(),
            include_bytes!("../../test/policy_v2/corim/tcb_mapping_no_san.corim").as_slice(),
        ] {
            let signer = verify_fixture_signature(cose);
            assert_eq!(signer.root_der, original.root_der);
            assert_eq!(
                signer.leaf_identity.subject_dn_der,
                original.leaf_identity.subject_dn_der
            );
            assert_ne!(
                signer.leaf_identity.subject_alt_name_der,
                original.leaf_identity.subject_alt_name_der
            );
            assert_eq!(signer.leaf_eku_oids_der, original.leaf_eku_oids_der);
            let corim = ServtdCorim::decode_signed(cose, 0, EMULATION_ANCHOR).unwrap();
            corim
                .verify_signer_chain_not_revoked(EMULATION_CRL)
                .unwrap();
            let hash = crate::v2::hex_string_to_bytes(EMULATION_HASH).unwrap();
            assert_eq!(corim.lookup_by_tdinfo_hash(&hash).unwrap().isvsvn, 1);
        }
    }

    #[test]
    fn signed_corim_rejects_dn_and_purpose_changes() {
        let original = verify_fixture_signature(EMULATION_COSE);
        for cose in [
            include_bytes!("../../test/policy_v2/corim/tcb_mapping_subject_mismatch.corim")
                .as_slice(),
            include_bytes!("../../test/policy_v2/corim/tcb_mapping_other_eku.corim").as_slice(),
        ] {
            let signer = verify_fixture_signature(cose);
            assert_eq!(signer.root_der, original.root_der);
            assert!(matches!(
                ServtdCorim::decode_signed(cose, 0, EMULATION_ANCHOR),
                Err(PolicyError::InvalidServtdTcbMapping)
            ));
        }
    }

    #[test]
    fn signed_corim_rejects_anchor_without_subject_binding() {
        let signer = verify_fixture_signature(EMULATION_COSE);
        let mut input = crate::v2::measurement::SIGNER_ANCHOR_DOMAIN_TAG.to_vec();
        input.push(0);
        input.extend_from_slice(&crypto::hash::digest_sha384(&signer.root_der).unwrap());
        input.push(0);
        input.extend_from_slice(&signer.leaf_eku_oids_der[0]);
        let invalid_anchor: [u8; SHA384_DIGEST_SIZE] = crypto::hash::digest_sha384(&input)
            .unwrap()
            .try_into()
            .unwrap();
        assert_ne!(invalid_anchor, *EMULATION_ANCHOR);
        assert!(matches!(
            ServtdCorim::decode_signed(EMULATION_COSE, 0, &invalid_anchor),
            Err(PolicyError::InvalidServtdTcbMapping)
        ));
    }

    #[test]
    fn signed_corim_rejects_anchor_with_san_binding() {
        for cose in [
            EMULATION_COSE,
            include_bytes!("../../test/policy_v2/corim/tcb_mapping_no_san.corim").as_slice(),
        ] {
            let signer = verify_fixture_signature(cose);
            let mut input = crate::v2::measurement::SIGNER_ANCHOR_DOMAIN_TAG.to_vec();
            input.push(0);
            input.extend_from_slice(&crypto::hash::digest_sha384(&signer.root_der).unwrap());
            input.push(0);
            input.extend_from_slice(
                &crypto::hash::digest_sha384(&signer.leaf_identity.subject_dn_der).unwrap(),
            );
            input.push(0);
            let san_input = match &signer.leaf_identity.subject_alt_name_der {
                Some(san) => [b"\x01".as_slice(), san].concat(),
                None => vec![0],
            };
            input.extend_from_slice(&crypto::hash::digest_sha384(&san_input).unwrap());
            input.push(0);
            input.extend_from_slice(&signer.leaf_eku_oids_der[0]);
            let invalid_anchor: [u8; SHA384_DIGEST_SIZE] = crypto::hash::digest_sha384(&input)
                .unwrap()
                .try_into()
                .unwrap();
            assert_ne!(invalid_anchor, *EMULATION_ANCHOR);
            assert!(matches!(
                ServtdCorim::decode_signed(cose, 0, &invalid_anchor),
                Err(PolicyError::InvalidServtdTcbMapping)
            ));
        }
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
    fn corim_peer_crl_metadata_is_authenticated_after_chain_attachment() {
        let base: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../test/policy_v2/policy_v2.json")).unwrap();
        let revoked = include_bytes!("../../test/policy_v2/corim/revoked.crl.pem");
        let mut tampered = revoked.to_vec();
        let index = tampered
            .windows(5)
            .rposition(|bytes| bytes == b"\n----")
            .unwrap()
            - 5;
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        for (delivered, accepted) in [
            (revoked.as_slice(), true),
            (tampered.as_slice(), false),
            (
                include_bytes!("../../../crypto/test/crl/root_empty.crl.pem").as_slice(),
                false,
            ),
        ] {
            let mut value = base.clone();
            value["policyData"]
                .as_object_mut()
                .unwrap()
                .remove("servtdCollateral");
            value["policyData"]["servtdCrl"] = core::str::from_utf8(delivered).unwrap().into();
            let bytes = serde_json::to_vec(&value).unwrap();
            let raw = crate::v2::RawPolicyData::deserialize_from_json(&bytes).unwrap();
            let mut peer = raw
                .verify_with_authoritative_servtd_crl(EMULATION_ANCHOR, EMULATION_CRL)
                .unwrap();
            peer.attach_verified_peer_servtd_corim(EMULATION_COSE)
                .unwrap();
            assert_eq!(
                peer.verify_signer_chains_not_revoked(EMULATION_CRL).is_ok(),
                accepted
            );
        }
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

    /// A measurement holding the hash and, for a non-zero mask, the 8-byte
    /// little-endian `raw-value`.
    fn digest_measurement(hash: &[u8], attr: u64) -> MeasurementMap {
        MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(SHA256_ALG, hash.to_vec())]),
                raw_value: (attr != 0).then(|| RawValueChoice::Bytes(attr.to_le_bytes().to_vec())),
                ..MeasurementValuesMap::new()
            },
            authorized_by: None,
        }
    }

    fn ref_triple(hash: &[u8]) -> ReferenceTriple {
        ref_triple_attr(hash, 0)
    }

    fn ref_triple_attr(hash: &[u8], attr: u64) -> ReferenceTriple {
        ReferenceTriple::new(migration_td_env(), vec![digest_measurement(hash, attr)])
    }

    fn ces_triple(hash: &[u8], svn: u16) -> ConditionalEndorsementSeriesTriple {
        ces_triple_attr(hash, 0, svn)
    }

    fn ces_triple_attr(hash: &[u8], attr: u64, svn: u16) -> ConditionalEndorsementSeriesTriple {
        let condition = CesCondition {
            environment: migration_td_env(),
            claims_list: Vec::new(),
            authorized_by: None,
        };
        let selection = digest_measurement(hash, attr);
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
        let entries: Vec<_> = entries
            .iter()
            .map(|(hash, svn)| (hash.clone(), 0, *svn))
            .collect();
        build_tcb_mapping_attr(&entries)
    }

    /// Like [`build_tcb_mapping`] for `(hash, servtd_attr, svn)` entries.
    pub(crate) fn build_tcb_mapping_attr(entries: &[(Vec<u8>, u64, u16)]) -> Vec<u8> {
        let mut comid = ComidBuilder::new(TagIdChoice::Text("migtd-tcb-mapping".into()));
        for (hash, attr, svn) in entries {
            comid = comid.add_reference_triple(ref_triple_attr(hash, *attr));
            comid = comid.add_conditional_endorsement_series(ces_triple_attr(hash, *attr, *svn));
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

    fn conditional_triple(hash: &[u8], svn: u16, initial: bool) -> ConditionalEndorsementTriple {
        let environment = EnvironmentMap {
            class: Some(class()),
            instance: None,
            group: None,
        };
        let (hash_key, svn_key) = if initial {
            (INIT_HASH_KEY, INIT_SVN_KEY)
        } else {
            (CURRENT_HASH_KEY, CURRENT_SVN_KEY)
        };
        ConditionalEndorsementTriple(
            vec![StatefulEnvironmentRecord(
                environment.clone(),
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text(hash_key.into())),
                    mval: MeasurementValuesMap {
                        digests: Some(vec![Digest::new(SHA384_ALG, hash.to_vec())]),
                        ..MeasurementValuesMap::new()
                    },
                    authorized_by: None,
                }],
            )],
            vec![EndorsedTriple::new(
                environment,
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text(svn_key.into())),
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(u64::from(svn))),
                        ..MeasurementValuesMap::new()
                    },
                    authorized_by: None,
                }],
            )],
        )
    }

    fn conditional_comid(triples: Vec<ConditionalEndorsementTriple>) -> ComidTag {
        let mut comid = ComidBuilder::new(TagIdChoice::Text("conditional-mapping".into()))
            .add_conditional_endorsement(conditional_triple(&hash(0xAA), 5, true))
            .build()
            .unwrap();
        // Permit malformed triples here so negative tests exercise the decoder.
        comid.triples.conditional_endorsement = Some(triples);
        comid
    }

    fn conditional_pair(hash: &[u8], svn: u16) -> Vec<ConditionalEndorsementTriple> {
        vec![
            conditional_triple(hash, svn, true),
            conditional_triple(hash, svn, false),
        ]
    }

    fn conditional_pair_attr(
        hash: &[u8],
        attr: u64,
        svn: u16,
    ) -> Vec<ConditionalEndorsementTriple> {
        let mut triples = conditional_pair(hash, svn);
        for triple in &mut triples {
            triple.0[0].1[0].mval.raw_value =
                Some(RawValueChoice::Bytes(attr.to_le_bytes().to_vec()));
        }
        triples
    }

    #[test]
    fn conditional_endorsements_lookup_requires_the_endorsed_attr() {
        let mut triples = conditional_pair_attr(&hash(0xAA), MASK_A, 5);
        triples.extend(conditional_pair_attr(&hash(0xAA), MASK_B, 5));
        let mut zero = conditional_pair_attr(&hash(0xBB), 0, 7);
        zero[0].0[0].1[0].mval.raw_value = None;
        triples.extend(zero);
        let provider =
            ServtdCorim::decode(&build_corim(vec![conditional_comid(triples)]), 0).unwrap();
        for attr in [MASK_A, MASK_B] {
            let hit = provider
                .lookup_by_servtd_info_hash(&hash(0xAA), attr)
                .unwrap();
            assert_eq!((hit.isvsvn, hit.servtd_attr), (5, attr));
        }
        assert!(provider.lookup_by_tdinfo_hash(&hash(0xAA)).is_none());
        assert_eq!(
            provider.lookup_by_tdinfo_hash(&hash(0xBB)).unwrap().isvsvn,
            7
        );
        assert!(provider
            .lookup_by_servtd_info_hash(&hash(0xBB), MASK_A)
            .is_none());
    }

    #[test]
    fn conditional_endorsements_require_matching_attrs_and_cross_mask_svns() {
        let mut mismatched = conditional_pair_attr(&hash(0xAA), MASK_A, 5);
        mismatched[1].0[0].1[0].mval.raw_value =
            Some(RawValueChoice::Bytes(MASK_B.to_le_bytes().to_vec()));
        let mut conflicting = conditional_pair_attr(&hash(0xAA), MASK_A, 5);
        conflicting.extend(conditional_pair_attr(&hash(0xAA), MASK_B, 7));
        for triples in [mismatched, conflicting] {
            assert!(matches!(
                ServtdCorim::decode(&build_corim(vec![conditional_comid(triples)]), 0),
                Err(PolicyError::InvalidServtdTcbMapping)
            ));
        }
        for svn in [5, 7] {
            let legacy = ComidBuilder::new(TagIdChoice::Text("legacy".into()))
                .add_reference_triple(ref_triple_attr(&hash(0xAA), MASK_A))
                .add_conditional_endorsement_series(ces_triple_attr(&hash(0xAA), MASK_A, svn))
                .build()
                .unwrap();
            let named = conditional_comid(conditional_pair_attr(&hash(0xAA), MASK_B, 5));
            for comids in [vec![legacy.clone(), named.clone()], vec![named, legacy]] {
                assert_eq!(
                    ServtdCorim::decode(&build_corim(comids), 0).is_ok(),
                    svn == 5
                );
            }
        }
    }

    #[test]
    fn conditional_endorsements_reject_invalid_attrs() {
        for raw_value in [
            RawValueChoice::Bytes(vec![0; 7]),
            RawValueChoice::Bytes(vec![0; 9]),
            RawValueChoice::Bytes((1u64 << 32).to_le_bytes().to_vec()),
            RawValueChoice::Bytes((1u64 << 34).to_le_bytes().to_vec()),
            RawValueChoice::Bytes((1u64 << 38).to_le_bytes().to_vec()),
            RawValueChoice::Masked {
                value: MASK_A.to_le_bytes().to_vec(),
                mask: u64::MAX.to_le_bytes().to_vec(),
            },
        ] {
            for phase in 0..2 {
                let mut triples = conditional_pair_attr(&hash(0xAA), MASK_A, 5);
                triples[phase].0[0].1[0].mval.raw_value = Some(raw_value.clone());
                assert!(matches!(
                    ServtdCorim::decode(&build_corim(vec![conditional_comid(triples)]), 0),
                    Err(PolicyError::InvalidServtdTcbMapping)
                ));
            }
        }
    }

    #[test]
    fn conditional_endorsements_resolve_all_six_producer_sample_entries() {
        let hashes = [
            "06905e39f8d772210d9a3fcc924f7040c8d94c4f94917d25fab40f637511f2a4f05b7aae118ae2df9a0db53071c984f6",
            "b9b77e461e499ce1caeadf7b41a758c00520b52dff071e6e342b13cd4f865ade8965f520cebb52cac3104f0147d66786",
            "6814ca38cad715d2eb02afa6b675273bee5a67c4dc86fe2210f21f792a89b5d7428b7388475823fcda35b9d7ae8e755a",
        ]
        .map(|hash| crate::v2::hex_string_to_bytes(hash).unwrap());
        let mut triples = Vec::new();
        for initial in [true, false] {
            for hash in &hashes {
                triples.push(conditional_triple(hash, 1, initial));
            }
        }
        let bytes = build_corim(vec![conditional_comid(triples)]);
        let provider = ServtdCorim::decode(&bytes, 0).unwrap();
        assert_eq!(provider.comid_count(), 1);
        for hash in hashes {
            let lookup = provider.lookup_by_tdinfo_hash(&hash).unwrap();
            assert_eq!(lookup.isvsvn, 1);
            assert!(lookup.tcb_date.is_none());
            assert!(lookup.tcb_status.is_none());
        }
        assert!(provider.lookup_by_tdinfo_hash(&hash(0xCC)).is_none());
        assert!(provider.lookup_by_tdinfo_hash(&[0; 32]).is_none());
    }

    #[test]
    fn conditional_endorsements_accept_equal_duplicates_and_svn_boundaries_across_comids() {
        let mut comids = Vec::new();
        for (hash, svn) in [(hash(0xAA), 0), (hash(0xBB), u16::MAX)] {
            for initial in [false, true, true, false] {
                comids.push(conditional_comid(vec![conditional_triple(
                    &hash, svn, initial,
                )]));
            }
        }
        let provider = ServtdCorim::decode(&build_corim(comids), 0).unwrap();
        assert_eq!(
            provider.lookup_by_tdinfo_hash(&hash(0xAA)).unwrap().isvsvn,
            0
        );
        assert_eq!(
            provider.lookup_by_tdinfo_hash(&hash(0xBB)).unwrap().isvsvn,
            u16::MAX
        );
    }

    #[test]
    fn conditional_endorsements_require_identical_phase_coverage_and_svns() {
        for triples in [
            vec![conditional_triple(&hash(0xAA), 5, true)],
            vec![conditional_triple(&hash(0xAA), 5, false)],
            vec![
                conditional_triple(&hash(0xAA), 5, true),
                conditional_triple(&hash(0xBB), 5, false),
            ],
            vec![
                conditional_triple(&hash(0xAA), 5, true),
                conditional_triple(&hash(0xAA), 7, false),
            ],
        ] {
            for reverse in [false, true] {
                let mut triples = triples.clone();
                if reverse {
                    triples.reverse();
                }
                assert!(matches!(
                    ServtdCorim::decode(&build_corim(vec![conditional_comid(triples)]), 0),
                    Err(PolicyError::InvalidServtdTcbMapping)
                ));
            }
        }
    }

    #[test]
    fn conditional_endorsements_reject_same_phase_conflicts_across_comids_in_either_order() {
        for initial in [true, false] {
            for svn in [5, 7] {
                let comids = vec![
                    conditional_comid(conditional_pair(&hash(0xAA), svn)),
                    conditional_comid(vec![conditional_triple(&hash(0xAA), 12 - svn, initial)]),
                ];
                assert!(matches!(
                    ServtdCorim::decode(&build_corim(comids), 0),
                    Err(PolicyError::InvalidServtdTcbMapping)
                ));
            }
        }
    }

    #[test]
    fn conditional_endorsements_and_legacy_ces_share_conflict_checks() {
        for (hash, svn, accepted) in [
            (hash(0xAA), 5, true),
            (hash(0xAA), 7, false),
            (hash(0xBB), 7, true),
        ] {
            for reverse in [false, true] {
                let legacy = ComidBuilder::new(TagIdChoice::Text("legacy".into()))
                    .add_reference_triple(ref_triple(&hash))
                    .add_conditional_endorsement_series(ces_triple(&hash, svn))
                    .build()
                    .unwrap();
                let mut comids = vec![legacy, conditional_comid(conditional_pair(&[0xAA; 48], 5))];
                if reverse {
                    comids.reverse();
                }
                assert_eq!(
                    ServtdCorim::decode(&build_corim(comids), 0).is_ok(),
                    accepted
                );
            }
        }
    }

    #[test]
    fn legacy_ces_cannot_supply_a_missing_conditional_phase() {
        for initial in [true, false] {
            let mut comid = conditional_comid(vec![conditional_triple(&hash(0xAA), 5, initial)]);
            comid.triples.reference_triples = Some(vec![ref_triple(&hash(0xAA))]);
            comid.triples.conditional_endorsement_series = Some(vec![ces_triple(&hash(0xAA), 5)]);
            assert!(matches!(
                ServtdCorim::decode(&build_corim(vec![comid]), 0),
                Err(PolicyError::InvalidServtdTcbMapping)
            ));
        }
    }

    #[test]
    fn conditional_endorsements_reject_unsupported_shapes_and_constraints() {
        type Mutation = (&'static str, fn(&mut ConditionalEndorsementTriple));
        let mutations: &[Mutation] = &[
            ("no conditions", |t| t.0.clear()),
            ("extra condition", |t| t.0.push(t.0[0].clone())),
            ("no endorsements", |t| t.1.clear()),
            ("extra endorsement", |t| t.1.push(t.1[0].clone())),
            ("no hash measurement", |t| t.0[0].1.clear()),
            ("extra hash measurement", |t| {
                let measurement = t.0[0].1[0].clone();
                t.0[0].1.push(measurement);
            }),
            ("no SVN measurement", |t| t.1[0].1.clear()),
            ("extra SVN measurement", |t| {
                let measurement = t.1[0].1[0].clone();
                t.1[0].1.push(measurement);
            }),
            ("missing class", |t| t.0[0].0.class = None),
            ("wrong vendor", |t| {
                t.0[0].0.class.as_mut().unwrap().vendor = Some("AMD".into())
            }),
            ("wrong model", |t| {
                t.0[0].0.class.as_mut().unwrap().model = Some("SGX".into())
            }),
            ("class ID", |t| {
                t.0[0].0.class.as_mut().unwrap().class_id = Some(ClassIdChoice::Uuid([0; 16]))
            }),
            ("class index", |t| {
                t.0[0].0.class.as_mut().unwrap().index = Some(1)
            }),
            ("class layer", |t| {
                t.0[0].0.class.as_mut().unwrap().layer = Some(1)
            }),
            ("instance", |t| {
                t.0[0].0.instance = migration_td_env().instance
            }),
            ("group", |t| {
                t.0[0].0.group = Some(GroupIdChoice::Uuid([0; 16]))
            }),
            ("endorsement environment", |t| t.1[0].0 = migration_td_env()),
            ("missing hash key", |t| t.0[0].1[0].mkey = None),
            ("non-text hash key", |t| {
                t.0[0].1[0].mkey = Some(MeasuredElement::Uint(0))
            }),
            ("unknown hash key", |t| {
                t.0[0].1[0].mkey = Some(MeasuredElement::Text("other".into()))
            }),
            ("missing SVN key", |t| t.1[0].1[0].mkey = None),
            ("unknown SVN key", |t| {
                t.1[0].1[0].mkey = Some(MeasuredElement::Text("other".into()))
            }),
            ("non-text SVN key", |t| {
                t.1[0].1[0].mkey = Some(MeasuredElement::Uint(0))
            }),
            ("cross-phase SVN key", |t| {
                let key = match &t.1[0].1[0].mkey {
                    Some(MeasuredElement::Text(key)) if key == INIT_SVN_KEY => CURRENT_SVN_KEY,
                    _ => INIT_SVN_KEY,
                };
                t.1[0].1[0].mkey = Some(MeasuredElement::Text(key.into()));
            }),
            ("missing digest", |t| t.0[0].1[0].mval.digests = None),
            ("empty digests", |t| t.0[0].1[0].mval.digests = Some(vec![])),
            ("multiple digests", |t| {
                t.0[0].1[0]
                    .mval
                    .digests
                    .as_mut()
                    .unwrap()
                    .push(Digest::new(SHA384_ALG, hash(0xAA)))
            }),
            ("wrong algorithm", |t| {
                t.0[0].1[0].mval.digests = Some(vec![Digest::new(SHA256_ALG, hash(0xAA))])
            }),
            ("text algorithm", |t| {
                t.0[0].1[0].mval.digests = Some(vec![Digest::new_text("sha-384", hash(0xAA))])
            }),
            ("short hash", |t| {
                t.0[0].1[0].mval.digests = Some(vec![Digest::new(SHA384_ALG, vec![0; 47])])
            }),
            ("long hash", |t| {
                t.0[0].1[0].mval.digests = Some(vec![Digest::new(SHA384_ALG, vec![0; 49])])
            }),
            ("missing SVN", |t| t.1[0].1[0].mval.svn = None),
            ("minimum SVN", |t| {
                t.1[0].1[0].mval.svn = Some(SvnChoice::MinValue(5))
            }),
            ("overflow SVN", |t| {
                t.1[0].1[0].mval.svn = Some(SvnChoice::ExactValue(65536))
            }),
            ("extra condition value", |t| {
                t.0[0].1[0].mval.svn = Some(SvnChoice::ExactValue(5))
            }),
            ("extra endorsement value", |t| {
                t.1[0].1[0].mval.name = Some("constraint".into())
            }),
            ("extension condition", |t| {
                t.0[0].1[0]
                    .mval
                    .extra_entries
                    .insert(-1, corim::cbor::value::Value::Integer(1));
            }),
            ("hash authorization", |t| {
                t.0[0].1[0].authorized_by = Some(vec![])
            }),
            ("SVN authorization", |t| {
                t.1[0].1[0].authorized_by = Some(vec![])
            }),
        ];
        for (name, mutate) in mutations {
            for phase in 0..2 {
                let mut triples = conditional_pair(&hash(0xAA), 5);
                mutate(&mut triples[phase]);
                let comid = conditional_comid(triples);
                assert!(
                    matches!(
                        validated_svn_mappings(core::slice::from_ref(&comid)),
                        Err(PolicyError::InvalidServtdTcbMapping)
                    ),
                    "accepted {} in phase {}",
                    name,
                    phase
                );
                // Empty environment/value maps cannot be serialized by corim.
                // Exercise public decoding for all representable mutations too.
                if let Ok(builder) =
                    CorimBuilder::new(CorimId::Text("malformed".into())).add_comid_tag(comid)
                {
                    assert!(
                        matches!(
                            ServtdCorim::decode(&builder.build_bytes().unwrap(), 0),
                            Err(PolicyError::InvalidServtdTcbMapping)
                        ),
                        "decoded {} in phase {}",
                        name,
                        phase
                    );
                }
            }
        }
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

    const MASK_A: u64 = crate::v2::SERVTD_ATTR_IGNORE_MROWNER;
    const MASK_B: u64 =
        crate::v2::SERVTD_ATTR_IGNORE_MROWNER | crate::v2::SERVTD_ATTR_IGNORE_MROWNERCONFIG;

    #[test]
    fn raw_value_attr_selects_the_entry() {
        let tcb = build_tcb_mapping_attr(&[
            (hash(0xAA), 0, 1),
            (hash(0xCC), MASK_A, 2),
            (hash(0xBB), MASK_B, 3),
        ]);
        let provider = ServtdCorim::decode(&tcb, 0).unwrap();

        let plain = provider.lookup_by_servtd_info_hash(&hash(0xAA), 0).unwrap();
        assert_eq!((plain.isvsvn, plain.servtd_attr), (1, 0));
        let masked = provider
            .lookup_by_servtd_info_hash(&hash(0xCC), MASK_A)
            .unwrap();
        assert_eq!((masked.isvsvn, masked.servtd_attr), (2, MASK_A));
        let other = provider
            .lookup_by_servtd_info_hash(&hash(0xBB), MASK_B)
            .unwrap();
        assert_eq!((other.isvsvn, other.servtd_attr), (3, MASK_B));

        // The attribute is part of the key.
        assert!(provider
            .lookup_by_servtd_info_hash(&hash(0xAA), MASK_A)
            .is_none());
        assert!(provider
            .lookup_by_servtd_info_hash(&hash(0xCC), 0)
            .is_none());
        assert!(provider
            .lookup_by_servtd_info_hash(&hash(0xBB), 0)
            .is_none());
        assert!(provider
            .lookup_by_servtd_info_hash(&hash(0xBB), MASK_A)
            .is_none());
        assert!(provider.lookup_by_tdinfo_hash(&hash(0xBB)).is_none());
    }

    #[test]
    fn absent_raw_value_means_attr_zero() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5)]);
        let provider = ServtdCorim::decode(&tcb, 0).unwrap();
        assert_eq!(
            provider
                .lookup_by_servtd_info_hash(&hash(0xAA), 0)
                .unwrap()
                .isvsvn,
            5
        );
    }

    #[test]
    fn raw_value_is_encoded_as_little_endian_tagged_bytes() {
        let tcb = build_tcb_mapping_attr(&[(hash(0xAA), MASK_A, 5)]);
        // #6.560 (d9 02 30) of an 8-byte string (48), little endian.
        let mut expected = vec![0xd9, 0x02, 0x30, 0x48];
        expected.extend_from_slice(&MASK_A.to_le_bytes());
        assert!(tcb.windows(expected.len()).any(|w| w == expected));
    }

    #[test]
    fn reference_must_match_the_selected_attr() {
        let comid = ComidBuilder::new(TagIdChoice::Text("different-attr".into()))
            .add_reference_triple(ref_triple_attr(&hash(0xAA), 0))
            .add_conditional_endorsement_series(ces_triple_attr(&hash(0xAA), MASK_A, 5))
            .build()
            .unwrap();
        assert!(matches!(
            ServtdCorim::decode(&build_corim(vec![comid]), 0),
            Err(PolicyError::InvalidServtdTcbMapping)
        ));
    }

    #[test]
    fn conflicting_svns_for_the_same_hash_and_attr_are_rejected() {
        let tcb = build_tcb_mapping_attr(&[(hash(0xAA), MASK_A, 5), (hash(0xAA), MASK_A, 7)]);
        assert!(matches!(
            ServtdCorim::decode(&tcb, 0),
            Err(PolicyError::InvalidServtdTcbMapping)
        ));
        // The same hash under different masks must map to the same SVN.
        let tcb = build_tcb_mapping_attr(&[(hash(0xAA), 0, 5), (hash(0xAA), MASK_A, 7)]);
        assert!(matches!(
            ServtdCorim::decode(&tcb, 0),
            Err(PolicyError::InvalidServtdTcbMapping)
        ));
        let tcb = build_tcb_mapping_attr(&[(hash(0xAA), 0, 5), (hash(0xAA), MASK_A, 5)]);
        assert!(ServtdCorim::decode(&tcb, 0).is_ok());
    }

    fn corim_with_raw_value(raw_value: RawValueChoice) -> Vec<u8> {
        let with_raw = |mut measurement: MeasurementMap| {
            measurement.mval.raw_value = Some(raw_value.clone());
            measurement
        };
        let reference = ReferenceTriple::new(
            migration_td_env(),
            vec![with_raw(digest_measurement(&hash(0xAA), 0))],
        );
        let mut ces = ces_triple(&hash(0xAA), 5);
        let mut record_selection = digest_measurement(&hash(0xAA), 0);
        record_selection.mval.raw_value = Some(raw_value.clone());
        ces = ConditionalEndorsementSeriesTriple::new(
            ces.condition().clone(),
            vec![ConditionalSeriesRecord::new(
                vec![record_selection],
                ces.series()[0].addition().to_vec(),
            )],
        );
        let comid = ComidBuilder::new(TagIdChoice::Text("raw-value".into()))
            .add_reference_triple(reference)
            .add_conditional_endorsement_series(ces)
            .build()
            .unwrap();
        build_corim(vec![comid])
    }

    #[test]
    fn invalid_raw_values_are_rejected() {
        for raw_value in [
            // Not 8 bytes.
            RawValueChoice::Bytes(vec![0; 4]),
            RawValueChoice::Bytes(vec![0; 9]),
            // Unsupported bits (IGNORE_ATTRIBUTES, IGNORE_MRTD, IGNORE_RTMR0).
            RawValueChoice::Bytes((1u64 << 32).to_le_bytes().to_vec()),
            RawValueChoice::Bytes((1u64 << 34).to_le_bytes().to_vec()),
            RawValueChoice::Bytes((1u64 << 38).to_le_bytes().to_vec()),
            RawValueChoice::Bytes(1u64.to_le_bytes().to_vec()),
            // Masked raw values are not used.
            RawValueChoice::Masked {
                value: MASK_A.to_le_bytes().to_vec(),
                mask: u64::MAX.to_le_bytes().to_vec(),
            },
        ] {
            assert!(
                matches!(
                    ServtdCorim::decode(&corim_with_raw_value(raw_value.clone()), 0),
                    Err(PolicyError::InvalidServtdTcbMapping)
                ),
                "{:?}",
                raw_value
            );
        }
        // An explicit zero is the same as no raw value.
        let tcb = corim_with_raw_value(RawValueChoice::Bytes(0u64.to_le_bytes().to_vec()));
        assert!(ServtdCorim::decode(&tcb, 0).is_ok());
    }
}
