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
//! The hash -> svn lookup is driven by the CES triples. There is no TD
//! Identity document: the SVN is the endorsement, and the MigTD `tcb_date` /
//! `tcb_status` translation occurs at policy-authoring time.
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

use alloc::vec::Vec;
use core::convert::TryFrom;

use corim::{
    types::{
        comid::ComidTag,
        environment::EnvironmentMap,
        measurement::{MeasurementMap, SvnChoice},
        signed::{decode_signed_corim, CoseAlgorithm, CwtClaims},
        triples::ConditionalEndorsementSeriesTriple,
    },
    validate::decode_and_validate_at,
};

use crypto::SHA384_DIGEST_SIZE;

use crate::{
    v2::{compute_signer_anchor, ServtdLookup},
    PolicyError,
};

// ---- MigTD CoRIM wire-format constants -----------------------------------

/// Component class for both documents: `class = { vendor: "Intel",
/// model: "TDX" }` (no `class-id`). The producer switched from a shared
/// class-id UUID to this vendor/model class.
pub const CLASS_VENDOR: &str = "Intel";
/// See [`CLASS_VENDOR`].
pub const CLASS_MODEL: &str = "TDX";

/// Instance bytes shared by both documents' environments
/// (`environment.instance = #6.560("migration-td")`). The TCB Mapping and
/// TD Identity CoRIMs are no longer distinguished by instance — they are
/// separate signed files, and within each the triple shape (digest-selecting
/// vs svn-selecting CES) determines the lookup.
pub const MIGRATION_TD_INSTANCE_BYTES: &[u8] = b"migration-td";

// `tcb_date` and `tcb_status` are carried under the Intel-profile extension
// keys re-exported from `corim::profile::intel`:
//   MVAL_TEE_TCBDATE   = -72  (`tee.tcbdate`,   CBOR #6.1(epoch-seconds))
//   MVAL_TEE_TCBSTATUS = -88  (`tee.tcbstatus`, text)
// No MigTD-local key numbers are defined here.

/// Decoded CoRIM servtd collateral: the TCB Mapping document (hash -> svn).
pub struct ServtdCorim {
    /// CoMID tags from the TCB Mapping CoRIM (digest-selecting CES).
    tcb_mapping: Vec<ComidTag>,
    /// Verified leaf-first COSE `x5chain`, retained so callers can apply the
    /// locally authoritative servTD CRL after signature/anchor verification.
    signer_chain: Option<Vec<Vec<u8>>>,
}

impl ServtdCorim {
    /// Decode the TCB Mapping CoRIM blob (CBOR, `#6.501` unsigned wrapper) and
    /// validate it structurally per draft-ietf-rats-corim-10.
    /// `now_epoch_secs` evaluates any embedded validity windows.
    ///
    /// Signature verification of the surrounding `COSE_Sign1` envelope is the
    /// caller's responsibility; this input is the inner payload bytes.
    pub fn decode(tcb_mapping_cbor: &[u8], now_epoch_secs: i64) -> Result<Self, PolicyError> {
        let (_c1, tcb_mapping) = decode_and_validate_at(tcb_mapping_cbor, now_epoch_secs)
            .map_err(|_| PolicyError::InvalidServtdTcbMapping)?;
        Ok(Self {
            tcb_mapping,
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
        for comid in &self.tcb_mapping {
            let Some(ces_list) = comid.triples.conditional_endorsement_series.as_ref() else {
                continue;
            };
            for ces in ces_list {
                if let Some(svn) = ces_svn_for_hash(ces, hash) {
                    return Some(svn);
                }
            }
        }
        None
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
/// 4. Bind the chain's root plus each dedicated EKU purpose the leaf asserts to
///    `expected_signer_anchor` — the RTMR1-measured policy signer anchor — so
///    the CoRIM signer is the same root-of-trust the firmware measured from the
///    CFV. The anchor is recomputed for each asserted purpose and one must
///    reproduce the measured value; otherwise it is fatal (fail-closed).
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

    let (root_der, leaf_eku_oids_der) =
        crypto::verify_cose_sign1_es384_x5chain(&certs, &tbs, &envelope.signature)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    // Anchor-first match: the signer leaf may assert the dedicated MigTD
    // policy-signer purpose alongside unrelated EKUs (e.g. a code-signing OID).
    // Recompute the signer anchor for each asserted purpose and accept iff one
    // reproduces the RTMR1-measured `expected_signer_anchor` under the presented
    // root. This binds the CoRIM signer to the measured root-of-trust without
    // the firmware hard-coding which EKU OID identifies the signer.
    let mut anchor_matches = false;
    for leaf_eku_oid_der in &leaf_eku_oids_der {
        if compute_signer_anchor(&root_der, leaf_eku_oid_der)? == *expected_signer_anchor {
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

// ---- TCB Mapping (CES) helpers --------------------------------------------

/// If this CES triple is in the migration-TD environment and its first
/// series record selects on `hash`, return the SVN it adds.
fn ces_svn_for_hash(ces: &ConditionalEndorsementSeriesTriple, hash: &[u8]) -> Option<u16> {
    if !is_migration_td_environment(&ces.condition().environment) {
        return None;
    }
    for record in ces.series() {
        let selected = record
            .selection()
            .first()
            .and_then(digest_value)
            .map(|d| d == hash)
            .unwrap_or(false);
        if !selected {
            continue;
        }
        if let Some(svn) = record.addition().first().and_then(svn_exact) {
            return u16::try_from(svn).ok();
        }
    }
    None
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
mod test {
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
            triples::{CesCondition, ConditionalSeriesRecord, ReferenceTriple},
        },
    };

    /// Producer's (mislabeled) digest alg id — see the SHA-256/SHA-384 gap.
    const SHA256_ALG: i64 = 1;

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
    fn build_tcb_mapping(entries: &[(Vec<u8>, u16)]) -> Vec<u8> {
        let mut comid = ComidBuilder::new(TagIdChoice::Text("migtd-tcb-mapping".into()));
        for (hash, svn) in entries {
            comid = comid.add_reference_triple(ref_triple(hash));
            comid = comid.add_conditional_endorsement_series(ces_triple(hash, *svn));
        }
        let comid = comid.build().expect("build tcb-mapping comid");
        CorimBuilder::new(CorimId::Text("migtd-tcb-mapping".into()))
            .add_comid_tag(comid)
            .expect("attach comid")
            .build_bytes()
            .expect("encode corim")
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
