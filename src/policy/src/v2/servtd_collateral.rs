// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{string::String, vec::Vec};
use core::convert::TryInto;
use serde::{Deserialize, Serialize};
use serde_json::{self, value::RawValue};

use crate::{
    v2::{bytes_to_hex_string, hex_string_to_bytes},
    MigTdInfoProperty, PolicyError, Report,
};

use crypto::{hash::digest_sha384, SHA384_DIGEST_SIZE};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServtdCollateral<'a> {
    pub major_version: u32,
    pub minor_version: u32,
    /// Mapping signer chain. When omitted, verification uses the policy issuer
    /// chain enrolled in the CFV, not `servtdIdentityIssuerChain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servtd_tcb_mapping_issuer_chain: Option<String>,
    #[serde(borrow)]
    pub servtd_tcb_mapping: RawServtdTcbMapping<'a>,
    /// Optional TD Identity issuer chain (PEM). Present only when the optional
    /// `servtdIdentity` is shipped. The chain and signed identity remain
    /// measured in RTMR2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servtd_identity_issuer_chain: Option<String>,
    /// Optional MigTD TD Identity (`isvsvn -> (tcb_date, tcb_status)`).
    ///
    /// JSON-only and optional (there is no CoRIM form). When present it lets
    /// migration policy use `tcbDate` / `tcbStatus` bars; when absent, policy
    /// is driven by the ISV SVN alone.
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub servtd_identity: Option<RawServtdIdentity<'a>>,
    /// PEM CRL signed by a CA present in the mapping and any identity signer chains.
    /// A numbered CRL is required here or at top-level `servtdCrl`, including for
    /// CoRIM-only policies without a JSON TCB mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servtd_crl: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawServtdIdentity<'a> {
    #[serde(borrow)]
    pub td_identity: &'a RawValue,
    pub signature: String,
}

impl<'a> RawServtdIdentity<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<RawServtdIdentity>(slice)
            .map_err(|_| PolicyError::InvalidServtdIdentity)
    }

    pub fn verify_signature(&self, issuer_chain: &[u8]) -> Result<TdIdentity, PolicyError> {
        let signature = hex_string_to_bytes(&self.signature)?;

        crypto::verify_cert_chain_and_signature(
            issuer_chain,
            self.td_identity.get().as_bytes(),
            &signature,
        )
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        serde_json::from_str::<TdIdentity>(self.td_identity.get())
            .map_err(|_| PolicyError::InvalidServtdIdentity)
    }
}

/// MigTD TD Identity (optional, JSON-only), simplified per the hash-based
/// TCB-mapping redesign.
///
/// Because the TCB Mapping now matches by `SERVTD_INFO_HASH`, TD Identity no
/// longer describes the MigTD's `TDINFO_STRUCT`; the former register
/// descriptors (`xfam`, `attributes`, `mrConfigId`, `mrOwner`,
/// `mrOwnerConfig`, MRTD/RTMRs) and the SGX-enclave `mrsigner` / `isvProdId`
/// fields are dropped. It reduces to an envelope plus an
/// `isvsvn -> (tcb_date, tcb_status)` table.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_levels: Vec<TcbLevel>,
}

impl TdIdentity {
    pub fn deserialize_from_json(slice: &[u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<TdIdentity>(slice).map_err(|_| PolicyError::InvalidServtdIdentity)
    }

    pub fn get_tcb_level_by_svn(&self, svn: u16) -> Option<&TcbLevel> {
        // TCB levels are breakpoints: pick the highest isvsvn <= reported svn
        // (floor match), not an exact match. Exact match can reject valid
        // newer svns and miss `Revoked` deny for in-between values.
        self.tcb_levels
            .iter()
            .filter(|level| level.tcb.isvsvn <= svn)
            .max_by_key(|level| level.tcb.isvsvn)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: String,
    pub tcb_status: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tcb {
    pub isvsvn: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawServtdTcbMapping<'a> {
    #[serde(borrow)]
    pub td_tcb_mapping: &'a RawValue,
    pub signature: String,
}

impl<'a> RawServtdTcbMapping<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<RawServtdTcbMapping>(slice)
            .map_err(|_| PolicyError::InvalidServtdTcbMapping)
    }

    pub fn verify_signature(&self, issuer_chain: &[u8]) -> Result<TdTcbMapping, PolicyError> {
        let signature = hex_string_to_bytes(&self.signature)?;

        crypto::verify_cert_chain_and_signature(
            issuer_chain,
            self.td_tcb_mapping.get().as_bytes(),
            &signature,
        )
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        let mapping = serde_json::from_str::<TdTcbMapping>(self.td_tcb_mapping.get())
            .map_err(|_| PolicyError::InvalidServtdTcbMapping)?;
        mapping.validate()?;
        Ok(mapping)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdTcbMapping {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub svn_mappings: Vec<SvnMapping>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SvnMapping {
    pub td_measurements: Measurements,
    pub isvsvn: u16,
}

/// `SERVTD_ATTR` bits that select TDINFO fields ignored by `SERVTD_INFO_HASH`.
/// A set bit makes the TDX module hash 0 instead of the named field.
pub const SERVTD_ATTR_IGNORE_XFAM: u64 = 1 << 33;
pub const SERVTD_ATTR_IGNORE_MRTD: u64 = 1 << 34;
pub const SERVTD_ATTR_IGNORE_MRCONFIGID: u64 = 1 << 35;
pub const SERVTD_ATTR_IGNORE_MROWNER: u64 = 1 << 36;
pub const SERVTD_ATTR_IGNORE_MROWNERCONFIG: u64 = 1 << 37;
pub const SERVTD_ATTR_IGNORE_RTMR0: u64 = 1 << 38;
pub const SERVTD_ATTR_IGNORE_RTMR1: u64 = 1 << 39;
pub const SERVTD_ATTR_IGNORE_RTMR2: u64 = 1 << 40;
pub const SERVTD_ATTR_IGNORE_RTMR3: u64 = 1 << 41;
/// The only `SERVTD_ATTR` bits MigTD accepts. Bit 32 (`IGNORE_ATTRIBUTES`) must
/// be 0 per the TDX Module ABI; bits 42..=48 select fields that the MigTD
/// TDINFO layout does not carry.
pub const SERVTD_ATTR_VALID_MASK: u64 = SERVTD_ATTR_IGNORE_XFAM
    | SERVTD_ATTR_IGNORE_MRTD
    | SERVTD_ATTR_IGNORE_MRCONFIGID
    | SERVTD_ATTR_IGNORE_MROWNER
    | SERVTD_ATTR_IGNORE_MROWNERCONFIG
    | SERVTD_ATTR_IGNORE_RTMR0
    | SERVTD_ATTR_IGNORE_RTMR1
    | SERVTD_ATTR_IGNORE_RTMR2
    | SERVTD_ATTR_IGNORE_RTMR3;

/// Whether `servtd_attr` only uses bits MigTD supports.
pub const fn is_valid_servtd_attr(servtd_attr: u64) -> bool {
    servtd_attr & !SERVTD_ATTR_VALID_MASK == 0
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Measurements {
    /// Hash-to-SVN TCB mapping key: the `SERVTD_INFO_HASH` the TDX module
    /// reports, i.e. SHA384 of the TDINFO_STRUCT after the fields selected by
    /// `servtd_attr` are replaced by 0. For `servtd_attr == 0` it is
    /// `SHA384(TDINFO_STRUCT)` of the complete TDINFO.
    ///
    /// Hex-encoded (case-insensitive). JSON key `servtdInfoHash`; the earlier
    /// name `tdinfo_hash` is still accepted.
    #[serde(rename = "servtdInfoHash", alias = "tdinfo_hash")]
    pub tdinfo_hash: String,
    /// `SERVTD_ATTR` mask this release is bound with (default 0). JSON key
    /// `servtdAttr`; the earlier name `servtd_attr` is still accepted.
    #[serde(
        rename = "servtdAttr",
        alias = "servtd_attr",
        default,
        skip_serializing_if = "is_zero"
    )]
    pub servtd_attr: u64,
}

impl Measurements {
    pub fn new_from_bytes(tdinfo_hash: &[u8]) -> Self {
        Self::new_with_attr(tdinfo_hash, 0)
    }

    /// Build an entry from an already hex-encoded hash.
    pub fn new_from_hex(tdinfo_hash: String, servtd_attr: u64) -> Self {
        Measurements {
            tdinfo_hash,
            servtd_attr,
        }
    }

    pub fn new_with_attr(tdinfo_hash: &[u8], servtd_attr: u64) -> Self {
        Measurements {
            tdinfo_hash: bytes_to_hex_string(tdinfo_hash),
            servtd_attr,
        }
    }

    fn to_ascii_uppercase(&self) -> Self {
        Measurements {
            tdinfo_hash: self.tdinfo_hash.to_ascii_uppercase(),
            servtd_attr: self.servtd_attr,
        }
    }
}

impl TdTcbMapping {
    fn validate(&self) -> Result<(), PolicyError> {
        for (index, mapping) in self.svn_mappings.iter().enumerate() {
            let hash = hex_string_to_bytes(&mapping.td_measurements.tdinfo_hash)
                .map_err(|_| PolicyError::InvalidServtdTcbMapping)?;
            if hash.len() != SHA384_DIGEST_SIZE
                || !is_valid_servtd_attr(mapping.td_measurements.servtd_attr)
            {
                return Err(PolicyError::InvalidServtdTcbMapping);
            }

            for previous in &self.svn_mappings[..index] {
                if previous
                    .td_measurements
                    .tdinfo_hash
                    .eq_ignore_ascii_case(&mapping.td_measurements.tdinfo_hash)
                    && previous.td_measurements.servtd_attr == mapping.td_measurements.servtd_attr
                    && previous.isvsvn != mapping.isvsvn
                {
                    return Err(PolicyError::InvalidServtdTcbMapping);
                }
            }
        }
        Ok(())
    }

    /// Distinct `servtd_attr` values used by the entries, in ascending order.
    pub fn servtd_attrs(&self) -> Vec<u64> {
        let mut attrs: Vec<u64> = self
            .svn_mappings
            .iter()
            .map(|mapping| mapping.td_measurements.servtd_attr)
            .collect();
        attrs.sort_unstable();
        attrs.dedup();
        attrs
    }

    /// Look up the engine SVN and `servtd_attr` of a TD whose attribute is not
    /// known. `servtd_info_hash(attr)` returns the TD's `SERVTD_INFO_HASH` for
    /// the given mask. Each distinct attribute in the mapping is tried; the
    /// match is rejected if entries with different SVNs match.
    pub fn lookup_with<F>(&self, mut servtd_info_hash: F) -> Option<(u16, u64)>
    where
        F: FnMut(u64) -> Option<[u8; SHA384_DIGEST_SIZE]>,
    {
        let mut found: Option<(u16, u64)> = None;
        for attr in self.servtd_attrs() {
            let Some(hash) = servtd_info_hash(attr) else {
                continue;
            };
            if let Some(svn) = self.get_engine_svn_by_servtd_info_hash(&hash, attr) {
                match found {
                    Some((previous, _)) if previous != svn => return None,
                    Some(_) => {}
                    None => found = Some((svn, attr)),
                }
            }
        }
        found
    }

    /// Look up the engine SVN for the TD represented by `report`.
    pub fn get_engine_svn_by_report(&self, report: &Report) -> Option<u16> {
        self.lookup_with(|attr| compute_servtd_info_hash_from_report(report, attr).ok())
            .map(|(svn, _)| svn)
    }

    /// Look up the engine SVN by a `servtd_attr = 0` hash (48 raw bytes).
    pub fn get_engine_svn_by_tdinfo_hash(&self, tdinfo_hash: &[u8]) -> Option<u16> {
        self.get_engine_svn_by_servtd_info_hash(tdinfo_hash, 0)
    }

    /// Look up the engine SVN by `SERVTD_INFO_HASH` (48 raw bytes) and the
    /// `SERVTD_ATTR` it was computed with.
    pub fn get_engine_svn_by_servtd_info_hash(
        &self,
        servtd_info_hash: &[u8],
        servtd_attr: u64,
    ) -> Option<u16> {
        if servtd_info_hash.len() != SHA384_DIGEST_SIZE {
            return None;
        }
        let target = Measurements::new_with_attr(servtd_info_hash, servtd_attr);
        self.get_engine_svn_by_measurements(&target)
    }

    pub fn get_engine_svn_by_measurements(&self, measurements: &Measurements) -> Option<u16> {
        for mapping in &self.svn_mappings {
            if Self::compare_measurements(&mapping.td_measurements, measurements) {
                return Some(mapping.isvsvn);
            }
        }
        None
    }

    #[inline]
    fn compare_measurements(pattern: &Measurements, target: &Measurements) -> bool {
        // Hex strings are case-insensitive.
        let pattern = pattern.to_ascii_uppercase();
        let target = target.to_ascii_uppercase();
        pattern.tdinfo_hash == target.tdinfo_hash && pattern.servtd_attr == target.servtd_attr
    }
}

/// Packed TDINFO size: 8 + 8 + 8*48 + 0x70 = 512 bytes.
const TDINFO_PACKED_SIZE: usize = 8 + 8 + 8 * SHA384_DIGEST_SIZE + TDINFO_RESERVED_SIZE;
const TDINFO_RESERVED_SIZE: usize = 0x70;

/// Pack the *unmasked* `TdInfoStruct` bytes from its 10 measurement fields in
/// the same canonical order used by `td-shim-tools` (and therefore by
/// `migtd-hash`).
///
/// Field order: attributes, xfam, mrtd, mrconfigid, mrowner, mrownerconfig,
/// rtmr0, rtmr1, rtmr2, rtmr3, reserved(0x70 zero bytes).
///
/// The trailing 0x70 bytes are zero. MigTD does not support bound Service TDs,
/// and attestation verification rejects a nonzero `servtd_hash`.
#[allow(clippy::too_many_arguments)]
pub fn pack_unmasked_tdinfo(
    attributes: &[u8; 8],
    xfam: &[u8; 8],
    mrtd: &[u8; SHA384_DIGEST_SIZE],
    mrconfig_id: &[u8; SHA384_DIGEST_SIZE],
    mrowner: &[u8; SHA384_DIGEST_SIZE],
    mrownerconfig: &[u8; SHA384_DIGEST_SIZE],
    rtmr0: &[u8; SHA384_DIGEST_SIZE],
    rtmr1: &[u8; SHA384_DIGEST_SIZE],
    rtmr2: &[u8; SHA384_DIGEST_SIZE],
    rtmr3: &[u8; SHA384_DIGEST_SIZE],
) -> [u8; TDINFO_PACKED_SIZE] {
    let mut buf = [0u8; TDINFO_PACKED_SIZE];
    let mut off = 0usize;
    let mut put = |off: &mut usize, src: &[u8]| {
        buf[*off..*off + src.len()].copy_from_slice(src);
        *off += src.len();
    };
    put(&mut off, attributes);
    put(&mut off, xfam);
    put(&mut off, mrtd);
    put(&mut off, mrconfig_id);
    put(&mut off, mrowner);
    put(&mut off, mrownerconfig);
    put(&mut off, rtmr0);
    put(&mut off, rtmr1);
    put(&mut off, rtmr2);
    put(&mut off, rtmr3);
    debug_assert_eq!(off, TDINFO_PACKED_SIZE - TDINFO_RESERVED_SIZE);
    buf
}

/// Compute `SERVTD_INFO_HASH` from the 10 individual TDINFO measurement fields
/// and the `SERVTD_ATTR` mask: every field the mask selects is replaced by 0
/// before the TDINFO is packed and hashed. `servtd_attr == 0` gives the hash of
/// the complete TDINFO.
///
/// Formula: `SHA384(pack(masked attributes, xfam, mrtd, ..., rtmr3, reserved))`
#[allow(clippy::too_many_arguments)]
pub fn compute_servtd_info_hash_from_fields(
    attributes: &[u8; 8],
    xfam: &[u8; 8],
    mrtd: &[u8; SHA384_DIGEST_SIZE],
    mrconfig_id: &[u8; SHA384_DIGEST_SIZE],
    mrowner: &[u8; SHA384_DIGEST_SIZE],
    mrownerconfig: &[u8; SHA384_DIGEST_SIZE],
    rtmr0: &[u8; SHA384_DIGEST_SIZE],
    rtmr1: &[u8; SHA384_DIGEST_SIZE],
    rtmr2: &[u8; SHA384_DIGEST_SIZE],
    rtmr3: &[u8; SHA384_DIGEST_SIZE],
    servtd_attr: u64,
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    if !is_valid_servtd_attr(servtd_attr) {
        return Err(PolicyError::InvalidParameter);
    }
    let zero8 = [0u8; 8];
    let zero48 = [0u8; SHA384_DIGEST_SIZE];
    let masked8 = |bit: u64, value: &[u8; 8]| {
        if servtd_attr & bit != 0 {
            zero8
        } else {
            *value
        }
    };
    let masked48 = |bit: u64, value: &[u8; SHA384_DIGEST_SIZE]| {
        if servtd_attr & bit != 0 {
            zero48
        } else {
            *value
        }
    };
    let packed = pack_unmasked_tdinfo(
        attributes,
        &masked8(SERVTD_ATTR_IGNORE_XFAM, xfam),
        &masked48(SERVTD_ATTR_IGNORE_MRTD, mrtd),
        &masked48(SERVTD_ATTR_IGNORE_MRCONFIGID, mrconfig_id),
        &masked48(SERVTD_ATTR_IGNORE_MROWNER, mrowner),
        &masked48(SERVTD_ATTR_IGNORE_MROWNERCONFIG, mrownerconfig),
        &masked48(SERVTD_ATTR_IGNORE_RTMR0, rtmr0),
        &masked48(SERVTD_ATTR_IGNORE_RTMR1, rtmr1),
        &masked48(SERVTD_ATTR_IGNORE_RTMR2, rtmr2),
        &masked48(SERVTD_ATTR_IGNORE_RTMR3, rtmr3),
    );
    digest_sha384(&packed)
        .map_err(|_| PolicyError::HashCalculation)?
        .try_into()
        .map_err(|_| PolicyError::HashCalculation)
}

/// Compute `tdinfo_hash` (the hash of the complete, unmasked TDINFO) from the
/// 10 individual TDINFO measurement fields. Equals `init_servtd_info_hash` for
/// MigTDs bound with `servtd_attr == 0`.
#[allow(clippy::too_many_arguments)]
pub fn compute_tdinfo_hash_from_fields(
    attributes: &[u8; 8],
    xfam: &[u8; 8],
    mrtd: &[u8; SHA384_DIGEST_SIZE],
    mrconfig_id: &[u8; SHA384_DIGEST_SIZE],
    mrowner: &[u8; SHA384_DIGEST_SIZE],
    mrownerconfig: &[u8; SHA384_DIGEST_SIZE],
    rtmr0: &[u8; SHA384_DIGEST_SIZE],
    rtmr1: &[u8; SHA384_DIGEST_SIZE],
    rtmr2: &[u8; SHA384_DIGEST_SIZE],
    rtmr3: &[u8; SHA384_DIGEST_SIZE],
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    compute_servtd_info_hash_from_fields(
        attributes,
        xfam,
        mrtd,
        mrconfig_id,
        mrowner,
        mrownerconfig,
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
        0,
    )
}

fn as_array<const N: usize>(slice: &[u8]) -> Result<&[u8; N], PolicyError> {
    slice.try_into().map_err(|_| PolicyError::InvalidParameter)
}

/// Compute `tdinfo_hash` (unmasked) for the TD described by `report`.
pub fn compute_tdinfo_hash_from_report(
    report: &Report,
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    compute_servtd_info_hash_from_report(report, 0)
}

/// Compute `SERVTD_INFO_HASH` for the TD described by `report` under the
/// `servtd_attr` mask. Returns the 48-byte hash.
pub fn compute_servtd_info_hash_from_report(
    report: &Report,
    servtd_attr: u64,
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    let attributes =
        as_array::<8>(report.get_migtd_info_property(&MigTdInfoProperty::Attributes)?)?;
    let xfam = as_array::<8>(report.get_migtd_info_property(&MigTdInfoProperty::Xfam)?)?;
    let mrtd =
        as_array::<SHA384_DIGEST_SIZE>(report.get_migtd_info_property(&MigTdInfoProperty::MrTd)?)?;
    let mrconfig_id = as_array::<SHA384_DIGEST_SIZE>(
        report.get_migtd_info_property(&MigTdInfoProperty::MrConfigId)?,
    )?;
    let mrowner = as_array::<SHA384_DIGEST_SIZE>(
        report.get_migtd_info_property(&MigTdInfoProperty::MrOwner)?,
    )?;
    let mrownerconfig = as_array::<SHA384_DIGEST_SIZE>(
        report.get_migtd_info_property(&MigTdInfoProperty::MrOwnerConfig)?,
    )?;
    let rtmr0 =
        as_array::<SHA384_DIGEST_SIZE>(report.get_migtd_info_property(&MigTdInfoProperty::Rtmr0)?)?;
    let rtmr1 =
        as_array::<SHA384_DIGEST_SIZE>(report.get_migtd_info_property(&MigTdInfoProperty::Rtmr1)?)?;
    let rtmr2 =
        as_array::<SHA384_DIGEST_SIZE>(report.get_migtd_info_property(&MigTdInfoProperty::Rtmr2)?)?;
    let rtmr3 =
        as_array::<SHA384_DIGEST_SIZE>(report.get_migtd_info_property(&MigTdInfoProperty::Rtmr3)?)?;
    compute_servtd_info_hash_from_fields(
        attributes,
        xfam,
        mrtd,
        mrconfig_id,
        mrowner,
        mrownerconfig,
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
        servtd_attr,
    )
}

#[cfg(test)]
mod test {
    use super::*;

    fn mapping_with_hashes(entries: &[(String, u16)]) -> TdTcbMapping {
        let mut mapping: TdTcbMapping =
            serde_json::from_slice(include_bytes!("../../test/policy_v2/tcb_mapping.json"))
                .unwrap();
        mapping.svn_mappings = entries
            .iter()
            .map(|(hash, isvsvn)| SvnMapping {
                td_measurements: Measurements::new_from_hex(hash.clone(), 0),
                isvsvn: *isvsvn,
            })
            .collect();
        mapping
    }

    #[test]
    fn test_get_engine_svn() {
        let engine_bytes = include_bytes!("../../test/policy_v2/tcb_mapping.json");
        let engine: TdTcbMapping = serde_json::from_slice(engine_bytes).unwrap();
        engine.validate().unwrap();

        // The first svnMappings entry in the test fixture is the canonical
        // tdinfo_hash (= SHA384(TDINFO) = init_servtd_info_hash for attr=0).
        let expected_hash = engine.svn_mappings[0].td_measurements.tdinfo_hash.clone();
        let target = Measurements::new_from_hex(expected_hash.clone(), 0);
        assert_eq!(engine.get_engine_svn_by_measurements(&target), Some(1));

        // Case-insensitive match.
        let lower = Measurements::new_from_hex(expected_hash.to_ascii_lowercase(), 0);
        assert_eq!(engine.get_engine_svn_by_measurements(&lower), Some(1));

        // Wrong hash -> no match.
        let bogus = Measurements::new_from_hex(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .into(),
            0,
        );
        assert!(engine.get_engine_svn_by_measurements(&bogus).is_none());
    }

    #[test]
    fn json_mapping_rejects_malformed_hashes() {
        for hash in [
            String::new(),
            "ab".repeat(47),
            "ab".repeat(49),
            "a".repeat(95),
            "zz".repeat(48),
            "\u{00e9}".repeat(48),
        ] {
            assert!(matches!(
                mapping_with_hashes(&[(hash, 1)]).validate(),
                Err(PolicyError::InvalidServtdTcbMapping)
            ));
        }
    }

    #[test]
    fn json_mapping_rejects_conflicting_duplicate_svns() {
        let hash = "ab".repeat(48);
        for duplicate in [hash.clone(), hash.to_ascii_uppercase()] {
            assert!(matches!(
                mapping_with_hashes(&[(hash.clone(), 1), (duplicate, 2)]).validate(),
                Err(PolicyError::InvalidServtdTcbMapping)
            ));
        }
    }

    #[test]
    fn json_mapping_preserves_identical_duplicates() {
        let mut mapping = mapping_with_hashes(&[
            ("ab".repeat(48), 1),
            ("ab".repeat(48), 1),
            ("AB".repeat(48), 1),
            ("cd".repeat(48), 2),
        ]);
        mapping.validate().unwrap();
        assert_eq!(mapping.get_engine_svn_by_tdinfo_hash(&[0xab; 48]), Some(1));
        assert_eq!(mapping.get_engine_svn_by_tdinfo_hash(&[0xcd; 48]), Some(2));

        mapping.svn_mappings.clear();
        mapping.validate().unwrap();
        assert!(mapping.get_engine_svn_by_tdinfo_hash(&[0xab; 48]).is_none());
    }

    #[test]
    fn legacy_measurements_without_tdinfo_hash_are_rejected() {
        assert!(
            serde_json::from_str::<Measurements>(r#"{"mrtd":"00","rtmr0":"00","rtmr1":"00"}"#)
                .is_err()
        );
    }

    #[test]
    fn camel_case_tdinfo_hash_is_rejected() {
        assert!(serde_json::from_str::<Measurements>(r#"{"tdinfoHash":"00"}"#).is_err());
    }

    #[test]
    fn verify_servtd_collateral_signatures() {
        let servtd_collateral = include_bytes!("../../test/policy_v2/servtd_collateral.json");
        let collateral: ServtdCollateral =
            serde_json::from_slice(servtd_collateral).expect("Failed to parse collateral");
        let issuer_chain = collateral
            .servtd_tcb_mapping_issuer_chain
            .as_deref()
            .unwrap_or_else(|| {
                include_str!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem")
            });
        assert!(collateral
            .servtd_tcb_mapping
            .verify_signature(issuer_chain.as_bytes())
            .is_ok());
    }

    #[test]
    fn signed_conflicting_json_mapping_is_rejected() {
        let input = include_bytes!(
            "../../test/policy_v2/tcb_mapping_validation/conflicting_svn_signed.json"
        );
        let chain = include_bytes!("../../test/policy_v2/tcb_mapping_validation/issuer_chain.pem");
        let mapping = RawServtdTcbMapping::deserialize_from_json(input).unwrap();
        let signature = hex_string_to_bytes(&mapping.signature).unwrap();
        crypto::verify_cert_chain_and_signature(
            chain,
            mapping.td_tcb_mapping.get().as_bytes(),
            &signature,
        )
        .unwrap();

        let result = mapping.verify_signature(chain);
        assert!(
            matches!(result, Err(PolicyError::InvalidServtdTcbMapping)),
            "{result:?}"
        );
    }

    #[test]
    fn td_identity_simplified_parse_and_lookup() {
        // The simplified TD Identity carries only the envelope + tcbLevels;
        // the dropped TDINFO / SGX-enclave fields must not be required.
        let json = r#"{
            "id": "identity-1",
            "version": 1,
            "issueDate": "2025-01-01T00:00:00Z",
            "nextUpdate": "2026-01-01T00:00:00Z",
            "tcbLevels": [
                { "tcb": { "isvsvn": 1 }, "tcbDate": "2025-01-01T00:00:00Z", "tcbStatus": "Revoked" },
                { "tcb": { "isvsvn": 3 }, "tcbDate": "2025-06-01T00:00:00Z", "tcbStatus": "UpToDate" }
            ]
        }"#;
        let identity = TdIdentity::deserialize_from_json(json.as_bytes()).unwrap();
        let level = identity.get_tcb_level_by_svn(3).expect("svn 3 present");
        assert_eq!(level.tcb.isvsvn, 3);
        assert_eq!(level.tcb_date, "2025-06-01T00:00:00Z");
        assert_eq!(level.tcb_status, "UpToDate");

        let level = identity
            .get_tcb_level_by_svn(2)
            .expect("svn 2 floor-matches svn 1");
        assert_eq!(level.tcb.isvsvn, 1);
        assert_eq!(level.tcb_status, "Revoked");
        assert!(identity.get_tcb_level_by_svn(0).is_none());
    }

    #[test]
    fn servtd_collateral_identity_is_optional() {
        // With TD Identity present, both optional fields deserialize.
        let with_identity = r#"{
            "majorVersion": 1,
            "minorVersion": 0,
            "servtdTcbMappingIssuerChain": "chain",
            "servtdTcbMapping": { "tdTcbMapping": {}, "signature": "aa" },
            "servtdIdentityIssuerChain": "chain",
            "servtdIdentity": { "tdIdentity": {}, "signature": "bb" }
        }"#;
        let coll: ServtdCollateral =
            serde_json::from_slice(with_identity.as_bytes()).expect("parse with identity");
        assert!(coll.servtd_identity.is_some());
        assert!(coll.servtd_identity_issuer_chain.is_some());

        // SVN-only: omitting the identity fields is valid and leaves them None.
        let svn_only = r#"{
            "majorVersion": 1,
            "minorVersion": 0,
            "servtdTcbMappingIssuerChain": "chain",
            "servtdTcbMapping": { "tdTcbMapping": {}, "signature": "aa" }
        }"#;
        let coll: ServtdCollateral =
            serde_json::from_slice(svn_only.as_bytes()).expect("parse svn-only");
        assert!(coll.servtd_identity.is_none());
        assert!(coll.servtd_identity_issuer_chain.is_none());
    }

    /// Regression guard for the 512-byte TDINFO wire layout.
    #[test]
    fn packed_tdinfo_size_matches_servtd_ext_layout() {
        assert_eq!(TDINFO_PACKED_SIZE, 512);
        let attributes = [0x01u8; 8];
        let xfam = [0x02u8; 8];
        let m = [
            [0x10u8; SHA384_DIGEST_SIZE],
            [0x20u8; SHA384_DIGEST_SIZE],
            [0x30u8; SHA384_DIGEST_SIZE],
            [0x40u8; SHA384_DIGEST_SIZE],
            [0x50u8; SHA384_DIGEST_SIZE],
            [0x60u8; SHA384_DIGEST_SIZE],
            [0x70u8; SHA384_DIGEST_SIZE],
            [0x80u8; SHA384_DIGEST_SIZE],
        ];
        let packed = pack_unmasked_tdinfo(
            &attributes,
            &xfam,
            &m[0],
            &m[1],
            &m[2],
            &m[3],
            &m[4],
            &m[5],
            &m[6],
            &m[7],
        );
        assert_eq!(packed.len(), 512);
        assert_eq!(&packed[..8], &attributes);
        assert_eq!(&packed[8..16], &xfam);
        for (i, expected) in m.iter().enumerate() {
            let off = 16 + i * SHA384_DIGEST_SIZE;
            assert_eq!(&packed[off..off + SHA384_DIGEST_SIZE], &expected[..]);
        }
        assert!(packed[16 + 8 * SHA384_DIGEST_SIZE..]
            .iter()
            .all(|b| *b == 0));
    }

    /// Cross-implementation parity: `tdinfo_hash` computed from the
    /// canonical 10 fields here MUST equal `SHA384(unmasked_TDINFO_512)` used
    /// by `migtd-hash`, the TCB-mapping CoRIM production tools, and the bash
    /// mock-test scripts. If they ever drift, runtime policy lookup silently
    /// fails for all valid TDs.
    #[test]
    fn tdinfo_hash_matches_direct_sha384_formula() {
        use crypto::hash::digest_sha384;
        let attributes = [0xAAu8; 8];
        let xfam = [0xBBu8; 8];
        let mrtd = [0x11u8; SHA384_DIGEST_SIZE];
        let mrconfig_id = [0x22u8; SHA384_DIGEST_SIZE];
        let mrowner = [0x33u8; SHA384_DIGEST_SIZE];
        let mrownerconfig = [0x44u8; SHA384_DIGEST_SIZE];
        let rtmr0 = [0x55u8; SHA384_DIGEST_SIZE];
        let rtmr1 = [0x66u8; SHA384_DIGEST_SIZE];
        let rtmr2 = [0x77u8; SHA384_DIGEST_SIZE];
        let rtmr3 = [0x88u8; SHA384_DIGEST_SIZE];

        let got = compute_tdinfo_hash_from_fields(
            &attributes,
            &xfam,
            &mrtd,
            &mrconfig_id,
            &mrowner,
            &mrownerconfig,
            &rtmr0,
            &rtmr1,
            &rtmr2,
            &rtmr3,
        )
        .unwrap();

        let packed = pack_unmasked_tdinfo(
            &attributes,
            &xfam,
            &mrtd,
            &mrconfig_id,
            &mrowner,
            &mrownerconfig,
            &rtmr0,
            &rtmr1,
            &rtmr2,
            &rtmr3,
        );
        assert_eq!(packed.len(), 512);
        let expected = digest_sha384(&packed).unwrap();

        assert_eq!(&got[..], expected.as_slice());
    }

    fn hash_with_owner(mrowner: u8, mask: u64) -> [u8; SHA384_DIGEST_SIZE] {
        compute_servtd_info_hash_from_fields(
            &[0xAA; 8],
            &[0xBB; 8],
            &[0x11; SHA384_DIGEST_SIZE],
            &[0x22; SHA384_DIGEST_SIZE],
            &[mrowner; SHA384_DIGEST_SIZE],
            &[0x44; SHA384_DIGEST_SIZE],
            &[0x55; SHA384_DIGEST_SIZE],
            &[0x66; SHA384_DIGEST_SIZE],
            &[0x77; SHA384_DIGEST_SIZE],
            &[0x88; SHA384_DIGEST_SIZE],
            mask,
        )
        .unwrap()
    }

    fn mapping_with_attrs(entries: &[([u8; SHA384_DIGEST_SIZE], u64, u16)]) -> TdTcbMapping {
        let mut mapping = mapping_with_hashes(&[]);
        mapping.svn_mappings = entries
            .iter()
            .map(|(hash, attr, isvsvn)| SvnMapping {
                td_measurements: Measurements::new_with_attr(hash, *attr),
                isvsvn: *isvsvn,
            })
            .collect();
        mapping
    }

    #[test]
    fn servtd_attr_accepts_only_supported_bits() {
        assert!(is_valid_servtd_attr(0));
        assert!(is_valid_servtd_attr(
            SERVTD_ATTR_IGNORE_MROWNER | SERVTD_ATTR_IGNORE_MROWNERCONFIG
        ));
        assert!(is_valid_servtd_attr(SERVTD_ATTR_VALID_MASK));
        // Reserved low bits, IGNORE_ATTRIBUTES (bit 32), bits 42..=48 and above.
        for bit in [0, 31, 32, 42, 48, 49, 63] {
            assert!(!is_valid_servtd_attr(1u64 << bit), "bit {}", bit);
        }
    }

    #[test]
    fn masked_hash_ignores_only_selected_fields() {
        let mask = SERVTD_ATTR_IGNORE_MROWNER;
        assert_eq!(hash_with_owner(0x33, mask), hash_with_owner(0x99, mask));
        assert_ne!(hash_with_owner(0x33, 0), hash_with_owner(0x99, 0));
        // A mask hiding another field does not hide MROWNER.
        let other = SERVTD_ATTR_IGNORE_RTMR3;
        assert_ne!(hash_with_owner(0x33, other), hash_with_owner(0x99, other));
        // The mask changes the hash of the same TDINFO.
        assert_ne!(hash_with_owner(0x33, 0), hash_with_owner(0x33, mask));
    }

    #[test]
    fn unmasked_hash_matches_attr_zero() {
        assert_eq!(
            hash_with_owner(0x33, 0),
            compute_tdinfo_hash_from_fields(
                &[0xAA; 8],
                &[0xBB; 8],
                &[0x11; SHA384_DIGEST_SIZE],
                &[0x22; SHA384_DIGEST_SIZE],
                &[0x33; SHA384_DIGEST_SIZE],
                &[0x44; SHA384_DIGEST_SIZE],
                &[0x55; SHA384_DIGEST_SIZE],
                &[0x66; SHA384_DIGEST_SIZE],
                &[0x77; SHA384_DIGEST_SIZE],
                &[0x88; SHA384_DIGEST_SIZE],
            )
            .unwrap()
        );
    }

    #[test]
    fn invalid_mask_is_rejected_when_hashing() {
        let result = compute_servtd_info_hash_from_fields(
            &[0; 8],
            &[0; 8],
            &[0; SHA384_DIGEST_SIZE],
            &[0; SHA384_DIGEST_SIZE],
            &[0; SHA384_DIGEST_SIZE],
            &[0; SHA384_DIGEST_SIZE],
            &[0; SHA384_DIGEST_SIZE],
            &[0; SHA384_DIGEST_SIZE],
            &[0; SHA384_DIGEST_SIZE],
            &[0; SHA384_DIGEST_SIZE],
            1 << 32,
        );
        assert!(matches!(result, Err(PolicyError::InvalidParameter)));
    }

    #[test]
    fn lookup_by_hash_requires_matching_attr() {
        let mask = SERVTD_ATTR_IGNORE_MROWNER;
        let hash = hash_with_owner(0x33, mask);
        let mapping = mapping_with_attrs(&[(hash, mask, 7)]);
        assert_eq!(
            mapping.get_engine_svn_by_servtd_info_hash(&hash, mask),
            Some(7)
        );
        assert_eq!(mapping.get_engine_svn_by_servtd_info_hash(&hash, 0), None);
        assert_eq!(mapping.get_engine_svn_by_tdinfo_hash(&hash), None);
    }

    #[test]
    fn lookup_with_tries_each_attr_in_the_mapping() {
        let mask = SERVTD_ATTR_IGNORE_MROWNER;
        let mapping = mapping_with_attrs(&[
            (hash_with_owner(0x33, 0), 0, 1),
            (hash_with_owner(0x33, mask), mask, 2),
        ]);
        assert_eq!(mapping.servtd_attrs(), vec![0, mask]);

        // A TD whose owner differs from the attr-0 release still matches the
        // masked release, whatever its owner field is.
        for owner in [0x33, 0x99] {
            assert_eq!(
                mapping.lookup_with(|attr| Some(hash_with_owner(owner, attr))),
                if owner == 0x33 {
                    // Matches both entries with different SVNs: rejected.
                    None
                } else {
                    Some((2, mask))
                }
            );
        }
        // No entry matches, or the hash cannot be computed.
        assert_eq!(
            mapping.lookup_with(|_| Some([0xEE; SHA384_DIGEST_SIZE])),
            None
        );
        assert_eq!(mapping.lookup_with(|_| None), None);
    }

    #[test]
    fn lookup_with_accepts_agreeing_matches() {
        let mask = SERVTD_ATTR_IGNORE_MROWNER;
        let mapping = mapping_with_attrs(&[
            (hash_with_owner(0x33, 0), 0, 5),
            (hash_with_owner(0x33, mask), mask, 5),
        ]);
        assert_eq!(
            mapping.lookup_with(|attr| Some(hash_with_owner(0x33, attr))),
            Some((5, 0))
        );
    }

    #[test]
    fn mapping_validation_checks_attr() {
        let hash = [0x11u8; SHA384_DIGEST_SIZE];
        let mask = SERVTD_ATTR_IGNORE_MROWNER;
        // Same hash under different attrs may map to different SVNs.
        assert!(mapping_with_attrs(&[(hash, 0, 1), (hash, mask, 2)])
            .validate()
            .is_ok());
        // Same (hash, attr) with different SVNs is a conflict.
        assert!(mapping_with_attrs(&[(hash, mask, 1), (hash, mask, 2)])
            .validate()
            .is_err());
        // Unsupported attr bits are rejected.
        assert!(mapping_with_attrs(&[(hash, 1 << 32, 1)])
            .validate()
            .is_err());
    }

    #[test]
    fn servtd_attr_json_defaults_to_zero_and_round_trips() {
        let hash = "AB".repeat(SHA384_DIGEST_SIZE);
        let mask = SERVTD_ATTR_IGNORE_MROWNER;

        // Without a mask the attribute is 0 and is not serialized.
        let plain: Measurements =
            serde_json::from_str(&alloc::format!(r#"{{"servtdInfoHash":"{hash}"}}"#)).unwrap();
        assert_eq!(plain.servtd_attr, 0);
        let json = serde_json::to_string(&plain).unwrap();
        assert!(json.contains("servtdInfoHash"));
        assert!(!json.contains("servtdAttr"));

        // Current key names.
        let with_attr: Measurements = serde_json::from_str(&alloc::format!(
            r#"{{"servtdInfoHash":"{hash}","servtdAttr":{mask}}}"#
        ))
        .unwrap();
        assert_eq!(with_attr.servtd_attr, mask);
        let json = serde_json::to_string(&with_attr).unwrap();
        assert!(json.contains("\"servtdInfoHash\"") && json.contains("\"servtdAttr\""));
        assert!(!json.contains("tdinfo_hash") && !json.contains("servtd_attr"));
        assert_eq!(
            serde_json::from_str::<Measurements>(&json).unwrap(),
            with_attr
        );

        // Earlier key names are still accepted.
        let legacy: Measurements = serde_json::from_str(&alloc::format!(
            r#"{{"tdinfo_hash":"{hash}","servtd_attr":{mask}}}"#
        ))
        .unwrap();
        assert_eq!(legacy, with_attr);
        let legacy_plain: Measurements =
            serde_json::from_str(&alloc::format!(r#"{{"tdinfo_hash":"{hash}"}}"#)).unwrap();
        assert_eq!(legacy_plain, plain);

        // A key given under both names is rejected.
        assert!(serde_json::from_str::<Measurements>(&alloc::format!(
            r#"{{"servtdInfoHash":"{hash}","tdinfo_hash":"{hash}"}}"#
        ))
        .is_err());
    }
}
