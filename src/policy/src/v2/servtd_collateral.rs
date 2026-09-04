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
pub struct VerifiedServtdCollateral {
    pub servtd_identity: TdIdentity,
    pub servtd_tcb_mapping: TdTcbMapping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServtdCollateral<'a> {
    pub major_version: u32,
    pub minor_version: u32,
    pub servtd_identity_issuer_chain: String,
    #[serde(borrow)]
    pub servtd_identity: RawServtdIdentity<'a>,
    pub servtd_tcb_mapping: RawServtdTcbMapping<'a>,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_evaluation_number: u32,
    pub xfam: String,
    pub attributes: String,
    pub mr_config_id: String,
    pub mr_owner: String,
    pub mr_owner_config: String,
    pub mrsigner: String,
    pub isv_prod_id: u16,
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Measurements {
    /// Single-hash measurement key for hash-to-SVN TCB mapping.
    ///
    /// Equals `init_servtd_info_hash` for production MigTDs (servtd_attr=0):
    ///   tdinfo_hash = SHA384(unmasked TDINFO_STRUCT bytes)
    ///
    /// Hex-encoded (case-insensitive). The serde alias accepts both
    /// the canonical snake_case key and the legacy camelCase spelling.
    #[serde(rename = "tdinfo_hash", alias = "tdinfoHash")]
    pub tdinfo_hash: String,
}

impl Measurements {
    pub fn new_from_bytes(tdinfo_hash: &[u8]) -> Self {
        Measurements {
            tdinfo_hash: bytes_to_hex_string(tdinfo_hash),
        }
    }

    fn to_ascii_uppercase(&self) -> Self {
        Measurements {
            tdinfo_hash: self.tdinfo_hash.to_ascii_uppercase(),
        }
    }
}

impl TdTcbMapping {
    fn validate(&self) -> Result<(), PolicyError> {
        for (index, mapping) in self.svn_mappings.iter().enumerate() {
            let hash = hex_string_to_bytes(&mapping.td_measurements.tdinfo_hash)
                .map_err(|_| PolicyError::InvalidServtdTcbMapping)?;
            if hash.len() != SHA384_DIGEST_SIZE {
                return Err(PolicyError::InvalidServtdTcbMapping);
            }

            for previous in &self.svn_mappings[..index] {
                if previous
                    .td_measurements
                    .tdinfo_hash
                    .eq_ignore_ascii_case(&mapping.td_measurements.tdinfo_hash)
                    && previous.isvsvn != mapping.isvsvn
                {
                    return Err(PolicyError::InvalidServtdTcbMapping);
                }
            }
        }
        Ok(())
    }

    /// Look up the engine SVN for the TD represented by `report` by computing
    /// `tdinfo_hash` (per redesign §RTMR-layout) and matching the
    /// `svnMappings[].tdMeasurements.tdinfoHash` entries.
    pub fn get_engine_svn_by_report(&self, report: &Report) -> Option<u16> {
        let tdinfo_hash = compute_tdinfo_hash_from_report(report).ok()?;
        self.get_engine_svn_by_tdinfo_hash(&tdinfo_hash)
    }

    /// Look up the engine SVN by an already-computed `tdinfo_hash`
    /// (48 raw bytes). This is the canonical entry point for the redesign.
    pub fn get_engine_svn_by_tdinfo_hash(&self, tdinfo_hash: &[u8]) -> Option<u16> {
        if tdinfo_hash.len() != SHA384_DIGEST_SIZE {
            return None;
        }
        let target = Measurements::new_from_bytes(tdinfo_hash);
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

    /// `migtdengine check`: the peer engine must not be older than the engine
    /// recorded at initial binding (`enginesvnsrc >= enginesvninit`).
    ///
    /// `enginedatesrc >= enginedateinit` is not compared separately: the engine
    /// date is looked up from this SVN in `servtd_identity`, so it follows only
    /// while `tcbLevels` are non-decreasing in `isvsvn` — Intel's Enclave
    /// Identity convention, which nothing here validates.
    pub fn check_engine_not_older(
        &self,
        peer: &Measurements,
        init: &Measurements,
    ) -> Result<(), PolicyError> {
        let peer_svn = self
            .get_engine_svn_by_measurements(peer)
            .ok_or(PolicyError::SvnMismatch)?;
        let init_svn = self
            .get_engine_svn_by_measurements(init)
            .ok_or(PolicyError::SvnMismatch)?;

        if peer_svn < init_svn {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }

    #[inline]
    fn compare_measurements(pattern: &Measurements, target: &Measurements) -> bool {
        // Hex strings are case-insensitive.
        let pattern = pattern.to_ascii_uppercase();
        let target = target.to_ascii_uppercase();
        pattern.tdinfo_hash == target.tdinfo_hash
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
/// The trailing 0x70 bytes are zero. This corresponds to the SEAM module's
/// internal `TDINFO_STRUCT` layout used to compute `init_servtd_info_hash`
/// when a service TD is bound; for the bound MigTD itself, `servtd_hash` is
/// always zero (no nested bindings).
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

/// Compute `tdinfo_hash` from the 10 individual TDINFO measurement fields.
/// Equals `init_servtd_info_hash` for MigTDs bound with `servtd_attr == 0`.
///
/// Formula: `SHA384(pack(attributes, xfam, mrtd, ..., rtmr3, reserved))`
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
    let packed = pack_unmasked_tdinfo(
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
    );
    digest_sha384(&packed)
        .map_err(|_| PolicyError::HashCalculation)?
        .try_into()
        .map_err(|_| PolicyError::HashCalculation)
}

fn as_array<const N: usize>(slice: &[u8]) -> Result<&[u8; N], PolicyError> {
    slice.try_into().map_err(|_| PolicyError::InvalidParameter)
}

/// Compute `tdinfo_hash` for the TD described by `report`.
///
/// Returns the 48-byte hash, equals `init_servtd_info_hash` for
/// production MigTDs (`servtd_attr == 0`).
pub fn compute_tdinfo_hash_from_report(
    report: &Report,
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
    compute_tdinfo_hash_from_fields(
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
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_engine_svn() {
        let engine_bytes = include_bytes!("../../test/policy_v2/tcb_mapping.json");
        let engine: TdTcbMapping = serde_json::from_slice(engine_bytes).unwrap();
        engine.validate().unwrap();

        // A source policy must retain both the historical hash that initialized
        // the tenant TD and the current source MigTD hash.
        let init_hash = engine.svn_mappings[0].td_measurements.tdinfo_hash.clone();
        let current_hash = engine.svn_mappings[1].td_measurements.tdinfo_hash.clone();
        let target = Measurements {
            tdinfo_hash: init_hash.clone(),
        };
        assert_eq!(engine.get_engine_svn_by_measurements(&target), Some(1));
        let current = Measurements {
            tdinfo_hash: current_hash,
        };
        assert_eq!(engine.get_engine_svn_by_measurements(&current), Some(2));

        // Case-insensitive match.
        let lower = Measurements {
            tdinfo_hash: init_hash.to_ascii_lowercase(),
        };
        assert_eq!(engine.get_engine_svn_by_measurements(&lower), Some(1));

        // Wrong hash -> no match.
        let bogus = Measurements {
            tdinfo_hash:
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                    .into(),
        };
        assert!(engine.get_engine_svn_by_measurements(&bogus).is_none());
    }

    #[test]
    fn legacy_measurements_without_tdinfo_hash_are_rejected() {
        assert!(
            serde_json::from_str::<Measurements>(r#"{"mrtd":"00","rtmr0":"00","rtmr1":"00"}"#)
                .is_err()
        );
    }

    #[test]
    fn test_check_engine_not_older() {
        let engine = |tag: u8| Measurements::new_from_bytes(&[tag; 48]);
        let mapping = TdTcbMapping {
            id: String::from("TEST"),
            version: 1,
            issue_date: String::from("2025-01-01T00:00:00Z"),
            next_update: String::from("2026-01-01T00:00:00Z"),
            svn_mappings: [(0xa1u8, 1u16), (0xb2, 2)]
                .iter()
                .map(|(tag, isvsvn)| SvnMapping {
                    td_measurements: engine(*tag),
                    isvsvn: *isvsvn,
                })
                .collect(),
        };

        // Downgrade: peer engine older than the engine bound at init.
        assert!(mapping
            .check_engine_not_older(&engine(0xa1), &engine(0xb2))
            .is_err());
        assert!(mapping
            .check_engine_not_older(&engine(0xb2), &engine(0xa1))
            .is_ok());
        assert!(mapping
            .check_engine_not_older(&engine(0xa1), &engine(0xa1))
            .is_ok());

        // Either side unresolvable on the local mapping is a rejection.
        assert!(mapping
            .check_engine_not_older(&engine(0xcc), &engine(0xa1))
            .is_err());
        assert!(mapping
            .check_engine_not_older(&engine(0xa1), &engine(0xcc))
            .is_err());
    }

    #[test]
    fn verify_servtd_collateral_signatures() {
        let servtd_collateral = include_bytes!("../../test/policy_v2/servtd_collateral.json");
        let collateral: ServtdCollateral =
            serde_json::from_slice(servtd_collateral).expect("Failed to parse collateral");
        let policy_issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        assert!(collateral
            .servtd_tcb_mapping
            .verify_signature(policy_issuer_chain)
            .is_ok());
        assert!(collateral
            .servtd_identity
            .verify_signature(collateral.servtd_identity_issuer_chain.as_bytes())
            .is_ok());
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
    /// by `migtd-hash`, `mig-td-tools tdinfo-hash`, and the bash mock-test
    /// scripts. If they ever drift, runtime policy lookup silently fails for
    /// all valid TDs.
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
}
