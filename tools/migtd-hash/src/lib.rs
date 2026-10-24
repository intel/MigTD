// Copyright (c) 2023 - 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Error, Result};
use crypto::{hash::digest_sha384, SHA384_DIGEST_SIZE};
use igvm::{IgvmDirectiveHeader, IgvmFile};
use migtd::{
    config::{
        CONFIG_VOLUME_SIZE, MIGTD_POLICY_FFS_GUID, MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID,
        MIGTD_ROOT_CA_FFS_GUID, MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID,
    },
    event_log::TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
    policy,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
};
use td_layout::build_time::TD_SHIM_CONFIG_BASE;
use td_shim_interface::td_uefi_pi::{fv, pi};
use td_shim_tools::tee_info_hash::{Manifest, TdInfoStruct};

const MIGTD_IMAGE_SIZE: u64 = 0x100_0000;

pub const SERVTD_TYPE_MIGTD: u16 = 0;

const SERVTD_ATTR_IGNORE_ATTRIBUTES: u64 = 0x1_0000_0000;
const SERVTD_ATTR_IGNORE_XFAM: u64 = 0x2_0000_0000;
const SERVTD_ATTR_IGNORE_MRTD: u64 = 0x4_0000_0000;
const SERVTD_ATTR_IGNORE_MRCONFIGID: u64 = 0x8_0000_0000;
const SERVTD_ATTR_IGNORE_MROWNER: u64 = 0x10_0000_0000;
const SERVTD_ATTR_IGNORE_MROWNERCONFIG: u64 = 0x20_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR0: u64 = 0x40_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR1: u64 = 0x80_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR2: u64 = 0x100_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR3: u64 = 0x200_0000_0000;

/// Build the unmasked TDINFO_STRUCT from the MigTD image and its manifest.
///
/// MRTD/RTMR0 are derived from the IGVM image's measured pages alone.
/// For policy v2, RTMR1 uses the CFV's direct or PEM-derived signer anchor;
/// RTMR2 uses canonical policyData, not the outer policy signature.
/// The build pipeline produces a base IGVM with dummy CFV contents; the release
/// pipeline injects production policy and signer-anchor source bytes into the
/// same base IGVM via `td-shim-enroll` (no Rust rebuild for enrollment alone) and
/// then calls this function on the re-enrolled binary to get the production
/// `tdinfo_hash`. There is therefore no projection / override path here:
/// what the IGVM contains is what we measure.
///
/// This does NOT apply any `servtd_attr` ignore-bit masking. Call
/// [`apply_servtd_attr_masks`] separately if you need a masked copy. The
/// unmasked struct is required for the `tdinfo_hash` field of v2 TCB mappings:
/// `tdinfo_hash = SHA384(unmasked_TDINFO) = init_servtd_info_hash` when
/// `servtd_attr == 0`.
pub fn build_td_info_unmasked(
    manifest: &[u8],
    mut image: File,
    is_ra_disabled: bool,
    is_policy_v2: bool,
    igvmformat: bool,
) -> Result<TdInfoStruct, Error> {
    // Initialize the configurable fields of TD info structure.
    let manifest = serde_json::from_slice::<Manifest>(manifest)?;
    let mut td_info = TdInfoStruct {
        attributes: manifest.attributes,
        xfam: manifest.xfam,
        mrconfig_id: manifest.mrconfigid,
        mrowner: manifest.mrowner,
        mrownerconfig: manifest.mrownerconfig,
        ..Default::default()
    };

    if igvmformat {
        td_info.build_igvmmrtd(&mut image);
    } else {
        td_info.build_mrtd(&mut image, MIGTD_IMAGE_SIZE);
    }
    td_info.build_rtmr_with_seperator(0);

    let mut cfv = vec![0u8; CONFIG_VOLUME_SIZE];
    image.seek(SeekFrom::Start(0))?;
    if igvmformat {
        cfv = read_igvm_cfv_data(&mut image)?;
    } else {
        image.read_exact(&mut cfv)?;
    }

    let rtmr1 = rtmr1(&cfv, &td_info.rtmr1, is_policy_v2)?;
    td_info.rtmr1.copy_from_slice(rtmr1.as_slice());
    td_info
        .rtmr2
        .copy_from_slice(rtmr2(&cfv, is_ra_disabled, is_policy_v2)?.as_slice());

    Ok(td_info)
}

/// Field-by-field clone of a [`TdInfoStruct`] (which does not derive [`Clone`]).
pub fn clone_td_info(td: &TdInfoStruct) -> TdInfoStruct {
    TdInfoStruct {
        attributes: td.attributes,
        xfam: td.xfam,
        mrtd: td.mrtd,
        mrconfig_id: td.mrconfig_id,
        mrowner: td.mrowner,
        mrownerconfig: td.mrownerconfig,
        rtmr0: td.rtmr0,
        rtmr1: td.rtmr1,
        rtmr2: td.rtmr2,
        rtmr3: td.rtmr3,
        reserved: td.reserved,
    }
}

/// Apply the `IGNORE_*` masks in `servtd_attr` to `td_info` in place.
pub fn apply_servtd_attr_masks(td_info: &mut TdInfoStruct, servtd_attr: u64) {
    if (servtd_attr & SERVTD_ATTR_IGNORE_ATTRIBUTES) != 0 {
        td_info.attributes.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_XFAM) != 0 {
        td_info.xfam.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MRTD) != 0 {
        td_info.mrtd.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MRCONFIGID) != 0 {
        td_info.mrconfig_id.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MROWNER) != 0 {
        td_info.mrowner.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MROWNERCONFIG) != 0 {
        td_info.mrownerconfig.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR0) != 0 {
        td_info.rtmr0.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR1) != 0 {
        td_info.rtmr1.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR2) != 0 {
        td_info.rtmr2.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR3) != 0 {
        td_info.rtmr3.fill(0);
    }
}

/// Backwards-compatible wrapper that builds the TDINFO_STRUCT and applies the
/// `servtd_attr` ignore-bit masks in one shot.
pub fn build_td_info(
    manifest: &[u8],
    image: File,
    is_ra_disabled: bool,
    is_policy_v2: bool,
    servtd_attr: u64,
    igvmformat: bool,
) -> Result<TdInfoStruct, Error> {
    let mut td_info =
        build_td_info_unmasked(manifest, image, is_ra_disabled, is_policy_v2, igvmformat)?;
    apply_servtd_attr_masks(&mut td_info, servtd_attr);
    Ok(td_info)
}

fn read_igvm_cfv_data(image: &mut File) -> Result<Vec<u8>> {
    let mut contents = Vec::new();
    image.read_to_end(&mut contents)?;
    let igvm = IgvmFile::new_from_binary(&contents, None)
        .map_err(|e| anyhow!("failed to parse IGVM image: {e:?}"))?;
    let cfv_base = u64::from(TD_SHIM_CONFIG_BASE);
    let cfv_end = cfv_base + CONFIG_VOLUME_SIZE as u64;
    let mut cfv = vec![0u8; CONFIG_VOLUME_SIZE];

    for directive in igvm.directives() {
        let IgvmDirectiveHeader::PageData { gpa, data, .. } = directive else {
            continue;
        };
        copy_igvm_cfv_page(&mut cfv, cfv_base, cfv_end, *gpa, data)?;
    }

    Ok(cfv)
}

fn copy_igvm_cfv_page(
    cfv: &mut [u8],
    cfv_base: u64,
    cfv_end: u64,
    gpa: u64,
    data: &[u8],
) -> Result<()> {
    if gpa < cfv_base || gpa >= cfv_end || data.is_empty() {
        return Ok(());
    }

    let start = usize::try_from(gpa - cfv_base)
        .map_err(|_| anyhow!("IGVM CFV page GPA {gpa:#x} does not fit usize"))?;
    let end = start
        .checked_add(data.len())
        .filter(|end| *end <= cfv.len())
        .ok_or_else(|| anyhow!("IGVM CFV page at GPA {gpa:#x} exceeds the CFV range"))?;
    cfv[start..end].copy_from_slice(data);
    Ok(())
}

pub fn calculate_servtd_info_hash(td_info: TdInfoStruct) -> Result<Vec<u8>, Error> {
    // Convert the TD info structure to bytes.
    let mut buffer = [0u8; size_of::<TdInfoStruct>()];
    td_info.pack(&mut buffer);

    // Calculate digest.
    digest_sha384(&buffer).map_err(|_| anyhow!("Calculate digest"))
}

/// Compute the canonical v2 `tdinfo_hash` for a production MigTD (attr=0).
///
/// Definition (per the TDX module specification):
///   `tdinfo_hash = SHA384(TDINFO_STRUCT_512_bytes)`
///
/// This equals `init_servtd_info_hash` in SERVTD_EXT_STRUCT when `servtd_attr
/// == 0` (the production profile), enabling direct MAA lookup through
/// `svnMappings[].tdMeasurements.tdinfo_hash`.
pub fn calculate_tdinfo_hash(td_info: TdInfoStruct) -> Result<Vec<u8>, Error> {
    calculate_servtd_info_hash(td_info)
}

fn canonical_tdinfo_hash(hash: &str) -> Result<String> {
    let bytes =
        hex::decode(hash.trim()).map_err(|_| anyhow!("tdinfo_hash is not valid hexadecimal"))?;
    if bytes.len() != SHA384_DIGEST_SIZE {
        return Err(anyhow!(
            "tdinfo_hash is {} bytes, expected {}",
            bytes.len(),
            SHA384_DIGEST_SIZE
        ));
    }
    Ok(hex::encode_upper(bytes))
}

/// `SERVTD_ATTR` bits MigTD supports: IGNORE_XFAM through IGNORE_RTMR3.
/// `IGNORE_ATTRIBUTES` (bit 32) must be 0 per the TDX Module ABI.
pub const SERVTD_ATTR_VALID_MASK: u64 = SERVTD_ATTR_IGNORE_XFAM
    | SERVTD_ATTR_IGNORE_MRTD
    | SERVTD_ATTR_IGNORE_MRCONFIGID
    | SERVTD_ATTR_IGNORE_MROWNER
    | SERVTD_ATTR_IGNORE_MROWNERCONFIG
    | SERVTD_ATTR_IGNORE_RTMR0
    | SERVTD_ATTR_IGNORE_RTMR1
    | SERVTD_ATTR_IGNORE_RTMR2
    | SERVTD_ATTR_IGNORE_RTMR3;

/// Parse a `SERVTD_ATTR` value: decimal or `0x` hexadecimal, ignoring
/// surrounding whitespace. Blank is 0.
pub fn parse_servtd_attr(value: &str) -> Result<u64> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(0);
    }
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse::<u64>(),
    };
    parsed.map_err(|_| anyhow!("invalid servtd_attr {value:?}"))
}

/// `SERVTD_ATTR` of this MigTD build, from `config/servtd_attr.json`.
pub fn config_servtd_attr() -> Result<u64> {
    servtd_attr_from_json(include_str!("../../../config/servtd_attr.json"))
}

/// Read the `servtd_attr` key of the config JSON: a decimal or `0x` hex string,
/// or a number.
pub fn servtd_attr_from_json(json: &str) -> Result<u64> {
    let document: Value =
        serde_json::from_str(json).map_err(|e| anyhow!("invalid servtd_attr JSON: {e}"))?;
    match document.get("servtd_attr") {
        Some(Value::String(text)) => parse_servtd_attr(text),
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| anyhow!("servtd_attr is not an unsigned integer")),
        _ => Err(anyhow!("'servtd_attr' missing or not a string or number")),
    }
}

/// Whether `servtd_attr` only uses bits MigTD supports.
pub fn is_valid_servtd_attr(servtd_attr: u64) -> bool {
    servtd_attr & !SERVTD_ATTR_VALID_MASK == 0
}

/// Add or replace an entry in a v2 TCB mapping whose hashes were computed with
/// `SERVTD_ATTR == 0`. See [`update_tcb_mapping_v2_with_attr`].
pub fn update_tcb_mapping_v2(
    input: &[u8],
    current_mapping: Option<(&[u8], u16)>,
) -> Result<Vec<u8>> {
    update_tcb_mapping_v2_with_attr(input, current_mapping.map(|(hash, svn)| (hash, svn, 0)))
}

/// Add or replace an entry in a v2 TCB mapping.
///
/// `current_mapping` is `(servtd_info_hash, isvsvn, servtd_attr)`: the hash is
/// the `SERVTD_INFO_HASH` computed with the `servtd_attr` mask. An entry is
/// identified by `(hash, servtd_attr)`; the JSON keys are `servtdInfoHash` and
/// `servtdAttr` (the earlier `tdinfo_hash` / `servtd_attr` are still read), and
/// `servtdAttr` is written only when it is not 0, so mappings without masks keep their existing form.
///
/// Existing mappings are retained by default. Duplicate entries with the same
/// SVN are collapsed, while conflicting duplicates are rejected. The result is
/// sorted by the canonical uppercase hash and attribute and serialized without
/// a trailing newline so repeated updates produce stable signing input.
pub fn update_tcb_mapping_v2_with_attr(
    input: &[u8],
    current_mapping: Option<(&[u8], u16, u64)>,
) -> Result<Vec<u8>> {
    let mut document: Value =
        serde_json::from_slice(input).map_err(|e| anyhow!("invalid TCB mapping JSON: {e}"))?;
    let svn_mappings = document
        .get_mut("svnMappings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("'svnMappings' missing or not an array"))?;

    let mut mappings = BTreeMap::<(String, u64), u16>::new();
    for (index, mapping) in svn_mappings.iter().enumerate() {
        let measurements = mapping.get("tdMeasurements");
        // Current key names, with the earlier snake_case names still accepted.
        let field = |current: &str, legacy: &str| -> Result<Option<&Value>> {
            let get = |key: &str| measurements.and_then(|measurements| measurements.get(key));
            match (get(current), get(legacy)) {
                (Some(_), Some(_)) => Err(anyhow!(
                    "svnMappings[{index}].tdMeasurements has both {current} and {legacy}"
                )),
                (value, None) | (None, value) => Ok(value),
            }
        };
        let hash = field("servtdInfoHash", "tdinfo_hash")?
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "svnMappings[{index}].tdMeasurements.servtdInfoHash missing or not a string"
                )
            })?;
        let hash = canonical_tdinfo_hash(hash)
            .map_err(|e| anyhow!("invalid svnMappings[{index}] tdinfo_hash: {e}"))?;
        let attr = match field("servtdAttr", "servtd_attr")? {
            None => 0,
            Some(value) => value.as_u64().ok_or_else(|| {
                anyhow!("svnMappings[{index}].tdMeasurements.servtdAttr is not an unsigned number")
            })?,
        };
        if !is_valid_servtd_attr(attr) {
            return Err(anyhow!(
                "svnMappings[{index}] servtd_attr {attr:#x} uses unsupported bits"
            ));
        }
        let svn = mapping
            .get("isvsvn")
            .and_then(Value::as_u64)
            .and_then(|svn| u16::try_from(svn).ok())
            .ok_or_else(|| anyhow!("svnMappings[{index}].isvsvn missing or outside u16 range"))?;

        if let Some(previous_svn) = mappings.insert((hash.clone(), attr), svn) {
            if previous_svn != svn {
                return Err(anyhow!(
                    "conflicting duplicate tdinfo_hash {hash} (servtd_attr {attr:#x}): SVN {previous_svn} and {svn}"
                ));
            }
        }
    }

    let current_mapping = current_mapping
        .map(|(hash, svn, attr)| {
            if hash.len() != SHA384_DIGEST_SIZE {
                return Err(anyhow!(
                    "current tdinfo_hash is {} bytes, expected {}",
                    hash.len(),
                    SHA384_DIGEST_SIZE
                ));
            }
            if !is_valid_servtd_attr(attr) {
                return Err(anyhow!("servtd_attr {attr:#x} uses unsupported bits"));
            }
            Ok((hex::encode_upper(hash), svn, attr))
        })
        .transpose()?;

    if let Some((hash, svn, attr)) = current_mapping {
        let key = (hash, attr);
        if let Some(previous_svn) = mappings.get(&key) {
            if *previous_svn != svn {
                return Err(anyhow!(
                    "conflicting duplicate tdinfo_hash {} (servtd_attr {attr:#x}): SVN {previous_svn} and {svn}",
                    key.0
                ));
            }
        } else {
            mappings.insert(key, svn);
        }
    }

    *svn_mappings = mappings
        .into_iter()
        .map(|((hash, attr), svn)| {
            let mut measurements = json!({ "servtdInfoHash": hash });
            if attr != 0 {
                measurements["servtdAttr"] = json!(attr);
            }
            json!({
                "tdMeasurements": measurements,
                "isvsvn": svn,
            })
        })
        .collect();

    serde_json::to_vec(&document).map_err(|e| anyhow!("failed to serialize TCB mapping: {e}"))
}

fn rtmr1(
    cfv: &[u8],
    rtmr1: &[u8; SHA384_DIGEST_SIZE],
    is_policy_v2: bool,
) -> Result<Vec<u8>, Error> {
    let mut rtmr1 = Rtmr::new_with_value(rtmr1);
    if is_policy_v2 {
        // Prefer the direct 48-byte anchor; use PEM only if that slot is absent.
        // Both enrollment forms use the same signer-anchor formula.
        // Measuring a supplied digest does not authenticate its signer.
        let anchor_source = fv::get_file_from_fv(
            cfv,
            pi::fv::FV_FILETYPE_RAW,
            MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID,
        )
        .or_else(|| {
            fv::get_file_from_fv(
                cfv,
                pi::fv::FV_FILETYPE_RAW,
                MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID,
            )
        })
        .ok_or(anyhow!(
            "Unable to get signer anchor / policy issuer chain from image"
        ))?;

        // Policy v2: extend with SHA384(signer anchor), binding root DER,
        // full Subject DN DER, and dedicated EKU.
        let anchor = policy::resolve_signer_anchor(anchor_source)
            .map_err(|e| anyhow!("Failed to resolve signer anchor: {:?}", e))?;
        rtmr1.extend_with_raw_data(&anchor)?;
    }

    Ok(rtmr1.as_bytes().to_vec())
}

fn rtmr2(cfv: &[u8], is_ra_disabled: bool, is_policy_v2: bool) -> Result<Vec<u8>, Error> {
    let mut rtmr2 = Rtmr::new();
    if !is_ra_disabled {
        let policy = fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_POLICY_FFS_GUID)
            .ok_or(anyhow!("Unable to get policy from image"))?;

        if is_policy_v2 {
            // v2 (single-extend RTMR2): one extend over the canonical bytes
            // of `policyData` with `servtdCollateral.servtdTcbMapping`
            // removed so the mapping remains updateable after publication.
            // The exact same helper is used by the runtime
            // (`get_policy_and_measure`) and the integrity verifier
            // (`check_policy_integrity`), so a mismatch here would also break
            // runtime attestation — there is no separate "offline format".
            //
            // The bytes are taken straight from the CFV's enrolled policy;
            // the release pipeline injects the production-signed policy via
            // `td-shim-enroll` before this function is called, so what we
            // measure here is what the shipped IGVM will produce at runtime.
            let policy_data_bytes = policy::extract_canonical_policy_data_bytes(policy)
                .map_err(|e| anyhow!("Failed to extract canonical policyData bytes: {e:?}"))?;
            rtmr2.extend_with_raw_data(&policy_data_bytes)?;
        } else {
            rtmr2.extend_with_raw_data(policy)?;
            let root_ca =
                fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_ROOT_CA_FFS_GUID)
                    .ok_or(anyhow!("Unable to get root CA from image"))?;
            rtmr2.extend_with_raw_data(root_ca)?;
        }
    } else {
        rtmr2.extend_with_raw_data(TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT)?;
    }
    Ok(rtmr2.as_bytes().to_vec())
}

struct Rtmr {
    reg: [u8; SHA384_DIGEST_SIZE * 2],
}

impl Rtmr {
    fn new() -> Self {
        Self {
            reg: [0u8; SHA384_DIGEST_SIZE * 2],
        }
    }

    fn new_with_value(value: &[u8; SHA384_DIGEST_SIZE]) -> Self {
        let mut reg = [0u8; SHA384_DIGEST_SIZE * 2];
        reg[..SHA384_DIGEST_SIZE].copy_from_slice(value);

        Self { reg }
    }

    fn extend_with_raw_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let digest = calculate_digest(data)?;

        self.reg[SHA384_DIGEST_SIZE..].copy_from_slice(&digest);
        let digest = calculate_digest(&self.reg)?;
        self.reg[..SHA384_DIGEST_SIZE].copy_from_slice(&digest);

        Ok(())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.reg[..SHA384_DIGEST_SIZE]
    }
}

pub fn calculate_servtd_hash(
    servtd_info_hash: &[u8],
    servtd_type: u16,
    servtd_attr: u64,
) -> Result<Vec<u8>, Error> {
    let mut buffer = [0u8; SHA384_DIGEST_SIZE + size_of::<u16>() + size_of::<u64>()];
    let mut packed_size = 0usize;

    if servtd_info_hash.len() != SHA384_DIGEST_SIZE {
        return Err(anyhow!("servtd_info_hash length mismatch"));
    }

    buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(servtd_info_hash);
    packed_size += SHA384_DIGEST_SIZE;
    buffer[packed_size..packed_size + size_of::<u16>()].copy_from_slice(&servtd_type.to_le_bytes());
    packed_size += size_of::<u16>();
    buffer[packed_size..packed_size + size_of::<u64>()].copy_from_slice(&servtd_attr.to_le_bytes());

    digest_sha384(&buffer).map_err(|_| anyhow!("Calculate digest"))
}

fn calculate_digest(data: &[u8]) -> Result<Vec<u8>, Error> {
    let digest = digest_sha384(data).map_err(|_| anyhow!("Calculate digest"))?;
    if digest.len() != SHA384_DIGEST_SIZE {
        return Err(anyhow!("Calculate digest"));
    }

    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::{
        config_servtd_attr, copy_igvm_cfv_page, is_valid_servtd_attr, parse_servtd_attr,
        servtd_attr_from_json, update_tcb_mapping_v2, update_tcb_mapping_v2_with_attr,
        SERVTD_ATTR_IGNORE_MROWNER,
    };
    use serde_json::Value;

    #[test]
    fn igvm_cfv_pages_preserve_gpa_gaps() {
        let mut cfv = [0u8; 16];
        copy_igvm_cfv_page(&mut cfv, 0x1000, 0x1010, 0x1008, &[1, 2, 3, 4]).unwrap();

        assert_eq!(&cfv[..8], &[0u8; 8]);
        assert_eq!(&cfv[8..12], &[1, 2, 3, 4]);
        assert_eq!(&cfv[12..], &[0u8; 4]);
    }

    #[test]
    fn igvm_cfv_pages_reject_range_overflow() {
        let mut cfv = [0u8; 16];
        assert!(copy_igvm_cfv_page(&mut cfv, 0x1000, 0x1010, 0x100f, &[1, 2]).is_err());
        assert!(copy_igvm_cfv_page(&mut cfv, 0x1000, 0x1010, 0x2000, &[1, 2]).is_ok());
        assert_eq!(cfv, [0u8; 16]);
    }

    const HASH_11: &str =
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    const HASH_AA: &str =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn tcb_mapping_add_retains_historical_releases() {
        let input = format!(
            r#"{{"id":"mapping","svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}"}},"isvsvn":1}}]}}"#
        );
        let current = [0x11u8; 48];

        let output = update_tcb_mapping_v2(input.as_bytes(), Some((&current, 2))).unwrap();
        let value: Value = serde_json::from_slice(&output).unwrap();
        let mappings = value["svnMappings"].as_array().unwrap();

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0]["tdMeasurements"]["servtdInfoHash"], HASH_11);
        assert_eq!(mappings[0]["isvsvn"], 2);
        assert_eq!(mappings[1]["tdMeasurements"]["servtdInfoHash"], HASH_AA);
        assert_eq!(mappings[1]["isvsvn"], 1);
    }

    #[test]
    fn tcb_mapping_retains_multiple_hashes_for_same_svn() {
        let input = format!(
            r#"{{"id":"mapping","svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}"}},"isvsvn":1}}]}}"#
        );
        let current = [0x11u8; 48];

        let output = update_tcb_mapping_v2(input.as_bytes(), Some((&current, 1))).unwrap();
        let value: Value = serde_json::from_slice(&output).unwrap();
        let mappings = value["svnMappings"].as_array().unwrap();

        assert_eq!(mappings.len(), 2);
        assert!(mappings.iter().all(|mapping| mapping["isvsvn"] == 1));
        assert!(mappings
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["servtdInfoHash"] == HASH_11));
        assert!(mappings
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["servtdInfoHash"] == HASH_AA));
    }

    #[test]
    fn tcb_mapping_two_phase_uses_authority_history_not_mock_output() {
        let historical_hash = "22".repeat(48);
        let authority = format!(
            r#"{{"svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{historical_hash}"}},"isvsvn":1}}]}}"#
        );
        let mock_hash = [0x33u8; 48];
        let real_hash = [0x44u8; 48];

        let phase_one = update_tcb_mapping_v2(authority.as_bytes(), Some((&mock_hash, 2))).unwrap();
        let phase_one: Value = serde_json::from_slice(&phase_one).unwrap();
        assert!(phase_one["svnMappings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["servtdInfoHash"] == "33".repeat(48)));

        // The measured-image phase must restart from the authority input, not
        // from phase one's generated output containing the transient mock hash.
        let final_mapping =
            update_tcb_mapping_v2(authority.as_bytes(), Some((&real_hash, 2))).unwrap();
        let final_mapping: Value = serde_json::from_slice(&final_mapping).unwrap();
        let mappings = final_mapping["svnMappings"].as_array().unwrap();

        assert_eq!(mappings.len(), 2);
        assert!(mappings
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["servtdInfoHash"] == historical_hash));
        assert!(mappings
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["servtdInfoHash"] == "44".repeat(48)));
        assert!(!mappings
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["servtdInfoHash"] == "33".repeat(48)));
    }

    #[test]
    fn tcb_mapping_replace_same_hash_is_deterministic() {
        let input = format!(
            r#"{{"svnMappings":[{{"isvsvn":1,"tdMeasurements":{{"tdinfo_hash":"{}"}}}}]}}"#,
            HASH_AA.to_ascii_lowercase()
        );
        let current = [0xAAu8; 48];

        let first = update_tcb_mapping_v2(input.as_bytes(), Some((&current, 1))).unwrap();
        let second = update_tcb_mapping_v2(&first, Some((&current, 1))).unwrap();
        let value: Value = serde_json::from_slice(&first).unwrap();

        assert_eq!(first, second);
        assert_eq!(value["svnMappings"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["svnMappings"][0]["tdMeasurements"]["servtdInfoHash"],
            HASH_AA
        );
        assert_eq!(value["svnMappings"][0]["isvsvn"], 1);
    }

    #[test]
    fn tcb_mapping_rejects_conflicting_current_hash() {
        let input = format!(
            r#"{{"svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}"}},"isvsvn":1}}]}}"#
        );
        let current = [0xAAu8; 48];

        let error = update_tcb_mapping_v2(input.as_bytes(), Some((&current, 2))).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicting duplicate tdinfo_hash"));
    }

    #[test]
    fn tcb_mapping_rejects_conflicting_duplicate_hashes() {
        let input = format!(
            r#"{{"svnMappings":[
                {{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}"}},"isvsvn":1}},
                {{"tdMeasurements":{{"tdinfo_hash":"{}"}},"isvsvn":2}}
            ]}}"#,
            HASH_AA.to_ascii_lowercase()
        );

        let error = update_tcb_mapping_v2(input.as_bytes(), None).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicting duplicate tdinfo_hash"));
    }

    #[test]
    fn v2_mapping_update_records_servtd_attr() {
        let input = format!(
            r#"{{"id":"mapping","svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}"}},"isvsvn":1}}]}}"#
        );
        let masked = vec![0x55; 48];
        let output = update_tcb_mapping_v2_with_attr(
            input.as_bytes(),
            Some((&masked, 2, SERVTD_ATTR_IGNORE_MROWNER)),
        )
        .unwrap();
        let document: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let mappings = document["svnMappings"].as_array().unwrap();
        assert_eq!(mappings.len(), 2);
        let masked_entry = mappings
            .iter()
            .find(|mapping| mapping["tdMeasurements"]["servtdInfoHash"] == "55".repeat(48))
            .unwrap();
        assert_eq!(
            masked_entry["tdMeasurements"]["servtdAttr"],
            SERVTD_ATTR_IGNORE_MROWNER
        );
        // Entries without a mask do not gain a `servtd_attr` field.
        let plain = mappings
            .iter()
            .find(|mapping| mapping["tdMeasurements"]["servtdInfoHash"] == HASH_AA)
            .unwrap();
        assert!(plain["tdMeasurements"].get("servtdAttr").is_none());
    }

    #[test]
    fn v2_mapping_update_keys_entries_by_hash_and_attr() {
        let hash = vec![0x55; 48];
        let first =
            update_tcb_mapping_v2_with_attr(br#"{"svnMappings":[]}"#, Some((&hash, 1, 0))).unwrap();
        // Same hash under another mask is a distinct entry with its own SVN.
        let second =
            update_tcb_mapping_v2_with_attr(&first, Some((&hash, 2, SERVTD_ATTR_IGNORE_MROWNER)))
                .unwrap();
        let document: serde_json::Value = serde_json::from_slice(&second).unwrap();
        assert_eq!(document["svnMappings"].as_array().unwrap().len(), 2);
        // Same hash and mask with another SVN conflicts.
        assert!(update_tcb_mapping_v2_with_attr(
            &second,
            Some((&hash, 3, SERVTD_ATTR_IGNORE_MROWNER))
        )
        .is_err());
        // Re-adding the same entry is stable.
        assert_eq!(
            update_tcb_mapping_v2_with_attr(&second, Some((&hash, 2, SERVTD_ATTR_IGNORE_MROWNER)))
                .unwrap(),
            second
        );
    }

    #[test]
    fn servtd_attr_text_parses_decimal_and_hex() {
        assert_eq!(parse_servtd_attr("").unwrap(), 0);
        assert_eq!(parse_servtd_attr("0x0\n").unwrap(), 0);
        assert_eq!(parse_servtd_attr(" 137438953472 ").unwrap(), 1 << 37);
        assert_eq!(parse_servtd_attr("0x2000000000").unwrap(), 1 << 37);
        assert!(parse_servtd_attr("0xZZ").is_err());
        assert!(parse_servtd_attr("-1").is_err());
        assert!(is_valid_servtd_attr(config_servtd_attr().unwrap()));
    }

    #[test]
    fn servtd_attr_json_accepts_string_and_number() {
        assert_eq!(
            servtd_attr_from_json(r#"{"servtd_attr":"0x0"}"#).unwrap(),
            0
        );
        assert_eq!(
            servtd_attr_from_json(r#"{"servtd_attr":"0x2000000000"}"#).unwrap(),
            1 << 37
        );
        assert_eq!(
            servtd_attr_from_json(r#"{"servtd_attr":137438953472}"#).unwrap(),
            1 << 37
        );
        assert!(servtd_attr_from_json(r#"{}"#).is_err());
        assert!(servtd_attr_from_json(r#"{"servtd_attr":-1}"#).is_err());
        assert!(servtd_attr_from_json(r#"{"servtd_attr":"zz"}"#).is_err());
        assert!(servtd_attr_from_json("not json").is_err());
    }

    #[test]
    fn v2_mapping_accepts_current_and_legacy_key_names() {
        let current = format!(
            r#"{{"svnMappings":[{{"tdMeasurements":{{"servtdInfoHash":"{HASH_AA}","servtdAttr":{SERVTD_ATTR_IGNORE_MROWNER}}},"isvsvn":1}}]}}"#
        );
        let legacy = format!(
            r#"{{"svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}","servtd_attr":{SERVTD_ATTR_IGNORE_MROWNER}}},"isvsvn":1}}]}}"#
        );
        let from_current = update_tcb_mapping_v2_with_attr(current.as_bytes(), None).unwrap();
        let from_legacy = update_tcb_mapping_v2_with_attr(legacy.as_bytes(), None).unwrap();
        // Both read the same entry and write the current names.
        assert_eq!(from_current, from_legacy);
        let document: Value = serde_json::from_slice(&from_current).unwrap();
        let measurements = &document["svnMappings"][0]["tdMeasurements"];
        assert_eq!(measurements["servtdInfoHash"], HASH_AA);
        assert_eq!(measurements["servtdAttr"], SERVTD_ATTR_IGNORE_MROWNER);
        assert!(measurements.get("tdinfo_hash").is_none());
        assert!(measurements.get("servtd_attr").is_none());

        // The same field under both names is ambiguous.
        let both = format!(
            r#"{{"svnMappings":[{{"tdMeasurements":{{"servtdInfoHash":"{HASH_AA}","tdinfo_hash":"{HASH_AA}"}},"isvsvn":1}}]}}"#
        );
        assert!(update_tcb_mapping_v2_with_attr(both.as_bytes(), None).is_err());
    }

    #[test]
    fn v2_mapping_update_rejects_unsupported_attr_bits() {
        let hash = vec![0x55; 48];
        assert!(!is_valid_servtd_attr(1 << 32));
        assert!(is_valid_servtd_attr(SERVTD_ATTR_IGNORE_MROWNER));
        assert!(update_tcb_mapping_v2_with_attr(
            br#"{"svnMappings":[]}"#,
            Some((&hash, 1, 1 << 32))
        )
        .is_err());
        let input = format!(
            r#"{{"svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}","servtd_attr":{}}},"isvsvn":1}}]}}"#,
            1u64 << 48
        );
        assert!(update_tcb_mapping_v2_with_attr(input.as_bytes(), None).is_err());
    }
}
