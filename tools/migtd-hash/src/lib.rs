// Copyright (c) 2023 - 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Error, Result};
use crypto::{hash::digest_sha384, SHA384_DIGEST_SIZE};
use migtd::{
    config::{
        CONFIG_VOLUME_SIZE, MIGTD_POLICY_FFS_GUID, MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID,
        MIGTD_ROOT_CA_FFS_GUID, MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID,
    },
    event_log::TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
    policy,
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
};
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
/// RTMR1/RTMR2 are derived from the CFV contents (policy issuer chain +
/// signed policyData fields). The build pipeline produces a base IGVM with
/// dummy CFV contents; the release pipeline injects the production policy +
/// chain into the same base IGVM via `td-shim-enroll` (no Rust rebuild) and
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
        cfv = td_info.read_igvmcfvdata(&mut image);
    } else {
        image.read(&mut cfv)?;
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

fn rtmr1(
    cfv: &[u8],
    rtmr1: &[u8; SHA384_DIGEST_SIZE],
    is_policy_v2: bool,
) -> Result<Vec<u8>, Error> {
    let mut rtmr1 = Rtmr::new_with_value(rtmr1);
    if is_policy_v2 {
        // Prefer the 48-byte signer-anchor slot (CoRIM-only enrollment); fall
        // back to the policy issuer chain PEM (legacy JSON enrollment). Both
        // resolve to the same RTMR1 anchor via `resolve_signer_anchor`.
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

        // v2: extend with SHA384(signer_anchor) where
        //   signer_anchor = SHA384("MIGTD-RTMR1-ANCHOR-V1" || 0x00 ||
        //                          SHA384(root_der) || 0x00 || leaf_eku_oid_der)
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
                .map_err(|e| anyhow!("Failed to extract canonical policyData bytes: {:?}", e))?;
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
