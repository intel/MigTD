// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use r_efi::efi::Guid;
use td_layout::build_time::{TD_SHIM_CONFIG_BASE, TD_SHIM_CONFIG_SIZE};
use td_shim_interface::td_uefi_pi::{fv, pi};

pub const CONFIG_VOLUME_BASE: usize = TD_SHIM_CONFIG_BASE as usize;
pub const CONFIG_VOLUME_SIZE: usize = TD_SHIM_CONFIG_SIZE as usize;

pub const MIGTD_POLICY_FFS_GUID: Guid = Guid::from_fields(
    0x0BE92DC3,
    0x6221,
    0x4C98,
    0x87,
    0xC1,
    &[0x8E, 0xEF, 0xFD, 0x70, 0xDE, 0x5A],
);
pub const MIGTD_ROOT_CA_FFS_GUID: Guid = Guid::from_fields(
    0xCA437832,
    0x4C51,
    0x4322,
    0xB1,
    0x3D,
    &[0xA2, 0x1B, 0xD0, 0xC8, 0xFF, 0xF6],
);

// {3F2FB27A-9596-431C-A68D-D3EAB39F8AEB}
pub const MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID: Guid = Guid::from_fields(
    0x3F2FB27A,
    0x9596,
    0x431C,
    0xA6,
    0x8D,
    &[0xD3, 0xEA, 0xB3, 0x9F, 0x8A, 0xEB],
);

// {2B9D5A84-6F3C-4E71-8A2D-0C7E1F4B6A93}
//
// FFS GUID of the 48-byte RTMR1 signer anchor
// `A = SHA384(tag ‖ H(rootDER) ‖ leafEkuOidDER)` (hash of the root cert plus the
// leaf's dedicated signer-purpose EKU OID DER). This is the CoRIM-only
// enrollment form: instead of enrolling the full policy issuer chain PEM (whose
// only runtime role was to derive this anchor), the pipeline enrolls the
// precomputed anchor directly. Measured into RTMR1 exactly like the PEM-derived
// anchor, so the two forms are measurement-equivalent. When present it takes
// precedence over `MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID`.
pub const MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID: Guid = Guid::from_fields(
    0x2B9D5A84,
    0x6F3C,
    0x4E71,
    0x8A,
    0x2D,
    &[0x0C, 0x7E, 0x1F, 0x4B, 0x6A, 0x93],
);

// {7E5B9C11-2D4A-4F6E-9B3C-1A2B3C4D5E6F}
//
// FFS GUID of the signed ServTD TCB-mapping CoRIM (`COSE_Sign1`) enrolled in
// the CFV. This file is intentionally NOT measured: `do_measurements()` never
// reads this GUID, so enrolling it does not change MRTD/RTMR or the resulting
// `tdinfo_hash`. Trust comes from the CoRIM's COSE signature bound to the RTMR1
// policy signer anchor (see `ServtdCorim::decode_signed`).
#[cfg(feature = "servtd_corim")]
pub const MIGTD_SERVTD_CORIM_FFS_GUID: Guid = Guid::from_fields(
    0x7E5B9C11,
    0x2D4A,
    0x4F6E,
    0x9B,
    0x3C,
    &[0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F],
);

pub fn get_config_volume() -> &'static [u8] {
    unsafe { core::slice::from_raw_parts(CONFIG_VOLUME_BASE as *const u8, CONFIG_VOLUME_SIZE) }
}

pub fn get_policy() -> Option<&'static [u8]> {
    let cfv = get_config_volume();
    fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_POLICY_FFS_GUID)
}

pub fn get_root_ca() -> Option<&'static [u8]> {
    let cfv = get_config_volume();
    fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_ROOT_CA_FFS_GUID)
}

pub fn get_policy_issuer_chain() -> Option<&'static [u8]> {
    let cfv = get_config_volume();
    fv::get_file_from_fv(
        cfv,
        pi::fv::FV_FILETYPE_RAW,
        MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID,
    )
}

/// Read the 48-byte RTMR1 signer anchor from the CFV, if enrolled (the
/// CoRIM-only enrollment form). Returns `None` when only the legacy policy
/// issuer chain PEM is enrolled; callers then fall back to
/// [`get_policy_issuer_chain`] and derive the anchor from the PEM.
pub fn get_signer_anchor() -> Option<&'static [u8]> {
    let cfv = get_config_volume();
    fv::get_file_from_fv(
        cfv,
        pi::fv::FV_FILETYPE_RAW,
        MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID,
    )
}

/// Resolve the signer-anchor *source* bytes from the CFV: the 48-byte anchor
/// slot when present, otherwise the policy issuer chain PEM. Both forms are
/// accepted by `policy::resolve_signer_anchor`. Returns `None` only when
/// neither slot is enrolled.
pub fn get_signer_anchor_source() -> Option<&'static [u8]> {
    get_signer_anchor().or_else(get_policy_issuer_chain)
}

/// Read the signed ServTD TCB-mapping CoRIM (`COSE_Sign1`) from the CFV, if
/// enrolled. Returns `None` when no CoRIM was enrolled (the policy then falls
/// back to the JSON `servtdCollateral` mapping). This file is deliberately not
/// measured; see [`MIGTD_SERVTD_CORIM_FFS_GUID`].
#[cfg(feature = "servtd_corim")]
pub fn get_servtd_corim() -> Option<&'static [u8]> {
    let cfv = get_config_volume();
    fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_SERVTD_CORIM_FFS_GUID)
}
