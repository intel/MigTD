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
// {B1A29D14-2D12-4307-9C10-A47960838A85}
pub const MIGTD_ENGINE_FFS_GUID: Guid = Guid::from_fields(
    0xb1a29d14,
    0x2d12,
    0x4307,
    0x9c,
    0x10,
    &[0xa4, 0x79, 0x60, 0x83, 0x8a, 0x85],
);
// {EDFD2B6D-7FA9-455B-9EA1-4CA0B9EC01A8}
pub const MIGTD_ENGINE_PUBKEY_FFS_GUID: Guid = Guid::from_fields(
    0xedfd2b6d,
    0x7fa9,
    0x455b,
    0x9e,
    0xa1,
    &[0x4c, 0xa0, 0xb9, 0xec, 0x1, 0xa8],
);
// {B3C1DCFE-6BEF-449F-A183-63A84EA1E0B4}
pub const MIGTD_POLICY_PUBKEY_FFS_GUID: Guid = Guid::from_fields(
    0xb3c1dcfe,
    0x6bef,
    0x449f,
    0xa1,
    0x83,
    &[0x63, 0xa8, 0x4e, 0xa1, 0xe0, 0xb4],
);
// {A55107C8-5599-48F3-A2AD-8D2ECA13CD03}
pub const MIGTD_COLLATERALS_FFS_GUID: Guid = Guid::from_fields(
    0xa55107c8,
    0x5599,
    0x48f3,
    0xa2,
    0xad,
    &[0x8d, 0x2e, 0xca, 0x13, 0xcd, 0x3],
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

pub fn get_engine() -> Option<&'static [u8]> {
    let cfv = get_config_volume();
    fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_ENGINE_FFS_GUID)
}

pub fn get_engine_public_key() -> Option<&'static [u8]> {
    let cfv = get_config_volume();
    fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_ENGINE_PUBKEY_FFS_GUID)
}

pub fn get_policy_public_key() -> Option<&'static [u8]> {
    let cfv = get_config_volume();
    fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_POLICY_PUBKEY_FFS_GUID)
}

pub fn get_collaterals() -> Option<&'static [u8]> {
    let cfv = get_config_volume();
    fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_COLLATERALS_FFS_GUID)
}
