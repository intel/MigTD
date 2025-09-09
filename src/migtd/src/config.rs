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

// {B3C1DCFE-6BEF-449F-A183-63A84EA1E0B4}
pub const MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID: Guid = Guid::from_fields(
    0xb3c1dcfe,
    0x6bef,
    0x449f,
    0xa1,
    0x83,
    &[0x63, 0xa8, 0x4e, 0xa1, 0xe0, 0xb4],
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
