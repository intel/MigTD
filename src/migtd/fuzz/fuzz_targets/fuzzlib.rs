// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use migtd::migration::data::{ServiceQueryResponse, VmcallServiceResponse, read_mig_info};
use r_efi::efi::Guid;

type Result<T> = core::result::Result<T, MigrationError>;

#[derive(Debug)]
pub enum MigrationError {
    ParseResponse,
    InvalidResponse,
    NoCertificatesPresented,
}

const VMCALL_SERVICE_COMMON_GUID: Guid = Guid::from_fields(
    0xfb6fc5e1,
    0x3378,
    0x4acb,
    0x89,
    0x64,
    &[0xfa, 0x5e, 0xe4, 0x3b, 0x9c, 0x8a],
);

pub fn fuzz_service_response(data: &[u8]) -> Result<()> {
    let rsp = VmcallServiceResponse::try_read(data).ok_or(MigrationError::InvalidResponse)?;

    if rsp.read_guid() != VMCALL_SERVICE_COMMON_GUID.as_bytes() {
        return Err(MigrationError::InvalidResponse);
    }

    let _ = rsp
        .read_data::<ServiceQueryResponse>(0)
        .ok_or(MigrationError::ParseResponse)?;

    Ok(())
}

pub fn fuzz_read_mig_info(data: &[u8]) -> Result<()> {
    let _ = read_mig_info(data).ok_or(MigrationError::ParseResponse)?;
    Ok(())
}