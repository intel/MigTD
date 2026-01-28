// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use core::mem::MaybeUninit;
use crypto::{hash::digest_sha384, SHA384_DIGEST_SIZE};
use tdx_tdcall::tdx::{tdcall_servtd_rd, tdcall_vm_write};

use crate::migration::MigrationResult;

/// SERVTD_EXT_STRUCT fields in target TD’s TDCS
pub const TDCS_FIELD_SERVTD_INIT_SERVTD_INFO_HASH: u64 = 0x191000030000020E;
pub const TDCS_FIELD_SERVTD_INIT_ATTR: u64 = 0x191000030000020D;
pub const TDCS_FIELD_INIT_CPUSVN: u64 = 0x1110000300000060;
pub const TDCS_FIELD_INIT_TEE_TCB_SVN: u64 = 0x1110000300000062;
pub const TDCS_FIELD_INIT_TEE_MODEL: u64 = 0x1110000200000064;
/// SERVTD_EXT_STRUCT fields in Service TDs Binding Table Entry in target TD’s TDCS
pub const TDCS_FIELD_SERVTD_INFO_HASH: u64 = 0x1910000300000207;
pub const TDCS_FIELD_SERVTD_ATTR: u64 = 0x1910000300000202;

/// Hash of SERVTD_EXT that the new Service TD 0 (i.e., rebound Service TD or MigTD on the
/// destination platform) believes is the SERVTD_EXT for this TD.
pub const TDCS_FIELD_SERVTD_ACCEPT_SERVTD_EXT_HASH: u64 = 0x1910000300000214;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServtdExt {
    pub init_servtd_info_hash: [u8; 48],
    pub init_attr: [u8; 8],
    reserved: [u8; 8],
    pub init_cpusvn: [u8; 16],
    pub init_tee_tcb_svn: [u8; 16],
    pub init_tee_model: [u8; 12],
    pub cur_servtd_info_hash: [u8; 48],
    pub cur_servtd_attr: [u8; 8],
    reserved2: [u8; 104],
}

impl ServtdExt {
    pub fn read_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<ServtdExt>() {
            return None;
        }

        let mut uninit = MaybeUninit::<ServtdExt>::uninit();
        // SAFETY: `MaybeUninit<T>` has same memory layout with T.
        Some(unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                uninit.as_mut_ptr() as *mut u8,
                core::mem::size_of::<ServtdExt>(),
            );
            uninit.assume_init()
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }

    pub fn calculate_approved_servtd_ext_hash(mut self) -> Result<Vec<u8>, MigrationResult> {
        self.cur_servtd_attr.fill(0);
        self.cur_servtd_info_hash.fill(0);
        digest_sha384(self.as_bytes()).map_err(|_| MigrationResult::InvalidParameter)
    }
}

#[repr(C)]
pub struct TeeModel {
    custom: u16,
    platform_id: u16,
    fm: u32,
    reservtd: [u8; 8],
}

pub fn read_servtd_ext(
    binding_handle: u64,
    target_td_uuid: &[u64],
) -> Result<ServtdExt, MigrationResult> {
    let read_field =
        |field_base: u64, elem_size: usize, buf: &mut [u8]| -> Result<(), MigrationResult> {
            for (idx, chunk) in buf.chunks_mut(elem_size).enumerate() {
                let result =
                    tdcall_servtd_rd(binding_handle, field_base + idx as u64, target_td_uuid)?;
                let bytes = result.content.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }

            Ok(())
        };

    let mut init_servtd_info_hash = [0u8; 48];
    let mut init_attr = [0u8; 8];
    let mut init_cpusvn = [0u8; 16];
    let mut init_tee_tcb_svn = [0u8; 16];
    let mut init_tee_model = [0u8; 12];
    let mut cur_servtd_info_hash = [0u8; 48];
    let mut cur_servtd_attr = [0u8; 8];

    read_field(
        TDCS_FIELD_SERVTD_INIT_SERVTD_INFO_HASH,
        8,
        &mut init_servtd_info_hash,
    )?;
    read_field(TDCS_FIELD_SERVTD_INIT_ATTR, 8, &mut init_attr)?;
    read_field(TDCS_FIELD_INIT_CPUSVN, 8, &mut init_cpusvn)?;
    read_field(TDCS_FIELD_INIT_TEE_TCB_SVN, 8, &mut init_tee_tcb_svn)?;
    read_field(TDCS_FIELD_INIT_TEE_MODEL, 4, &mut init_tee_model)?;
    read_field(TDCS_FIELD_SERVTD_INFO_HASH, 8, &mut cur_servtd_info_hash)?;
    read_field(TDCS_FIELD_SERVTD_ATTR, 8, &mut cur_servtd_attr)?;

    Ok(ServtdExt {
        init_servtd_info_hash,
        init_attr,
        init_cpusvn,
        init_tee_tcb_svn,
        init_tee_model,
        cur_servtd_info_hash,
        cur_servtd_attr,
        reserved: [0u8; 8],
        reserved2: [0u8; 104],
    })
}

pub fn write_approved_servtd_ext_hash(servtd_ext_hash: &[u8]) -> Result<(), MigrationResult> {
    if servtd_ext_hash.len() != SHA384_DIGEST_SIZE {
        return Err(MigrationResult::InvalidParameter);
    }

    for (idx, chunk) in servtd_ext_hash.chunks_exact(size_of::<u64>()).enumerate() {
        let elem = u64::from_le_bytes(chunk.try_into().unwrap());
        tdcall_vm_write(
            TDCS_FIELD_SERVTD_ACCEPT_SERVTD_EXT_HASH + idx as u64,
            elem,
            0,
        )?;
    }

    Ok(())
}

mod test {
    use super::ServtdExt;

    #[test]
    fn test_structure_sizes() {
        assert_eq!(size_of::<ServtdExt>(), 268)
    }
}
