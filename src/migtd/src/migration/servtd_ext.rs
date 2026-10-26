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
const TDCS_FIELD_WRITE_MASK: u64 = u64::MAX;

/// Hardcoded expected SERVTD_ATTR value.
///
/// Per MigTD Design Guide: "SERVTD_ATTR is written by untrusted VMM. In order
/// to ensure VMM writes a right value, the MigTD MUST verify
/// TDG.SERVTD.RD(CURR_SERVTD_ATTR) matching a hardcoded value in the MigTD
/// reflecting the intended SERVTD_ATTR."
///
/// The value is a property of this MigTD build, read at build time from the
/// `servtd_attr` key of `config/servtd_attr.json` (a decimal or `0x` hex string,
/// or a number; 0 means no mask). Bits 41:33 select the TDINFO fields that
/// `SERVTD_INFO_HASH` ignores. The mapping entry of the release records the same
/// value so that peers can resolve this MigTD.
pub const EXPECTED_SERVTD_ATTR: u64 =
    servtd_attr_from_json(include_str!("../../../../config/servtd_attr.json"));

#[cfg(feature = "policy_v2")]
const _: () = assert!(
    policy::is_valid_servtd_attr(EXPECTED_SERVTD_ATTR),
    "config/servtd_attr.json uses unsupported SERVTD_ATTR bits"
);

/// Extract the value of the `servtd_attr` key from the config JSON. This is a
/// minimal scanner for the build-time constant; a missing key or a malformed
/// value fails the build.
const fn servtd_attr_from_json(json: &str) -> u64 {
    let bytes = json.as_bytes();
    let key = b"\"servtd_attr\"";
    let mut index = 0;
    let mut found = false;
    while index + key.len() <= bytes.len() {
        let mut matched = 0;
        while matched < key.len() && bytes[index + matched] == key[matched] {
            matched += 1;
        }
        if matched == key.len() {
            found = true;
            break;
        }
        index += 1;
    }
    assert!(found, "config/servtd_attr.json has no \"servtd_attr\" key");
    index += key.len();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    assert!(
        index < bytes.len() && bytes[index] == b':',
        "config/servtd_attr.json: expected ':' after \"servtd_attr\""
    );
    index += 1;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if index < bytes.len() && bytes[index] == b'"' {
        index += 1;
    }
    let start = index;
    while index < bytes.len()
        && !matches!(bytes[index], b'"' | b',' | b'}')
        && !bytes[index].is_ascii_whitespace()
    {
        index += 1;
    }
    parse_number(bytes, start, index)
}

/// Parse `bytes[start..end]` as decimal or `0x` hexadecimal. Empty, malformed or
/// oversized input fails the build.
const fn parse_number(bytes: &[u8], start: usize, end: usize) -> u64 {
    assert!(
        start < end,
        "config/servtd_attr.json: empty servtd_attr value"
    );
    let hex = end - start > 2
        && bytes[start] == b'0'
        && (bytes[start + 1] == b'x' || bytes[start + 1] == b'X');
    let (radix, mut index) = if hex {
        (16u64, start + 2)
    } else {
        (10u64, start)
    };
    let mut result = 0u64;
    while index < end {
        let digit = match bytes[index] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'f' => (c - b'a') as u64 + 10,
            c @ b'A'..=b'F' => (c - b'A') as u64 + 10,
            _ => panic!("config/servtd_attr.json: servtd_attr is not a number"),
        };
        assert!(
            digit < radix,
            "config/servtd_attr.json: invalid digit in servtd_attr"
        );
        result = match result.checked_mul(radix) {
            Some(shifted) => shifted + digit,
            None => panic!("config/servtd_attr.json: servtd_attr does not fit in 64 bits"),
        };
        index += 1;
    }
    result
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServtdExt {
    pub init_servtd_info_hash: [u8; 48],
    pub init_attr: [u8; 8],
    reserved: [u8; 8],
    pub init_cpusvn: [u8; 16],
    pub init_tee_tcb_svn: [u8; 16],
    pub init_tee_model: [u8; 12],
    reserved1: [u8; 4],
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

    // Verify CURR_SERVTD_ATTR matches the hardcoded expected value.
    let actual_attr = u64::from_le_bytes(cur_servtd_attr);
    if actual_attr != EXPECTED_SERVTD_ATTR {
        log::error!(
            "SERVTD_ATTR mismatch vs hardcoded: expected {EXPECTED_SERVTD_ATTR:#x}, got {actual_attr:#x}"
        );
        return Err(MigrationResult::InvalidParameter);
    }

    Ok(ServtdExt {
        init_servtd_info_hash,
        init_attr,
        init_cpusvn,
        init_tee_tcb_svn,
        init_tee_model,
        reserved1: [0u8; 4],
        cur_servtd_info_hash,
        cur_servtd_attr,
        reserved: [0u8; 8],
        reserved2: [0u8; 104],
    })
}

/// Verify that CURR_SERVTD_ATTR of the target TD (VMM input) matches the
/// hardcoded expected value (MigTD internal).
///
/// Per GHCI 1.5: Both source and destination MigTDs must verify this before
/// any TDG.SERVTD.WR operations (mig_dec_key, mig_version).
pub fn verify_servtd_attr(
    binding_handle: u64,
    target_td_uuid: &[u64],
) -> Result<(), MigrationResult> {
    let result = tdcall_servtd_rd(binding_handle, TDCS_FIELD_SERVTD_ATTR, target_td_uuid)?;
    let actual_attr = result.content;
    if actual_attr != EXPECTED_SERVTD_ATTR {
        log::error!(
            "SERVTD_ATTR mismatch: VMM wrote {actual_attr:#x}, MigTD expects {EXPECTED_SERVTD_ATTR:#x}"
        );
        return Err(MigrationResult::InvalidParameter);
    }
    Ok(())
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
            TDCS_FIELD_WRITE_MASK,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::{servtd_attr_from_json, ServtdExt, EXPECTED_SERVTD_ATTR};

    #[test]
    fn test_structure_sizes() {
        assert_eq!(size_of::<ServtdExt>(), 272)
    }

    #[test]
    fn servtd_attr_json_parses_string_and_number_values() {
        assert_eq!(servtd_attr_from_json(r#"{"servtd_attr": "0"}"#), 0);
        assert_eq!(servtd_attr_from_json(r#"{"servtd_attr":"0x0"}"#), 0);
        assert_eq!(
            servtd_attr_from_json(r#"{ "servtd_attr" : "137438953472" }"#),
            1 << 37
        );
        assert_eq!(
            servtd_attr_from_json("{\n  \"servtd_attr\": \"0x2000000000\"\n}\n"),
            1 << 37
        );
        assert_eq!(
            servtd_attr_from_json(r#"{"servtd_attr":"0X3FE00000000"}"#),
            0x3FE_0000_0000
        );
        assert_eq!(
            servtd_attr_from_json(r#"{"servtd_attr": 137438953472}"#),
            1 << 37
        );
        // Other keys are ignored.
        assert_eq!(
            servtd_attr_from_json(r#"{"note":"x","servtd_attr":"0x2000000000","z":1}"#),
            1 << 37
        );
    }

    #[test]
    fn build_value_comes_from_the_config_file() {
        assert_eq!(
            EXPECTED_SERVTD_ATTR,
            servtd_attr_from_json(include_str!("../../../../config/servtd_attr.json"))
        );
    }
}
