// Copyright (c) 2022 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Firmware Volume emulation
//! Provides file-based emulation for MigTD policy and endorsement files.

use crate::td_uefi_pi::pi::fv::FV_FILETYPE_RAW;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use r_efi::efi::Guid;

// Static buffers to store emulated files
const POLICY_BUFFER_SIZE: usize = 1024 * 1024; // 1MB for policy files (increased to handle large v2 policies)
static mut POLICY_BUFFER: [u8; POLICY_BUFFER_SIZE] = [0; POLICY_BUFFER_SIZE];
static mut POLICY_SIZE: usize = 0;
static POLICY_INITIALIZED: AtomicBool = AtomicBool::new(false);

static mut ROOT_CA_BUFFER: [u8; 4096] = [0; 4096]; // 4KB for root CA files
static mut ROOT_CA_SIZE: usize = 0;
static ROOT_CA_INITIALIZED: AtomicBool = AtomicBool::new(false);

static mut POLICY_ISSUER_CHAIN_BUFFER: [u8; 8192] = [0; 8192]; // 8KB for policy issuer chain files
static mut POLICY_ISSUER_CHAIN_SIZE: usize = 0;
static POLICY_ISSUER_CHAIN_INITIALIZED: AtomicBool = AtomicBool::new(false);

const SIGNER_ANCHOR_SIZE: usize = 48;
static mut SIGNER_ANCHOR_BUFFER: [u8; SIGNER_ANCHOR_SIZE] = [0; SIGNER_ANCHOR_SIZE];
static SIGNER_ANCHOR_INITIALIZED: AtomicBool = AtomicBool::new(false);

const SERVTD_CORIM_BUFFER_SIZE: usize = 1024 * 1024;
static mut SERVTD_CORIM_BUFFER: [u8; SERVTD_CORIM_BUFFER_SIZE] = [0; SERVTD_CORIM_BUFFER_SIZE];
static mut SERVTD_CORIM_SIZE: usize = 0;
static SERVTD_CORIM_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Known GUIDs for policy and root CA files in migtd
const MIGTD_POLICY_FFS_GUID: Guid = Guid::from_fields(
    0x0BE92DC3,
    0x6221,
    0x4C98,
    0x87,
    0xC1,
    &[0x8E, 0xEF, 0xFD, 0x70, 0xDE, 0x5A],
);

const MIGTD_ROOT_CA_FFS_GUID: Guid = Guid::from_fields(
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

pub const MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID: Guid = Guid::from_fields(
    0x2B9D5A84,
    0x6F3C,
    0x4E71,
    0x8A,
    0x2D,
    &[0x0C, 0x7E, 0x1F, 0x4B, 0x6A, 0x93],
);

pub const MIGTD_SERVTD_CORIM_FFS_GUID: Guid = Guid::from_fields(
    0x7E5B9C11,
    0x2D4A,
    0x4F6E,
    0x9B,
    0x3C,
    &[0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F],
);

#[cfg(any(feature = "policy_v2", test))]
pub(crate) fn reset_policy_endorsements() {
    POLICY_ISSUER_CHAIN_INITIALIZED.store(false, Ordering::SeqCst);
    SIGNER_ANCHOR_INITIALIZED.store(false, Ordering::SeqCst);
    SERVTD_CORIM_INITIALIZED.store(false, Ordering::SeqCst);
}

/// Set policy data for emulation
pub fn set_policy_data(data: &[u8]) -> bool {
    unsafe {
        let policy_buffer_ptr = ptr::addr_of_mut!(POLICY_BUFFER);
        if data.len() > (*policy_buffer_ptr).len() {
            return false;
        }

        let policy_size_ptr = ptr::addr_of_mut!(POLICY_SIZE);
        (*policy_buffer_ptr)[..data.len()].copy_from_slice(data);
        *policy_size_ptr = data.len();
    }
    POLICY_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

/// Set root CA data for emulation
pub fn set_root_ca_data(data: &[u8]) -> bool {
    unsafe {
        let root_ca_buffer_ptr = ptr::addr_of_mut!(ROOT_CA_BUFFER);
        if data.len() > (*root_ca_buffer_ptr).len() {
            return false;
        }

        let root_ca_size_ptr = ptr::addr_of_mut!(ROOT_CA_SIZE);
        (*root_ca_buffer_ptr)[..data.len()].copy_from_slice(data);
        *root_ca_size_ptr = data.len();
    }
    ROOT_CA_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

/// Set policy issuer chain data for emulation
pub fn set_policy_issuer_chain_data(data: &[u8]) -> bool {
    unsafe {
        let chain_buffer_ptr = ptr::addr_of_mut!(POLICY_ISSUER_CHAIN_BUFFER);
        if data.len() > (*chain_buffer_ptr).len() {
            return false;
        }

        let chain_size_ptr = ptr::addr_of_mut!(POLICY_ISSUER_CHAIN_SIZE);
        (*chain_buffer_ptr)[..data.len()].copy_from_slice(data);
        *chain_size_ptr = data.len();
    }
    POLICY_ISSUER_CHAIN_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

/// Set the raw signer anchor before firmware-volume access begins.
pub fn set_signer_anchor_data(data: &[u8]) -> bool {
    if data.len() != SIGNER_ANCHOR_SIZE {
        return false;
    }
    unsafe {
        (&mut *ptr::addr_of_mut!(SIGNER_ANCHOR_BUFFER)).copy_from_slice(data);
    }
    SIGNER_ANCHOR_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

/// Set the opaque signed CoRIM before firmware-volume access begins.
pub fn set_servtd_corim_data(data: &[u8]) -> bool {
    if data.is_empty() || data.len() > SERVTD_CORIM_BUFFER_SIZE {
        return false;
    }
    unsafe {
        let buffer = &mut *ptr::addr_of_mut!(SERVTD_CORIM_BUFFER);
        buffer[..data.len()].copy_from_slice(data);
        *ptr::addr_of_mut!(SERVTD_CORIM_SIZE) = data.len();
    }
    SERVTD_CORIM_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

// File reader function type
type FileReader = fn(&str) -> Option<Vec<u8>>;

// Static file reader - set by set_file_reader
static mut FILE_READER: Option<FileReader> = None;

/// Set the file reader function for loading files from filesystem
pub fn set_file_reader(reader: FileReader) {
    unsafe {
        let file_reader_ptr = ptr::addr_of_mut!(FILE_READER);
        *file_reader_ptr = Some(reader);
    }
}

fn load_file(path: &str, store: fn(&[u8]) -> bool) -> bool {
    unsafe {
        let file_reader_ptr = ptr::addr_of!(FILE_READER);
        if let Some(reader) = *file_reader_ptr {
            if let Some(data) = reader(path) {
                return store(&data);
            }
        }
    }
    false
}

/// Load policy data from file path (if file reader is set)
pub fn load_policy_from_file(path: &str) -> bool {
    load_file(path, set_policy_data)
}

/// Load root CA data from file path (if file reader is set)
pub fn load_root_ca_from_file(path: &str) -> bool {
    load_file(path, set_root_ca_data)
}

/// Load policy issuer chain data from file path (if file reader is set)
pub fn load_policy_issuer_chain_from_file(path: &str) -> bool {
    load_file(path, set_policy_issuer_chain_data)
}

/// Load a 48-byte raw signer anchor from a file.
pub fn load_signer_anchor_from_file(path: &str) -> bool {
    load_file(path, set_signer_anchor_data)
}

/// Load an opaque signed servTD CoRIM from a file.
pub fn load_servtd_corim_from_file(path: &str) -> bool {
    load_file(path, set_servtd_corim_data)
}

/// Get a file from the emulated firmware volume.
///
/// This implementation supports common files needed by migtd:
/// - Policy files (using MIGTD_POLICY_FFS_GUID)
/// - Root CA files (using MIGTD_ROOT_CA_FFS_GUID)
/// - Policy issuer chain files (using MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID)
/// - Signer anchors (using MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID)
/// - Signed CoRIM files (using MIGTD_SERVTD_CORIM_FFS_GUID)
///
/// Other files will return None
pub fn get_file_from_fv(
    _fv_data: &[u8],
    fv_file_type: u8,
    file_name: Guid,
) -> Option<&'static [u8]> {
    // Only support RAW file type
    if fv_file_type != FV_FILETYPE_RAW {
        return None;
    }

    if file_name == MIGTD_POLICY_FFS_GUID && POLICY_INITIALIZED.load(Ordering::SeqCst) {
        unsafe {
            let policy_buffer_ptr = ptr::addr_of!(POLICY_BUFFER);
            let policy_size_ptr = ptr::addr_of!(POLICY_SIZE);
            Some(&(*policy_buffer_ptr)[..*policy_size_ptr])
        }
    } else if file_name == MIGTD_ROOT_CA_FFS_GUID && ROOT_CA_INITIALIZED.load(Ordering::SeqCst) {
        unsafe {
            let root_ca_buffer_ptr = ptr::addr_of!(ROOT_CA_BUFFER);
            let root_ca_size_ptr = ptr::addr_of!(ROOT_CA_SIZE);
            Some(&(*root_ca_buffer_ptr)[..*root_ca_size_ptr])
        }
    } else if file_name == MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID
        && POLICY_ISSUER_CHAIN_INITIALIZED.load(Ordering::SeqCst)
    {
        unsafe {
            let chain_buffer_ptr = ptr::addr_of!(POLICY_ISSUER_CHAIN_BUFFER);
            let chain_size_ptr = ptr::addr_of!(POLICY_ISSUER_CHAIN_SIZE);
            Some(&(*chain_buffer_ptr)[..*chain_size_ptr])
        }
    } else if file_name == MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID
        && SIGNER_ANCHOR_INITIALIZED.load(Ordering::SeqCst)
    {
        unsafe { Some(&*ptr::addr_of!(SIGNER_ANCHOR_BUFFER)) }
    } else if file_name == MIGTD_SERVTD_CORIM_FFS_GUID
        && SERVTD_CORIM_INITIALIZED.load(Ordering::SeqCst)
    {
        unsafe {
            let buffer = &*ptr::addr_of!(SERVTD_CORIM_BUFFER);
            Some(&buffer[..*ptr::addr_of!(SERVTD_CORIM_SIZE)])
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_reader(path: &str) -> Option<Vec<u8>> {
        match path {
            "anchor" => Some(vec![0x5a; SIGNER_ANCHOR_SIZE]),
            "short-anchor" => Some(vec![0; SIGNER_ANCHOR_SIZE - 1]),
            "hex-anchor" => Some(vec![b'A'; SIGNER_ANCHOR_SIZE * 2]),
            "corim" => Some(b"signed CoRIM bytes".to_vec()),
            "empty-corim" => Some(Vec::new()),
            "largest-corim" => Some(vec![0; SERVTD_CORIM_BUFFER_SIZE]),
            "oversized-corim" => Some(vec![0; SERVTD_CORIM_BUFFER_SIZE + 1]),
            "policy" | "root-ca" | "chain" => Some(path.as_bytes().to_vec()),
            _ => None,
        }
    }

    #[test]
    fn servtd_files_are_loaded_by_guid_without_changing_legacy_files() {
        set_file_reader(file_reader);
        assert!(
            get_file_from_fv(&[], FV_FILETYPE_RAW, MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID).is_none()
        );
        assert!(get_file_from_fv(&[], FV_FILETYPE_RAW, MIGTD_SERVTD_CORIM_FFS_GUID).is_none());
        assert!(!load_signer_anchor_from_file("missing"));
        assert!(!load_signer_anchor_from_file("short-anchor"));
        assert!(!load_signer_anchor_from_file("hex-anchor"));
        assert!(!load_servtd_corim_from_file("missing"));
        assert!(!load_servtd_corim_from_file("empty-corim"));
        assert!(!load_servtd_corim_from_file("oversized-corim"));
        assert!(load_servtd_corim_from_file("largest-corim"));
        assert_eq!(
            get_file_from_fv(&[], FV_FILETYPE_RAW, MIGTD_SERVTD_CORIM_FFS_GUID)
                .unwrap()
                .len(),
            SERVTD_CORIM_BUFFER_SIZE
        );

        assert!(load_policy_from_file("policy"));
        assert!(load_root_ca_from_file("root-ca"));
        assert!(load_policy_issuer_chain_from_file("chain"));
        assert!(load_signer_anchor_from_file("anchor"));
        assert!(load_servtd_corim_from_file("corim"));
        for (guid, expected) in [
            (MIGTD_POLICY_FFS_GUID, b"policy".as_slice()),
            (MIGTD_ROOT_CA_FFS_GUID, b"root-ca".as_slice()),
            (MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID, b"chain".as_slice()),
            (
                MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID,
                &[0x5a; SIGNER_ANCHOR_SIZE],
            ),
            (
                MIGTD_SERVTD_CORIM_FFS_GUID,
                b"signed CoRIM bytes".as_slice(),
            ),
        ] {
            assert_eq!(get_file_from_fv(&[], FV_FILETYPE_RAW, guid), Some(expected));
            assert!(get_file_from_fv(&[], FV_FILETYPE_RAW + 1, guid).is_none());
        }

        reset_policy_endorsements();
        for guid in [
            MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID,
            MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID,
            MIGTD_SERVTD_CORIM_FFS_GUID,
        ] {
            assert!(get_file_from_fv(&[], FV_FILETYPE_RAW, guid).is_none());
        }
        assert_eq!(
            get_file_from_fv(&[], FV_FILETYPE_RAW, MIGTD_POLICY_FFS_GUID),
            Some(b"policy".as_slice())
        );
        assert_eq!(
            get_file_from_fv(&[], FV_FILETYPE_RAW, MIGTD_ROOT_CA_FFS_GUID),
            Some(b"root-ca".as_slice())
        );
    }
}
