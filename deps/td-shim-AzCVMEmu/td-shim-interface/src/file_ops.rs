// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! File operations for AzCVMEmu emulation
//!
//! This module provides file reading functionality that can interface
//! with the host system's file system in emulated environments.

extern crate alloc;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::fs;
#[cfg(feature = "std")]
use std::path::Path;

/// File reader function type
pub type FileReader = fn(&str) -> Option<Vec<u8>>;

/// Simple file reader implementation for basic file I/O
///
/// This function attempts to read a file from the filesystem.
/// It's designed to work in environments where basic file I/O is available.
pub fn simple_file_reader(path: &str) -> Option<Vec<u8>> {
    // In a real implementation, this would use the host's file system
    // For demonstration, we'll simulate file reading with some basic logic

    // Try to read the file using a simple approach
    // This is a placeholder that would be replaced with actual file I/O
    match path {
        "/tmp/migtd_policy.bin" => {
            // Simulate reading a policy file
            Some(b"AzCVMEmu file-based policy data".to_vec())
        }
        "/tmp/migtd_root_ca.bin" => {
            // Simulate reading a root CA file
            Some(b"AzCVMEmu file-based root CA data".to_vec())
        }
        _ => {
            // File not found or unsupported path
            None
        }
    }
}

/// Read file contents using pattern matching
///
/// This is a demonstration of how file reading might work in a minimal environment.
/// In a real implementation, this would use proper file system APIs.
pub fn pattern_file_reader(path: &str) -> Option<Vec<u8>> {
    // This is a placeholder implementation
    // In a real environment, this would interface with the host OS file system

    // For now, return simulated data based on the file path
    match path {
        path if path.contains("policy") => {
            Some(b"Simulated policy file content from AzCVMEmu".to_vec())
        }
        path if path.contains("root_ca") => {
            Some(b"Simulated root CA file content from AzCVMEmu".to_vec())
        }
        _ => {
            // File not found or unsupported path
            None
        }
    }
}

/// Default file reader that provides reasonable test data
///
/// This reader provides default test data for policy and root CA files
/// when the actual files are not available or in testing scenarios.
pub fn default_file_reader(path: &str) -> Option<Vec<u8>> {
    match path {
        path if path.contains("policy") => {
            Some(b"Default AzCVMEmu policy data for testing".to_vec())
        }
        path if path.contains("root_ca") => {
            Some(b"Default AzCVMEmu root CA data for testing".to_vec())
        }
        _ => None,
    }
}

/// Real file reader implementation using standard library
///
/// This function reads actual files from the host filesystem when std is available.
/// It's designed for use in AzCVMEmu environments where standard runtime is available.
#[cfg(feature = "std")]
pub fn real_file_reader(path: &str) -> Option<Vec<u8>> {
    // Verify the path exists and is a regular file
    let file_path = Path::new(path);
    if !file_path.exists() || !file_path.is_file() {
        return None;
    }

    // Try to read the file
    match fs::read(path) {
        Ok(data) => {
            // Validate that we actually got some data
            if data.is_empty() {
                None
            } else {
                Some(data)
            }
        }
        Err(_) => None,
    }
}

/// Real file reader implementation (no-std fallback)
///
/// When std is not available, this falls back to pattern-based simulation.
#[cfg(not(feature = "std"))]
pub fn real_file_reader(path: &str) -> Option<Vec<u8>> {
    // In no-std environments, fall back to pattern-based reading
    pattern_file_reader(path)
}

/// Initialize file-based emulation with real file reader
///
/// This function sets up the emulation with a real file reader that can
/// access the host filesystem when std feature is enabled.
pub fn init_with_real_file_reader() {
    crate::td_uefi_pi::fv::set_file_reader(real_file_reader);
}

/// Initialize file-based emulation with real files at specified paths
///
/// This function loads the policy and root CA files immediately from the filesystem
/// and stores them in the emulation buffers.
pub fn init_file_based_emulation_with_real_files(policy_path: &str, root_ca_path: &str) -> bool {
    // Set the file reader first
    crate::td_uefi_pi::fv::set_file_reader(real_file_reader);

    // Load the files immediately
    let policy_loaded = crate::td_uefi_pi::fv::load_policy_from_file(policy_path);
    let root_ca_loaded = crate::td_uefi_pi::fv::load_root_ca_from_file(root_ca_path);

    policy_loaded && root_ca_loaded
}

/// Initialize file-based emulation with immediate file loading including policy issuer chain
///
/// This function loads the policy, root CA, and policy issuer chain files immediately
/// from the filesystem and stores them in the emulation buffers. It calls the base
/// implementation and adds policy issuer chain loading.
#[cfg(feature = "policy_v2")]
pub fn init_file_based_emulation_with_policy_chain(
    policy_path: &str,
    root_ca_path: &str,
    policy_issuer_chain_path: &str,
) -> bool {
    init_file_based_emulation_with_real_files(policy_path, root_ca_path)
        && crate::td_uefi_pi::fv::load_policy_issuer_chain_from_file(policy_issuer_chain_path)
}
