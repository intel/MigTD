// Copyright (c) 2022 Alibaba Cloud
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TD-shim interface emulation for Azure CVM environment
//!
//! This crate provides minimal emulation of td-shim-interface functionality
//! to support the policy crate in Azure CVM environments where the real
//! td-shim is not available.
//!
//! ## File-based Emulation APIs
//!
//! For file-based emulation, use the APIs in `td_uefi_pi::fv` module:
//! - `init_file_based_emulation_with_paths()` - Initialize with custom file paths
//! - `init_file_based_emulation()` - Initialize with default paths
//! - `load_policy_data()` / `load_root_ca_data()` - Load data from buffers
//! - `set_policy_file_path()` / `set_root_ca_file_path()` - Set file paths
//! - `set_file_reader()` - Set custom file reader function
//!
//! ## Usage Example
//!
//! ```rust
//! use td_shim_interface_emu::td_uefi_pi::fv;
//!
//! // Initialize file-based emulation with custom paths
//! fv::init_file_based_emulation_with_paths("/tmp/policy.bin", "/tmp/root_ca.bin");
//!
//! // Or load data directly from buffers
//! fv::load_policy_data(b"policy data");
//! fv::load_root_ca_data(b"root ca data");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod acpi;
pub mod file_ops;
pub mod td_uefi_pi;

// Re-export key functions for convenience
pub use td_uefi_pi::fv::{
    load_policy_from_file, load_root_ca_from_file, set_policy_data, set_root_ca_data,
};

#[cfg(feature = "policy_v2")]
pub use td_uefi_pi::fv::load_policy_issuer_chain_from_file;

#[cfg(feature = "policy_v2")]
pub use file_ops::init_file_based_emulation_with_policy_chain;
pub use file_ops::init_file_based_emulation_with_real_files;
