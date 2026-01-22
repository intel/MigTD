// Copyright (c) 2025 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! td-logger shim for AzCVMEmu mode.
//!
//! This module provides the same `dbg_write_string` interface as the real td-logger crate
//! but routes output to standard console (stderr) instead of TDX debug ports.
//!
//! Note:
//! The logging facade (log::Log trait) is not needed here since the MigTD VmmLoggerBackend
//! serves as the global logger.

/// Write a string to console (emulates TDX debug port write)
pub fn dbg_write_string(s: &str) {
    eprint!("{}", s);
}

/// Write a byte to console (emulates debug port write)
pub fn dbg_write_byte(byte: u8) {
    eprint!("{}", byte as char);
}
