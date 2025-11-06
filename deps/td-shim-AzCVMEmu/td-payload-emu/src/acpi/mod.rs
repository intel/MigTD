// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! ACPI emulation module for AzCVMEmu mode
//!
//! Re-exports ACPI functionality from td_shim_emu to match
//! the same API as td_payload::acpi in non-emulation mode

pub use td_shim_emu::event_log::get_acpi_tables;
