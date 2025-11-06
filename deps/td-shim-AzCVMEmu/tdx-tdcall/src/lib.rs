// Copyright (c) 2020-2025 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(feature = "no-std", no_std)]

//! Azure CVM Emulation layer for TDX TDCALL interface
//!
//! This crate provides a drop-in replacement for the original tdx-tdcall crate
//! that emulates TDX VMCALL operations using TCP transport for development and
//! testing in non-TDX environments.

extern crate alloc;

// Import the original tdx-tdcall as a dependency
pub use original_tdx_tdcall;

// Re-export all the standard tdx-tdcall types and constants
// Re-export error types and constants that are needed
pub use original_tdx_tdcall::{TdCallError, TdVmcallError, TdcallArgs};

// Export constants that we need from the original library
pub const TDCALL_STATUS_SUCCESS: u64 = 0;

// Our TDX emulation module
pub mod tdx_emu;

// Our emulated tdreport module
pub mod tdreport_emu;

// Hardcoded collateral data for AzCVMEmu mode
mod collateral_data;

// Re-export TDX emulation functions
pub use tdx_emu::{
    connect_tcp_client, init_tcp_emulation_with_mode, start_tcp_server_sync, tcp_receive_data,
    tcp_send_data, TcpEmulationMode,
};

// Re-export the emulated functions
pub mod tdx {
    // Re-export all non-MigTD functions from original
    pub use original_tdx_tdcall::tdx::{
        tdcall_accept_page,
        tdcall_get_td_info,
        tdcall_get_ve_info,
        tdcall_vp_read,
        tdvmcall_cpuid,
        // Standard VMCALL functions
        tdvmcall_halt,
        tdvmcall_io_read_16,
        tdvmcall_io_read_32,
        tdvmcall_io_read_8,
        tdvmcall_io_write_16,
        tdvmcall_io_write_32,
        tdvmcall_io_write_8,
        tdvmcall_mapgpa,
        tdvmcall_mmio_read,
        tdvmcall_mmio_write,
        tdvmcall_rdmsr,
        tdvmcall_service,
        // tdvmcall_setup_event_notify is emulated, not re-exported
        tdvmcall_sti_halt,
        tdvmcall_wrmsr,
        // Re-export types
        TdxDigest,
    };

    // Export emulated functions
    pub use crate::tdx_emu::{
        tdcall_extend_rtmr, tdcall_servtd_rd, tdcall_servtd_wr, tdcall_sys_rd, tdcall_sys_wr,
        tdvmcall_get_quote, tdvmcall_migtd_receive_sync as tdvmcall_migtd_receive,
        tdvmcall_migtd_reportstatus, tdvmcall_migtd_send_sync as tdvmcall_migtd_send,
        tdvmcall_migtd_waitforrequest, tdvmcall_setup_event_notify,
    };
}

// Emulated tdreport module for AzCVMEmu compatibility
pub mod tdreport {
    use crate::tdreport_emu::tdcall_report_emulated;
    use az_tdx_vtpm::tdx::TdReport as AzTdReport;
    use original_tdx_tdcall::TdCallError;

    // Re-export some useful constants and types from original
    pub use original_tdx_tdcall::tdreport::{
        TdxReport, TD_REPORT_ADDITIONAL_DATA_SIZE, TD_REPORT_SIZE,
    };

    /// Emulated tdcall_report function for AzCVMEmu mode
    /// Now returns the exact same error type as the original for perfect compatibility
    pub fn tdcall_report(additional_data: &[u8; 64]) -> Result<TdxReport, TdCallError> {
        let az_td_report = tdcall_report_emulated(additional_data)?;

        // Create a full 1024-byte TdxReport from the az-tdx-vtpm TdReport
        // We need to copy the az-tdx-vtpm data into a properly sized buffer
        let mut tdx_report_bytes = [0u8; TD_REPORT_SIZE];

        // Convert az_td_report to bytes using pointer cast
        let az_report_bytes = unsafe {
            core::slice::from_raw_parts(
                &az_td_report as *const AzTdReport as *const u8,
                core::mem::size_of::<AzTdReport>(),
            )
        };

        let copy_size = core::cmp::min(az_report_bytes.len(), TD_REPORT_SIZE);
        tdx_report_bytes[..copy_size].copy_from_slice(&az_report_bytes[..copy_size]);

        // Convert the full 1024-byte buffer to TdxReport
        let tdx_report = unsafe {
            // Safety: We have a properly sized 1024-byte buffer that matches TdxReport layout
            core::mem::transmute::<[u8; TD_REPORT_SIZE], TdxReport>(tdx_report_bytes)
        };

        Ok(tdx_report)
    }
}

// Add td_call emulation support
pub fn td_call(args: &mut TdcallArgs) -> u64 {
    const TDVMCALL_SYS_RD: u64 = 0x0000b;

    match args.rax {
        TDVMCALL_SYS_RD => {
            match crate::tdx_emu::tdcall_sys_rd(args.rcx) {
                Ok((rdx, r8)) => {
                    args.rdx = rdx;
                    args.r8 = r8;
                    TDCALL_STATUS_SUCCESS
                }
                Err(_) => 0xFFFFFFFFFFFFFFFF, // Error code
            }
        }
        _ => {
            // Return error for unsupported rax values
            0xFFFFFFFFFFFFFFFF // Generic error code
        }
    }
}
