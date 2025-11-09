// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

// Allow std for AzCVMEmu mode, otherwise use no_std
#![cfg_attr(not(feature = "AzCVMEmu"), no_std)]

extern crate alloc;

// Re-export TDX dependencies conditionally to avoid feature gates throughout the code
#[cfg(not(feature = "AzCVMEmu"))]
extern crate td_payload;
#[cfg(not(feature = "AzCVMEmu"))]
extern crate tdx_tdcall;

#[cfg(feature = "AzCVMEmu")]
extern crate td_payload_emu as td_payload;
#[cfg(feature = "AzCVMEmu")]
extern crate tdx_tdcall_emu as tdx_tdcall;

mod attest;
mod binding;
mod ghci;
pub mod root_ca;

#[cfg(feature = "igvm-attest")]
mod igvmattest;

pub use attest::*;

/// Supplemental data produced by quote verification, total serialized size is 774 bytes.
/// The layout of the data:
///
/// #[repr(C, packed)]
/// pub struct VerifiedReportData {
///     pub reserved0: [u8; 16],
///     pub tdx_module_mrseam: [u8; 48],
///     pub tdx_module_mrseamsigner: [u8; 48],
///     pub tdx_module_attr_seam: [u8; 8],
///     pub migtd_attr_td: [u8; 8],
///     pub migtd_xfam: [u8; 8],
///     pub migtd_mrtd: [u8; 48],
///     pub migtd_mrconfigid: [u8; 48],
///     pub migtd_mrowner: [u8; 48],
///     pub migtd_mrownerconfig: [u8; 48],
///     pub migtd_rtmr0: [u8; 48],
///     pub migtd_rtmr1: [u8; 48],
///     pub migtd_rtmr2: [u8; 48],
///     pub migtd_rtmr3: [u8; 48],
///     pub reserved1: [u8; 64],
///     pub platform_fmspc: [u8; 6],
///     pub platform_tdx_tcb_components: [u8; 16],
///     pub platform_pce_svn: [u8; 2],
///     pub platform_sgx_tcb_components: [u8; 16],
///     pub tdx_module_major_ver: u8,
///     pub tdx_module_svn: u8,
///     pub qe_misc_select: [u8; 4],
///     pub reserved2: [u8; 4],
///     pub qe_attributes: [u8; 16],
///     pub reserved3: [u8; 16],
///     pub qe_mrenclave: [u8; 32],
///     pub qe_mrsigner: [u8; 32],
///     pub qe_isv_prod_id: [u8; 2],
///     pub qe_isv_svn: [u8; 2],
///     pub tcb_date: u64,
///     pub tcb_status: [u8; 32],
/// }
pub const TD_VERIFIED_REPORT_SIZE: usize = 774;

#[derive(Debug)]
pub enum Error {
    InvalidRootCa,
    InitHeap,
    GetQuote,
    VerifyQuote,
    InvalidOutput,
    InvalidQuote,
    OutOfMemory,
}
