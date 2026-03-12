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

/// Supplemental data produced by quote verification, total serialized size is 822 bytes.
/// Matches C struct `servtd_tdx_quote_suppl_data` (packed).
/// The layout of the data:
///
/// #[repr(C, packed)]
/// pub struct VerifiedReportData {
///     pub reserved0: [u8; 16],                    //   0..16
///     pub tdx_module_mrseam: [u8; 48],            //  16..64
///     pub tdx_module_mrseamsigner: [u8; 48],       //  64..112
///     pub tdx_module_attr_seam: [u8; 8],           // 112..120
///     pub migtd_attr_td: [u8; 8],                  // 120..128
///     pub migtd_xfam: [u8; 8],                     // 128..136
///     pub migtd_mrtd: [u8; 48],                    // 136..184
///     pub migtd_mrconfigid: [u8; 48],              // 184..232
///     pub migtd_mrowner: [u8; 48],                 // 232..280
///     pub migtd_mrownerconfig: [u8; 48],           // 280..328
///     pub migtd_rtmr0: [u8; 48],                   // 328..376
///     pub migtd_rtmr1: [u8; 48],                   // 376..424
///     pub migtd_rtmr2: [u8; 48],                   // 424..472
///     pub migtd_rtmr3: [u8; 48],                   // 472..520
///     pub reserved1: [u8; 64],                     // 520..584
///     pub platform_fmspc: [u8; 6],                 // 584..590
///     pub platform_tdx_tcb_components: [u8; 16],   // 590..606
///     pub platform_pce_svn: [u8; 2],               // 606..608
///     pub platform_sgx_tcb_components: [u8; 16],   // 608..624
///     pub tdx_module_major_ver: u8,                // 624..625
///     pub tdx_module_svn: u8,                      // 625..626
///     pub qe_misc_select: [u8; 4],                 // 626..630
///     pub reserved2: [u8; 4],                      // 630..634
///     pub qe_attributes: [u8; 16],                 // 634..650
///     pub reserved3: [u8; 16],                     // 650..666
///     pub qe_mrenclave: [u8; 32],                  // 666..698
///     pub qe_mrsigner: [u8; 32],                   // 698..730
///     pub qe_isv_prod_id: [u8; 2],                 // 730..732
///     pub qe_isv_svn: [u8; 2],                     // 732..734
///     pub tcb_date: u64,                           // 734..742  effective = min(platform, qe)
///     pub tcb_status: [u8; 32],                    // 742..774
///     pub platform_tcb_date: u64,                  // 774..782
///     pub qe_tcb_date: u64,                        // 782..790
///     pub qe_tcb_status: [u8; 32],                 // 790..822
/// }
pub const TD_VERIFIED_REPORT_SIZE: usize = 822;

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
