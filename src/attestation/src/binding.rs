// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[allow(unused)]
#[repr(C)]
#[derive(Debug, PartialEq)]
pub(crate) enum AttestLibError {
    /// Success
    Success = 0x0000,
    /// Unexpected error
    Unexpected = 0x0001,
    /// The parameter is incorrect
    InvalidParameter = 0x0002,
    /// Not enough memory is available to complete this operation
    OutOfMemory = 0x0003,
    /// vsock related failure
    VsockFailure = 0x0004,
    /// Failed to get the TD Report
    ReportFailure = 0x0005,
    /// Failed to extend rtmr
    ExtendFailure = 0x0006,
    /// Request feature is not supported
    NotSupported = 0x0007,
    /// Failed to get the TD Quote
    QuoteFailure = 0x0008,
    /// The device driver return busy
    Busy = 0x0009,
    /// Failed to acess tdx attest device
    DeviceFailure = 0x000a,
    /// Only supported RTMR index is 2 and 3
    InvalidRtmrIndex = 0x000b,
}

extern "C" {
    /// Get MigTD's Quote by passing tdx_report.
    /// Note: all IN/OUT memory should be managed by Caller
    ///
    /// @param p_tdx_report [in] pointer to the input buffer for tdx_report. Must not be NULL.
    /// @param tdx_report_size [in] length of p_tdx_report(in bytes), should be = TDX_REPORT_SIZE.
    /// @param p_quote [in, out] pointer to the quote buffer. Must not be NULL.
    /// @param p_quote_size [in, out] This function will place the size of the Quote, in
    ///                           bytes, in the uint32_t pointed to by the
    ///                           p_quote_size parameter. Must not be NULL.
    /// @return Status code of the operation, one of:
    ///      - MIGTD_ATTEST_SUCCESS: Successfully generate the Quote
    ///      - MIGTD_ATTEST_ERROR_UNEXPECTED: An unexpected internal error occurred. E.g.
    ///          the parameter is incorrect, failed to get quote from QGS, heap memory allocation error,
    ///          the input (*p_quote_size) is not enough to place the real Quote, etc.
    pub(crate) fn get_quote(
        p_tdx_report: *const ::core::ffi::c_void,
        tdx_report_size: u32,
        p_quote: *mut ::core::ffi::c_void,
        p_quote_size: *mut u32,
    ) -> AttestLibError;
}

extern "C" {
    /// Verify the integrity of MigTD's Quote and return td report of MigTD
    /// Note: all IN/OUT memory should be managed by Caller
    /// @param p_quote [in] pointer to the input buffer for td_quote
    /// @param quote_size [in] length of p_quote(in bytes), should be the real size of MigTD td quote
    /// @param p_quote_collateral [in] quote collateral that get from PCS by get_collateral
    /// @param root_pub_key [in] pointer to Intel Root Public Key
    /// @param root_pub_key_size [in] length of Intel Root Public Key(in bytes)
    /// @param p_tdx_report_verify [in, out] pointer to the output buffer for tdx_report
    /// @param p_tdx_report_verify_size [in, out], out_size should be = TDX_REPORT_SIZE
    ///
    /// @return Status code of the operation, one of:
    ///      - MIGTD_ATTEST_SUCCESS
    ///      - MIGTD_ATTEST_ERROR_UNEXPECTED
    pub(crate) fn verify_quote_integrity(
        p_quote: *const ::core::ffi::c_void,
        quote_size: u32,
        root_pub_key: *const ::core::ffi::c_void,
        root_pub_key_size: u32,
        p_tdx_report_verify: *mut ::core::ffi::c_void,
        p_tdx_report_verify_size: *mut u32,
    ) -> AttestLibError;
}

extern "C" {
    /// Allocate heap space for MigTD Attestation library internal use,
    /// Must be called only once by MigTD before other attestation lib APIs
    ///
    /// @param p_td_heap_base [in] the heap base address allocated by MigTD, the address should be aligned(0x1000).
    /// @param td_heap_size [in] the capacity of the heap, should be multiples of 0x1000 (in bytes)
    ///
    /// @return true: Successfully init heap for internal use.
    /// @return false: Failed to init heap for internal use. E.g. the parameter is incorrect, etc.
    pub(crate) fn init_heap(
        p_td_heap_base: *const ::core::ffi::c_void,
        td_heap_size: u32,
    ) -> AttestLibError;
}
