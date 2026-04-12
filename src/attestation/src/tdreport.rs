// Copyright (c) 2021 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TD Report generation wrapper
//!
//! This module provides a wrapper around tdcall_report that can optionally
//! use a mock report for testing purposes when use-mock-quote feature is enabled.

// Re-export all items from the original tdreport module
pub use tdx_tdcall::tdreport::{
    tdcall_verify_report, ReportMac, ReportType, TdxReport, TD_REPORT_ADDITIONAL_DATA_SIZE,
    TD_REPORT_SIZE,
};

// Override tdcall_report with mock version
pub fn tdcall_report(
    _additional_data: &[u8; TD_REPORT_ADDITIONAL_DATA_SIZE],
) -> Result<TdxReport, tdx_tdcall::TdCallError> {
    use crate::mock_quote::create_mock_td_report;

    // Get the mock report from attestation module
    let mock_report = create_mock_td_report();

    Ok(mock_report)
}
