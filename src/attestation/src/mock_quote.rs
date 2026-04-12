// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg(feature = "use-mock-quote")]

use alloc::vec::Vec;
use log::debug;
use tdx_mock_data::QUOTE;
use tdx_tdcall::tdreport::TdxReport;

pub fn create_mock_td_report() -> TdxReport {
    tdx_mock_data::create_mock_td_report(QUOTE.as_ref())
}

pub fn get_mock_quote(_td_report_data: &[u8]) -> Vec<u8> {
    debug!("Mock quote created with size: {}", QUOTE.len());
    QUOTE.to_vec()
}
