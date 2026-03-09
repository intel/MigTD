// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Quote generation with retry logic for handling transient errors
#![cfg(feature = "attestation")]

use alloc::vec::Vec;

#[cfg(not(feature = "AzCVMEmu"))]
use tdx_tdcall::tdreport::tdcall_report;

#[cfg(feature = "AzCVMEmu")]
use tdx_tdcall_emu::tdreport::tdcall_report;

/// Initial backoff delay in milliseconds.
const INITIAL_DELAY_MS: u64 = 1000;

/// Maximum number of retries.
/// The cumulative exponential-backoff sleep time is bounded to stay below
/// SPDM_TIMEOUT (60 seconds). This bound does not include time spent in
/// TD report generation or `attestation::get_quote()` itself.
const MAX_RETRIES: u32 = 5; // Backoff sleep time totals up to 31 seconds with 1s initial delay

/// Error type for quote generation with retry
#[derive(Debug)]
pub enum QuoteError {
    /// Failed to generate TD report
    ReportGenerationFailed,
    /// Quote generation failed after all retry attempts
    QuoteGenerationFailed,
}

/// Get a quote with retry logic to handle potential security updates
///
/// On quote failure, fetches a new TD REPORT and retries with exponential backoff.
///
/// # Arguments
/// * `additional_data` - The 64-byte additional data to include in the TD REPORT
///
/// # Returns
/// * `Ok((quote, report))` - The generated quote and the TD REPORT used
/// * `Err(QuoteError)` - If TD report/quote generation fails
pub fn get_quote_with_retry(additional_data: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), QuoteError> {
    let mut attempt: u32 = 0;
    let mut busy_delay_ms = INITIAL_DELAY_MS;

    loop {
        let current_report = tdcall_report(additional_data).map_err(|e| {
            log::error!("Failed to get TD report: {:?}\n", e);
            QuoteError::ReportGenerationFailed
        })?;

        let report_bytes = current_report.as_bytes();

        match attestation::get_quote(report_bytes) {
            Ok(quote) => {
                log::info!("Quote generated successfully\n");
                return Ok((quote, report_bytes.to_vec()));
            }
            _ => {
                attempt += 1;
                if attempt > MAX_RETRIES {
                    log::error!("GetQuote failed after {} attempts\n", attempt);
                    return Err(QuoteError::QuoteGenerationFailed);
                }
                log::warn!(
                    "GetQuote failed (attempt {}/{}), retrying in {}ms\n",
                    attempt,
                    MAX_RETRIES + 1,
                    busy_delay_ms
                );
                delay_milliseconds(busy_delay_ms);
                busy_delay_ms *= 2;
            }
        }
    }
}

/// Delay for the specified number of milliseconds
#[cfg(feature = "AzCVMEmu")]
fn delay_milliseconds(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

#[cfg(not(feature = "AzCVMEmu"))]
fn delay_milliseconds(ms: u64) {
    use crate::driver::ticks::Timer;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use core::time::Duration;
    use td_payload::arch::apic::{disable, enable_and_hlt};

    let mut timer = Timer::after(Duration::from_millis(ms));
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);

    loop {
        if let Poll::Ready(()) = Pin::new(&mut timer).poll(&mut cx) {
            break;
        }
        enable_and_hlt();
        disable();
    }
}
