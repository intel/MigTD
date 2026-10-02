// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Quote generation with retry logic for handling transient errors
#![cfg(feature = "attestation")]

use alloc::vec::Vec;
use core::mem::size_of;
use tdx_tdcall::tdreport::TdxReport;

#[cfg(not(feature = "AzCVMEmu"))]
use tdx_tdcall::tdreport::tdcall_report;

#[cfg(feature = "AzCVMEmu")]
use tdx_tdcall_emu::tdreport::tdcall_report;

/// Initial retry delay in milliseconds (1 seconds)
#[cfg(not(feature = "AzCVMEmu"))]
const INITIAL_DELAY_MS: u64 = 1000;

//shorter for testing
#[cfg(feature = "AzCVMEmu")]
const INITIAL_DELAY_MS: u64 = 20;

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
    /// Quote verification failed
    QuoteVerificationFailed,
    /// The verified quote does not describe the TD REPORT used to request it
    QuoteReportMismatch,
}

const VERIFIED_TEE_TCB_SVN: core::ops::Range<usize> = 0..16;
const VERIFIED_MRSEAM: core::ops::Range<usize> = 16..64;
const VERIFIED_MRSIGNER_SEAM: core::ops::Range<usize> = 64..112;
const VERIFIED_SEAM_ATTRIBUTES: core::ops::Range<usize> = 112..120;
const VERIFIED_TD_INFO: core::ops::Range<usize> = 120..520;
const VERIFIED_REPORT_DATA: core::ops::Range<usize> = 520..584;

/// Verify a local quote and bind it to the TD REPORT supplied to the quote service.
#[cfg(not(any(feature = "use-mock-quote", feature = "test_disable_ra_and_accept_all")))]
pub fn verify_local_quote(quote: &[u8], report: &[u8]) -> Result<(), QuoteError> {
    let verified_report =
        attestation::verify_quote(quote).map_err(|_| QuoteError::QuoteVerificationFailed)?;
    verify_local_report(&verified_report, report)
}

/// Verify the static mock quote without binding it to the live TD REPORT.
#[cfg(all(
    feature = "use-mock-quote",
    not(feature = "test_disable_ra_and_accept_all")
))]
pub fn verify_local_quote(quote: &[u8], _report: &[u8]) -> Result<(), QuoteError> {
    attestation::verify_quote(quote).map_err(|_| QuoteError::QuoteVerificationFailed)?;
    log::warn!(
        "use-mock-quote mode: Skipping local quote binding verification. This is NOT secure for production use.\n"
    );
    Ok(())
}

/// Skip verification when remote attestation is explicitly disabled for testing.
#[cfg(feature = "test_disable_ra_and_accept_all")]
pub fn verify_local_quote(_quote: &[u8], _report: &[u8]) -> Result<(), QuoteError> {
    log::warn!(
        "test_disable_ra_and_accept_all mode: Skipping local quote binding verification. This is NOT secure for production use.\n"
    );
    Ok(())
}

/// Compare quote verification output with the authentic local TD REPORT.
pub fn verify_local_report(verified_report: &[u8], report: &[u8]) -> Result<(), QuoteError> {
    if verified_report.len() < VERIFIED_REPORT_DATA.end || report.len() != size_of::<TdxReport>() {
        return Err(QuoteError::QuoteReportMismatch);
    }

    let report = TdxReport::read_from_bytes(report).ok_or(QuoteError::QuoteReportMismatch)?;
    let tee_tcb_info = report.tee_tcb_info;
    let td_info = report.td_info;
    let report_mac = report.report_mac;

    if verified_report[VERIFIED_TEE_TCB_SVN] != tee_tcb_info.tee_tcb_svn
        || verified_report[VERIFIED_MRSEAM] != tee_tcb_info.mrseam
        || verified_report[VERIFIED_MRSIGNER_SEAM] != tee_tcb_info.mrsigner_seam
        || verified_report[VERIFIED_SEAM_ATTRIBUTES] != tee_tcb_info.attributes
        || verified_report[VERIFIED_TD_INFO] != td_info.as_bytes()[..400]
        || verified_report[VERIFIED_REPORT_DATA] != report_mac.report_data
    {
        return Err(QuoteError::QuoteReportMismatch);
    }

    Ok(())
}

/// Get a quote with retry logic to handle transient and retriable errors
///
/// On retriable errors, retries with exponential backoff starting at 1s.
/// Non-retriable errors cause immediate failure.
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
            Err(attestation::Error::Busy) => {
                attempt += 1;
                if attempt > MAX_RETRIES {
                    log::error!("GetQuote failed after {} attempts\n", attempt);
                    return Err(QuoteError::QuoteGenerationFailed);
                }
                log::warn!(
                    "GetQuote returned Busy (attempt {}/{}), retrying in {}ms\n",
                    attempt,
                    MAX_RETRIES + 1,
                    busy_delay_ms
                );
                delay_milliseconds(busy_delay_ms);
                busy_delay_ms *= 2;
            }
            Err(e) => {
                log::error!("GetQuote failed with non-retriable error: {:?}\n", e);
                return Err(QuoteError::QuoteGenerationFailed);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn matching_evidence() -> (Vec<u8>, Vec<u8>) {
        let zeroed = vec![0u8; size_of::<TdxReport>()];
        let mut report = TdxReport::read_from_bytes(&zeroed).unwrap();
        report.report_mac.report_data = [0x11; 64];
        report.tee_tcb_info.tee_tcb_svn = [0x20; 16];
        report.tee_tcb_info.mrseam = [0x22; 48];
        report.tee_tcb_info.mrsigner_seam = [0x33; 48];
        report.tee_tcb_info.attributes = [0x44; 8];

        let mut td_info = report.td_info;
        td_info.attributes = [0x51; 8];
        td_info.xfam = [0x52; 8];
        td_info.mrtd = [0x53; 48];
        td_info.mrconfig_id = [0x54; 48];
        td_info.mrowner = [0x55; 48];
        td_info.mrownerconfig = [0x56; 48];
        td_info.rtmr0 = [0x57; 48];
        td_info.rtmr1 = [0x58; 48];
        td_info.rtmr2 = [0x59; 48];
        td_info.rtmr3 = [0x5a; 48];
        report.td_info = td_info;

        let mut verified = vec![0u8; attestation::TD_VERIFIED_REPORT_SIZE];
        verified[VERIFIED_TEE_TCB_SVN].fill(0x20);
        verified[VERIFIED_REPORT_DATA].fill(0x11);
        verified[VERIFIED_MRSEAM].fill(0x22);
        verified[VERIFIED_MRSIGNER_SEAM].fill(0x33);
        verified[VERIFIED_SEAM_ATTRIBUTES].fill(0x44);
        verified[VERIFIED_TD_INFO].copy_from_slice(&td_info.as_bytes()[..400]);
        (verified, report.as_bytes().to_vec())
    }

    #[test]
    fn accepts_quote_for_authentic_report() {
        let (verified, report) = matching_evidence();
        assert!(verify_local_report(&verified, &report).is_ok());
    }

    #[test]
    fn rejects_substituted_td_identity() {
        let (mut verified, report) = matching_evidence();
        verified[VERIFIED_TD_INFO.start + 16] ^= 1;
        assert!(matches!(
            verify_local_report(&verified, &report),
            Err(QuoteError::QuoteReportMismatch)
        ));
    }

    #[test]
    fn rejects_substituted_tdx_module_identity() {
        let (mut verified, report) = matching_evidence();
        verified[VERIFIED_TEE_TCB_SVN.start] ^= 1;
        assert!(matches!(
            verify_local_report(&verified, &report),
            Err(QuoteError::QuoteReportMismatch)
        ));
    }

    #[test]
    fn rejects_substituted_report_data() {
        let (mut verified, report) = matching_evidence();
        verified[VERIFIED_REPORT_DATA.start] ^= 1;
        assert!(matches!(
            verify_local_report(&verified, &report),
            Err(QuoteError::QuoteReportMismatch)
        ));
    }

    #[test]
    fn rejects_malformed_evidence() {
        let (verified, report) = matching_evidence();
        assert!(verify_local_report(&verified[..583], &report).is_err());
        assert!(verify_local_report(&verified, &report[..report.len() - 1]).is_err());
    }

    #[test]
    fn ignores_td_info_fields_not_present_in_quote() {
        let (verified, report) = matching_evidence();
        let mut parsed = TdxReport::read_from_bytes(&report).unwrap();
        let mut td_info = parsed.td_info;
        td_info.servtd_hash = [0xaa; 48];
        td_info.reserved = [0xbb; 64];
        parsed.td_info = td_info;
        assert!(verify_local_report(&verified, parsed.as_bytes()).is_ok());
    }
}
