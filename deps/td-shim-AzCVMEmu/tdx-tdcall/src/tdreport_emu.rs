// Copyright (c) 2021 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TD Report generation emulation for AzCVMEmu mode
//!
//! This module provides emulation for TD report generation using vTPM interface
//! and IMDS for quote generation in Azure CVM environments.

use alloc::vec::Vec;
use az_tdx_vtpm::{hcl, imds, tdx, vtpm};
use log::{debug, error, info};
use original_tdx_tdcall::TdCallError;

/// Simple error type for internal emulation errors that are not TdCallError
/// Used only for get_quote_emulated which doesn't need TdCallError compatibility
#[derive(Debug)]
pub enum QuoteError {
    VtpmError,
    ImdsError,
    ConversionError,
}

/// Emulated TD report generation using vTPM interface
/// Returns TdCallError directly to match original tdcall_report function signature
pub fn tdcall_report_emulated(additional_data: &[u8; 64]) -> Result<tdx::TdReport, TdCallError> {
    #[cfg(feature = "test_disable_ra_and_accept_all")]
    {
        info!("Using mock TD report for test_disable_ra_and_accept_all feature");
        return Ok(create_mock_td_report(additional_data));
    }

    info!("Using AzCVMEmu vTPM interface for report generation");

    // Get the vTPM report with our additional data as user data
    debug!("Getting vTPM report with retry mechanism");

    // Retry logic for vTPM report generation
    let mut vtpm_report = None;
    let max_retries = 3;

    for attempt in 1..=max_retries {
        debug!("vTPM report attempt {} of {}", attempt, max_retries);

        match vtpm::get_report_with_report_data(additional_data) {
            Ok(report) => {
                debug!("vTPM report obtained successfully on attempt {}", attempt);
                vtpm_report = Some(report);
                break;
            }
            Err(e) => {
                error!("vTPM report attempt {} failed: {:?}", attempt, e);

                if attempt < max_retries {
                    debug!("Waiting 5 seconds before retry...");
                    // Wait 5 seconds using std::time in AzCVMEmu mode
                    let start = std::time::Instant::now();
                    while start.elapsed() < std::time::Duration::from_secs(5) {
                        // Busy wait
                    }
                } else {
                    error!("All vTPM report attempts failed");
                    // Map to TdCallError::TdxExitInvalidParameters for compatibility
                    return Err(TdCallError::TdxExitInvalidParameters);
                }
            }
        }
    }

    let vtpm_report = vtpm_report.ok_or(TdCallError::TdxExitInvalidParameters)?;

    // Create an HCL report from the vTPM report
    debug!("Creating HCL report from vTPM report");
    let hcl_report = match hcl::HclReport::new(vtpm_report) {
        Ok(report) => {
            debug!("HCL report created successfully");
            report
        }
        Err(_) => {
            error!("Failed to create HCL report");
            return Err(TdCallError::TdxExitInvalidParameters);
        }
    };

    // Convert the HCL report to a TD report
    debug!("Converting HCL report to TD report");
    match tdx::TdReport::try_from(hcl_report) {
        Ok(report) => {
            debug!("TD report conversion successful");
            Ok(report)
        }
        Err(_) => {
            error!("Failed to convert HCL report to TD report");
            Err(TdCallError::TdxExitInvalidParameters)
        }
    }
}

/// Emulated quote generation using IMDS interface
/// This function doesn't need to match original tdcall error types
pub fn get_quote_emulated(td_report_data: &[u8]) -> Result<Vec<u8>, QuoteError> {
    #[cfg(feature = "test_disable_ra_and_accept_all")]
    {
        debug!("Using mock quote for test_disable_ra_and_accept_all feature");
        return Ok(create_mock_quote(td_report_data));
    }

    debug!(
        "Getting quote from TD report data (size: {})",
        td_report_data.len()
    );

    // Check if we have a full TD report or just report data
    let td_report_struct = if td_report_data.len() >= core::mem::size_of::<tdx::TdReport>() {
        // We have a full TD report - use it directly
        unsafe { *(td_report_data.as_ptr() as *const tdx::TdReport) }
    } else {
        // We only have report data (48 bytes) - need to generate a full TD report first
        debug!("Generating TD report from report data");

        // Pad or truncate the report data to 64 bytes for tdcall_report_emulated
        let mut report_data_64 = [0u8; 64];
        let copy_len = core::cmp::min(64, td_report_data.len());
        report_data_64[..copy_len].copy_from_slice(&td_report_data[..copy_len]);

        // Generate a full TD report using our emulated function
        match tdcall_report_emulated(&report_data_64) {
            Ok(report) => report,
            Err(e) => {
                error!("Failed to generate TD report from report data: {:?}", e);
                return Err(QuoteError::ConversionError);
            }
        }
    };

    match imds::get_td_quote(&td_report_struct) {
        Ok(quote) => {
            info!("Successfully got TD quote from IMDS");
            Ok(quote)
        }
        Err(e) => {
            error!("IMDS call failed (expected outside Azure): {:?}", e);
            error!("Failed to get TD quote from IMDS: {:?}", e);
            Err(QuoteError::ImdsError)
        }
    }
}

/// Create a mock TD report for testing purposes
#[cfg(feature = "test_disable_ra_and_accept_all")]
pub fn create_mock_td_report(additional_data: &[u8; 64]) -> tdx::TdReport {
    debug!("Creating mock TD report with additional data");

    // Import the structures from original tdx-tdcall
    use original_tdx_tdcall::tdreport::{ReportMac, ReportType, TdInfo, TdxReport, TeeTcbInfo};

    // Create a mock TD report with realistic structure but test data
    let td_report = TdxReport {
        report_mac: ReportMac {
            report_type: ReportType {
                r#type: 0x81, // TDX report type
                subtype: 0x00,
                version: 0x00,
                reserved: 0x00,
            },
            reserved0: [0u8; 12],
            cpu_svn: [0x01; 16],           // Mock CPU SVN
            tee_tcb_info_hash: [0x42; 48], // Mock hash
            tee_info_hash: [0x43; 48],     // Mock hash
            report_data: *additional_data, // Include the actual additional data
            reserved1: [0u8; 32],
            mac: [0xBB; 32], // Mock MAC
        },
        tee_tcb_info: TeeTcbInfo {
            valid: [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            tee_tcb_svn: [0x02; 16],
            mrseam: [0x44; 48],
            mrsigner_seam: [0x45; 48],
            attributes: [0x00; 8],
            reserved: [0u8; 111],
        },
        reserved: [0u8; 17],
        td_info: TdInfo {
            attributes: [0x00; 8],
            xfam: [0x03; 8],
            mrtd: [0x46; 48],
            mrconfig_id: [0x47; 48],
            mrowner: [0x48; 48],
            mrownerconfig: [0x49; 48],
            rtmr0: [0x4A; 48],
            rtmr1: [0x4B; 48],
            rtmr2: [0x4C; 48],
            rtmr3: [0x4D; 48],
            servtd_hash: [0x4E; 48],
            reserved: [0u8; 64],
        },
    };

    debug!("Mock TD report created successfully");

    // Convert to az-tdx-vtpm TdReport for compatibility
    // This is a bit of a hack but necessary for type compatibility
    unsafe { core::mem::transmute(td_report) }
}

/// Create a mock quote for testing purposes  
#[cfg(feature = "test_disable_ra_and_accept_all")]
pub fn create_mock_quote(td_report_data: &[u8]) -> Vec<u8> {
    debug!(
        "Creating mock quote from TD report data (size: {})",
        td_report_data.len()
    );

    // Create a simplified mock quote structure
    let mut quote = Vec::new();

    // Mock quote header (simplified)
    quote.extend_from_slice(&[0x04, 0x00]); // Version
    quote.extend_from_slice(&[0x81, 0x00]); // Attestation key type (TDX)
    quote.extend_from_slice(&[0x00; 4]); // Reserved
    quote.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // Mock QE SVN
    quote.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]); // Mock PCE SVN
    quote.extend_from_slice(&[0x00; 16]); // QE Vendor ID
    quote.extend_from_slice(&[0xAA; 20]); // User data (mock)

    // Mock TD report section (include the actual report data for consistency)
    let report_size = core::cmp::min(td_report_data.len(), 1024);
    quote.extend_from_slice(&(report_size as u32).to_le_bytes()); // TD report size
    if report_size > 0 {
        quote.extend_from_slice(&td_report_data[..report_size]);
    }

    // Mock signature section
    quote.extend_from_slice(&[0x00; 4]); // Signature data size
    quote.extend_from_slice(&[0xBB; 64]); // Mock ECDSA signature
    quote.extend_from_slice(&[0xCC; 64]); // Mock public key

    debug!("Mock quote created with size: {}", quote.len());
    quote
}
