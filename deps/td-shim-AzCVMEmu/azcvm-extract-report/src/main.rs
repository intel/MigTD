// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! MigTD Report Extractor Tool
//!
//! This tool extracts report information from vTPM in Azure CVM environments
//! and outputs the data needed for ServTD collateral (TCB mapping and identity).
//!
//! For testing and development with migtd configured with skip-ra-and-accept-all,
//! use the --mock-report flag to generate predictable test data.
//!
//! Usage:
//!   azcvm-extract-report --output-json report_data.json
//!   azcvm-extract-report --mock-report --output-json mock_report_data.json

use anyhow::{Context, Result};
use az_tdx_vtpm::tdx;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use tdx_tdcall_emu::tdreport_emu::tdcall_report_emulated;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output JSON file path
    #[arg(short, long, default_value = "migtd_report_data.json")]
    output_json: String,

    /// Custom report data (48 bytes hex string)
    #[arg(long)]
    report_data: Option<String>,

    /// Generate mock report for skip-ra-and-accept-all mode (testing/development only)
    #[arg(long)]
    mock_report: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReportData {
    mrtd: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
    xfam: String,
    attributes: String,
    mr_config_id: String,
    mr_owner: String,
    mr_owner_config: String,
    servtd_hash: String,
    isv_prod_id: u16,
    isvsvn: u16,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>()
}

fn get_td_report_from_vtpm(report_data: Option<&[u8; 48]>, use_mock: bool) -> Result<tdx::TdReport> {
    if use_mock {
        // Use the existing create_mock_td_report function from tdx-tdcall-emu
        use tdx_tdcall_emu::tdreport_emu::create_mock_td_report;
        Ok(create_mock_td_report())
    } else {
        log::info!("Getting TD report from vTPM using tdcall_report_emulated");

        let default_report_data = [0u8; 48];
        let data = report_data.unwrap_or(&default_report_data);

        let mut report_data_64 = [0u8; 64];
        report_data_64[..48].copy_from_slice(data);

        tdcall_report_emulated(&report_data_64)
            .map_err(|e| anyhow::anyhow!("Failed to get TD report: {:?}", e))
    }
}

fn extract_report_data(td_report: &tdx::TdReport) -> Result<ReportData> {
    log::info!("Extracting report data from TD report");

    let td_info = &td_report.tdinfo;

    // Extract RTMRs from the TD report
    // Note: In Azure CVM Underhill environments, RTMRs will be zeros
    // But in mock/test environments with quote files, they can contain actual measurements
    let data = ReportData {
        mrtd: bytes_to_hex(&td_info.mrtd),
        rtmr0: bytes_to_hex(&td_info.rtrm[0].register_data),
        rtmr1: bytes_to_hex(&td_info.rtrm[1].register_data),
        rtmr2: bytes_to_hex(&td_info.rtrm[2].register_data),
        rtmr3: bytes_to_hex(&td_info.rtrm[3].register_data),
        xfam: bytes_to_hex(&td_info.xfam),
        attributes: bytes_to_hex(&td_info.attributes),
        mr_config_id: bytes_to_hex(&td_info.mrconfigid),
        mr_owner: bytes_to_hex(&td_info.mrowner),
        mr_owner_config: bytes_to_hex(&td_info.mrownerconfig),
        servtd_hash: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(), // MigTD itself has no ServTD
        isv_prod_id: 0, // MigTD doesn't use ISV_PROD_ID
        isvsvn: 1, // Default ISV SVN - should be incremented for each build
    };

    log::info!("Successfully extracted report data");
    log::debug!("MRTD: {}", data.mrtd);
    log::debug!("RTMR0: {}", data.rtmr0);
    log::debug!("RTMR1: {}", data.rtmr1);

    Ok(data)
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    log::info!("MigTD AzCVM Report Extractor Tool");
    log::info!("==================================");

    if args.mock_report {
        log::info!("🧪 MOCK MODE: Generating test data for skip-ra-and-accept-all");
        log::info!("    This data is suitable for testing MigTD with disabled remote attestation");
    }

    let report_data = if let Some(ref hex_str) = args.report_data {
        let bytes = hex::decode(hex_str).context("Invalid hex string for report data")?;
        if bytes.len() != 48 {
            anyhow::bail!("Report data must be exactly 48 bytes");
        }
        let mut data = [0u8; 48];
        data.copy_from_slice(&bytes);
        Some(data)
    } else {
        None
    };

    let td_report = get_td_report_from_vtpm(report_data.as_ref(), args.mock_report)
        .context("Failed to get TD report from vTPM")?;

    let report_data = extract_report_data(&td_report).context("Failed to extract report data")?;

    let json =
        serde_json::to_string_pretty(&report_data).context("Failed to serialize report data")?;

    fs::write(&args.output_json, json)
        .context(format!("Failed to write to {}", args.output_json))?;

    log::info!("Report data written to: {}", args.output_json);
    log::info!("✓ Success");

    Ok(())
}
