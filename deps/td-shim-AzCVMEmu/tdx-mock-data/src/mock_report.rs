// Copyright (c) 2021 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Mock TD report generation from a given quote blob.
//! It includes quote parsing utilities for TD quotes in both v4 and v5 formats.

use log::{debug, error};
use sha2::{Digest, Sha384};
use tdx_tdcall::tdreport::{ReportMac, ReportType, TdInfo, TdxReport, TeeTcbInfo};

/// Quote header size (48 bytes)
const QUOTE_HEADER_SIZE: usize = 48;

/// Quote v4 body size (584 bytes) - sgx_report2_body_t for TDX 1.0
const QUOTE_V4_BODY_SIZE: usize = 584;

/// Quote v5 body size for TD Report 1.0 (type=2, 584 bytes)
const QUOTE_V5_BODY_SIZE_10: usize = 584;

/// Quote v5 body size for TD Report 1.5 (type=3, 648 bytes)
const QUOTE_V5_BODY_SIZE_15: usize = 648;

/// Minimum quote v4 size
const MIN_QUOTE_V4_SIZE: usize = QUOTE_HEADER_SIZE + QUOTE_V4_BODY_SIZE + 4;

/// Minimum quote v5 size
const MIN_QUOTE_V5_SIZE: usize = QUOTE_HEADER_SIZE + 2 + 4 + QUOTE_V5_BODY_SIZE_10 + 4;

/// SGX Report2 Body structure (584 bytes) for TDX 1.0
///
/// Quote body structure (sgx_report2_body_t from Intel DCAP):
/// - Offset 0:   tee_tcb_svn       [16 bytes]
/// - Offset 16:  mr_seam           [48 bytes]
/// - Offset 64:  mrsigner_seam     [48 bytes]
/// - Offset 112: seam_attributes   [8 bytes]
/// - Offset 120: td_attributes     [8 bytes]
/// - Offset 128: xfam              [8 bytes]
/// - Offset 136: mr_td             [48 bytes]
/// - Offset 184: mr_config_id      [48 bytes]
/// - Offset 232: mr_owner          [48 bytes]
/// - Offset 280: mr_owner_config   [48 bytes]
/// - Offset 328: rt_mr[4]          [192 bytes = 4 x 48]
/// - Offset 520: report_data       [64 bytes]
/// Total: 584 bytes
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct SgxReport2Body {
    tee_tcb_svn: [u8; 16],
    mr_seam: [u8; 48],
    mrsigner_seam: [u8; 48],
    seam_attributes: [u8; 8],
    td_attributes: [u8; 8],
    xfam: [u8; 8],
    mr_td: [u8; 48],
    mr_config_id: [u8; 48],
    mr_owner: [u8; 48],
    mr_owner_config: [u8; 48],
    rt_mr: [[u8; 48]; 4],
    report_data: [u8; 64],
}

/// SGX Report2 Body structure for TDX 1.5 (648 bytes)
///
/// Extended version with additional fields:
/// - [v5 only] Offset 584: tee_tcb_svn2  [16 bytes] (for TD preserving)
/// - [v5 only] Offset 600: mr_servicetd  [48 bytes] (service TD hash)
/// Total: 648 bytes
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct SgxReport2BodyV15 {
    tee_tcb_svn: [u8; 16],
    mr_seam: [u8; 48],
    mrsigner_seam: [u8; 48],
    seam_attributes: [u8; 8],
    td_attributes: [u8; 8],
    xfam: [u8; 8],
    mr_td: [u8; 48],
    mr_config_id: [u8; 48],
    mr_owner: [u8; 48],
    mr_owner_config: [u8; 48],
    rt_mr: [[u8; 48]; 4],
    report_data: [u8; 64],
    tee_tcb_svn2: [u8; 16],
    mr_servicetd: [u8; 48],
}

/// Parse quote header to determine version and body location
///
/// Returns: (body_offset, body_size, header_version, tee_type)
fn parse_quote_header(quote_data: &[u8]) -> Result<(usize, usize, u16, u32), &'static str> {
    if quote_data.len() < QUOTE_HEADER_SIZE + 2 {
        error!(
            "Quote file too small: {} bytes (expected at least {})",
            quote_data.len(),
            QUOTE_HEADER_SIZE + 2
        );
        return Err("Quote file too small");
    }

    // Parse quote header (48 bytes)
    let header_version = u16::from_le_bytes([quote_data[0], quote_data[1]]);
    let tee_type = u32::from_le_bytes([
        quote_data[4],
        quote_data[5],
        quote_data[6],
        quote_data[7],
    ]);

    debug!(
        "Quote header - version: {}, tee_type: 0x{:02x}",
        header_version, tee_type
    );

    // Determine quote version and parse accordingly
    let (body_offset, body_size) = if header_version == 4 {
        // Quote v4: body starts immediately after header
        if quote_data.len() < MIN_QUOTE_V4_SIZE {
            error!(
                "Quote v4 file too small: {} bytes (expected at least {})",
                quote_data.len(),
                MIN_QUOTE_V4_SIZE
            );
            return Err("Invalid quote v4 file: too small");
        }
        debug!("Parsing Quote v4 format");
        (QUOTE_HEADER_SIZE, QUOTE_V4_BODY_SIZE)
    } else if header_version == 5 {
        // Quote v5: has type and size fields after header
        if quote_data.len() < MIN_QUOTE_V5_SIZE {
            error!(
                "Quote v5 file too small: {} bytes (expected at least {})",
                quote_data.len(),
                MIN_QUOTE_V5_SIZE
            );
            return Err("Invalid quote v5 file: too small");
        }

        let body_type = u16::from_le_bytes([quote_data[48], quote_data[49]]);
        let body_size =
            u32::from_le_bytes([quote_data[50], quote_data[51], quote_data[52], quote_data[53]])
                as usize;

        debug!(
            "Parsing Quote v5 format - body_type: {}, body_size: {}",
            body_type, body_size
        );

        // Body type 2 = TD Report 1.0 (584 bytes), type 3 = TD Report 1.5 (648 bytes)
        let expected_size = match body_type {
            2 => QUOTE_V5_BODY_SIZE_10,
            3 => QUOTE_V5_BODY_SIZE_15,
            _ => {
                error!("Unsupported Quote v5 body type: {}", body_type);
                return Err("Unsupported Quote v5 body type");
            }
        };

        if body_size != expected_size {
            error!(
                "Quote v5 body size mismatch: {} (expected {})",
                body_size, expected_size
            );
            return Err("Invalid Quote v5 body size");
        }

        (QUOTE_HEADER_SIZE + 6, body_size)
    } else {
        error!("Unsupported quote version: {}", header_version);
        return Err("Unsupported quote version");
    };

    Ok((body_offset, body_size, header_version, tee_type))
}

/// Parse quote body and extract report body and servtd_hash
///
/// Returns: (report_body, servtd_hash)
fn parse_quote_body(
    quote_data: &[u8],
    body_offset: usize,
    body_size: usize,
    header_version: u16,
) -> Result<(SgxReport2Body, [u8; 48]), &'static str> {
    if body_offset + body_size > quote_data.len() {
        error!("Quote body extends beyond data length");
        return Err("Quote body extends beyond data length");
    }

    // Get report body from quote
    let (report_body, servtd_hash) = if body_size == QUOTE_V5_BODY_SIZE_15 {
        // v5 with TD Report 1.5 (648 bytes) - includes mr_servicetd
        let report_v15 = unsafe {
            &*(quote_data[body_offset..body_offset + body_size].as_ptr()
                as *const SgxReport2BodyV15)
        };
        debug!("Successfully parsed TD quote v5.5 body (648 bytes)");

        // Extract the base report body fields
        let base_body = SgxReport2Body {
            tee_tcb_svn: report_v15.tee_tcb_svn,
            mr_seam: report_v15.mr_seam,
            mrsigner_seam: report_v15.mrsigner_seam,
            seam_attributes: report_v15.seam_attributes,
            td_attributes: report_v15.td_attributes,
            xfam: report_v15.xfam,
            mr_td: report_v15.mr_td,
            mr_config_id: report_v15.mr_config_id,
            mr_owner: report_v15.mr_owner,
            mr_owner_config: report_v15.mr_owner_config,
            rt_mr: report_v15.rt_mr,
            report_data: report_v15.report_data,
        };
        (base_body, report_v15.mr_servicetd)
    } else {
        // v4 or v5 with TD Report 1.0 (584 bytes)
        let report = unsafe {
            &*(quote_data[body_offset..body_offset + body_size].as_ptr() as *const SgxReport2Body)
        };
        debug!(
            "Successfully parsed TD quote v{} body (584 bytes)",
            header_version
        );

        // Copy the struct to move it out of the unsafe block
        let base_body = SgxReport2Body {
            tee_tcb_svn: report.tee_tcb_svn,
            mr_seam: report.mr_seam,
            mrsigner_seam: report.mrsigner_seam,
            seam_attributes: report.seam_attributes,
            td_attributes: report.td_attributes,
            xfam: report.xfam,
            mr_td: report.mr_td,
            mr_config_id: report.mr_config_id,
            mr_owner: report.mr_owner,
            mr_owner_config: report.mr_owner_config,
            rt_mr: report.rt_mr,
            report_data: report.report_data,
        };
        (base_body, [0u8; 48]) // SERVTD_HASH always zero for MigTD
    };

    Ok((report_body, servtd_hash))
}

/// Create a mock TD report from the provided quote data
///
/// This function parses the quote and extracts the necessary fields
/// to construct a TD report structure that matches the quote data.
///
/// # Arguments
/// * `quote_data` - The quote data to parse (can be from QUOTE constant or custom file)
pub fn create_mock_td_report(quote_data: &[u8]) -> TdxReport {
    debug!(
        "Creating mock TD report from quote data ({} bytes)",
        quote_data.len()
    );

    // Parse the quote header
    let (body_offset, body_size, header_version, tee_type) = match parse_quote_header(&quote_data) {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to parse quote header: {}", e);
            panic!("Invalid quote header");
        }
    };

    debug!(
        "Quote header - version: {}, tee_type: 0x{:02x}",
        header_version, tee_type
    );

    // Parse quote body
    let (report_body, servtd_hash) =
        match parse_quote_body(&quote_data, body_offset, body_size, header_version) {
            Ok(result) => result,
            Err(e) => {
                log::error!("Failed to parse quote body: {}", e);
                panic!("Invalid quote body");
            }
        };

    // Create TD report with values from parsed quote body
    let tee_tcb_info = TeeTcbInfo {
        valid: [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        tee_tcb_svn: report_body.tee_tcb_svn,
        mrseam: report_body.mr_seam,
        mrsigner_seam: report_body.mrsigner_seam,
        attributes: report_body.seam_attributes,
        tee_tcb_svn2: [0u8; 16],
        reserved: [0u8; 95],
    };

    let td_info = TdInfo {
        attributes: report_body.td_attributes,
        xfam: report_body.xfam,
        mrtd: report_body.mr_td,
        mrconfig_id: report_body.mr_config_id,
        mrowner: report_body.mr_owner,
        mrownerconfig: report_body.mr_owner_config,
        rtmr0: report_body.rt_mr[0],
        rtmr1: report_body.rt_mr[1],
        rtmr2: report_body.rt_mr[2],
        rtmr3: report_body.rt_mr[3],
        servtd_hash: servtd_hash,
        reserved: [0u8; 64],
    };

    // Compute SHA384 hashes of td_info and tee_tcb_info for report_mac integrity
    let tee_tcb_info_hash: [u8; 48] = Sha384::digest(tee_tcb_info.as_bytes()).into();
    let tee_info_hash: [u8; 48] = Sha384::digest(td_info.as_bytes()).into();

    let td_report = TdxReport {
        report_mac: ReportMac {
            report_type: ReportType {
                r#type: tee_type as u8,
                subtype: 0x00,
                version: header_version as u8,
                reserved: 0x00,
            },
            reserved0: [0u8; 12],
            cpu_svn: report_body.tee_tcb_svn,
            tee_tcb_info_hash,
            tee_info_hash,
            report_data: report_body.report_data,
            reserved1: [0u8; 32],
            mac: [0xBB; 32], // Mock MAC, not used for policy tests
        },
        tee_tcb_info,
        reserved: [0u8; 17],
        td_info,
    };

    debug!("Mock TD report created successfully from quote file");

    td_report
}
