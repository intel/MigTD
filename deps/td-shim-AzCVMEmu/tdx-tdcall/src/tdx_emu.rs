// Copyright (c) 2020-2025 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TDX emulation for MigTD operations in AzCVMEmu mode
//!
//! This module provides comprehensive emulation for TDX operations including:
//! - TDVMCALL MigTD functions (waitforrequest, reportstatus, send, receive)
//! - TDCALL ServTD functions (rd, wr)
//! - TDCALL SYS functions (rd, wr)
//! - TCP-based networking for communication between source and destination instances

use alloc::string::String;
use alloc::vec::Vec;
use lazy_static::lazy_static;
use log::{error, warn};
// Use interrupt-emu to fire callbacks registered by upper layers.
use interrupt_emu as intr;
use original_tdx_tdcall::tdx::ServtdRWResult;
use original_tdx_tdcall::{TdCallError, TdVmcallError};
use spin::Mutex;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// TCP emulation mode for MigTD
#[derive(Debug, Clone)]
pub enum TcpEmulationMode {
    Client, // Source - connects to destination
    Server, // Destination - listens for connections
}

lazy_static! {
    /// Global TCP address for emulation
    static ref TCP_ADDRESS: Mutex<Option<String>> = Mutex::new(None);
    /// Global TCP mode for emulation
    static ref TCP_MODE: Mutex<Option<TcpEmulationMode>> = Mutex::new(None);
    /// Connected TCP stream for data exchange
    static ref TCP_STREAM: Mutex<Option<TcpStream>> = Mutex::new(None);
    /// Emulated pending migration request info for waitforrequest
    static ref MIG_REQUEST: Mutex<Vec<EmuMigRequest>> = Mutex::new(Vec::new());
    /// Emulated MSK/TDCS field storage keyed by (binding_handle, target_uuid, field_identifier)
    static ref MSK_FIELDS: Mutex<HashMap<(u64, [u64;4], u64), u64>> = Mutex::new(HashMap::new());
    /// Emulated global-scope SYS fields keyed by field_identifier
    static ref SYS_FIELDS: Mutex<HashMap<u64, u64>> = Mutex::new(HashMap::new());
    /// Emulated td-scope metadata fields keyed by field_identifier
    static ref VM_FIELDS: Mutex<HashMap<u64, u64>> = Mutex::new(HashMap::new());
    /// Emulated rebind-session-token
    static ref REBIND_SESSION_TOKEN: Mutex<HashMap<(u64, [u64; 4]), [u8; 32]>> = Mutex::new(HashMap::new());
    /// Event notification vector for GetQuote completion
    static ref EVENT_NOTIFY_VECTOR: Mutex<Option<u64>> = Mutex::new(None);
    /// Pending receive buffer for large transfers that span multiple GHCI transactions
    static ref PENDING_RECV_BUFFER: Mutex<Option<Vec<u8>>> = Mutex::new(None);
}

/// Emulated migration request info used by tdvmcall_migtd_waitforrequest
#[derive(Clone, Debug)]
pub enum EmuMigRequest {
    StartMigration {
        request_id: u64,
        migration_source: u8,
        target_td_uuid: [u64; 4],
        binding_handle: u64,
    },
    GetReportData {
        request_id: u64,
        reportdata: [u8; 64],
    },
    EnableLogArea {
        request_id: u64,
        log_max_level: u8,
    },
}

impl Default for EmuMigRequest {
    fn default() -> Self {
        EmuMigRequest::StartMigration {
            request_id: 0,
            migration_source: 0,
            target_td_uuid: [0; 4],
            binding_handle: 0,
        }
    }
}

/// Seed the emulation layer with a pending migration request returned by waitforrequest
pub fn set_emulated_mig_request(req: EmuMigRequest) {
    MIG_REQUEST.lock().push(req);
}

/// Helper: Set a complete migration flow with EnableLogArea, GetReportData, and StartMigration
/// Automatically queues all three requests in sequence
/// Uses request_id for migration, request_id | 0x8000_0000_0000_0000 for EnableLogArea,
/// and request_id | 0x4000_0000_0000_0000 for GetReportData
pub fn set_emulated_start_migration(
    request_id: u64,
    migration_source: u8,
    target_td_uuid: [u64; 4],
    binding_handle: u64,
) {
    // Use different bit markers to distinguish each request type
    let enable_log_request_id = request_id | 0x8000_0000_0000_0000; // High bit for EnableLogArea
    let get_report_request_id = request_id | 0x4000_0000_0000_0000; // Second-high bit for GetReportData

    // Step 1: Queue EnableLogArea with Info level (3)
    set_emulated_mig_request(EmuMigRequest::EnableLogArea {
        request_id: enable_log_request_id,
        log_max_level: 3,
    });

    // Step 2: Queue GetReportData with default reportdata
    let mut reportdata = [0u8; 64];
    reportdata[0..8].copy_from_slice(&request_id.to_le_bytes());
    reportdata[8..23].copy_from_slice(b"MIGTD_MIGRATION"); // 15 bytes
    reportdata[23] = 0; // Null terminator
    set_emulated_mig_request(EmuMigRequest::GetReportData {
        request_id: get_report_request_id,
        reportdata,
    });

    // Step 3: Queue the StartMigration request with original request_id
    set_emulated_mig_request(EmuMigRequest::StartMigration {
        request_id,
        migration_source,
        target_td_uuid,
        binding_handle,
    });
}

/// Helper: Set a GetReportData request
/// Automatically queues EnableLogArea request first, then the report request
/// Uses request_id for report, and request_id | 0x8000_0000_0000_0000 for EnableLogArea
pub fn set_emulated_get_report_data(request_id: u64, reportdata: [u8; 64]) {
    // Use high-bit set for EnableLogArea to distinguish from main request
    let enable_log_request_id = request_id | 0x8000_0000_0000_0000;

    // First, queue EnableLogArea with Info level (3) and distinct request_id
    set_emulated_mig_request(EmuMigRequest::EnableLogArea {
        request_id: enable_log_request_id,
        log_max_level: 3,
    });

    // Then queue the GetReportData request with original request_id
    set_emulated_mig_request(EmuMigRequest::GetReportData {
        request_id,
        reportdata,
    });
}

/// Helper: Set an EnableLogArea request
pub fn set_emulated_enable_log_area(request_id: u64, log_max_level: u8) {
    set_emulated_mig_request(EmuMigRequest::EnableLogArea {
        request_id,
        log_max_level,
    });
}

/// Set TCP address and mode for emulation
pub fn init_tcp_emulation_with_mode(
    ip: &str,
    port: u16,
    mode: TcpEmulationMode,
) -> Result<(), &'static str> {
    let tcp_addr = format!("{}:{}", ip, port);

    // Validate IP address format (basic validation)
    if ip.is_empty() {
        return Err("IP address cannot be empty");
    }

    // Initialize VMM-side log area manager
    crate::logging_emu::init_log_area_manager();

    // Set the TCP configuration
    {
        let mut addr = TCP_ADDRESS.lock();
        *addr = Some(tcp_addr.clone());
    }
    {
        let mut tcp_mode = TCP_MODE.lock();
        *tcp_mode = Some(mode.clone());
    }

    match mode {
        TcpEmulationMode::Server => {
            // Server mode setup
        }
        TcpEmulationMode::Client => {
            // Client mode setup
        }
    }

    Ok(())
}

/// Start TCP server for destination instances (blocking call)
pub fn start_tcp_server_sync(addr: &str) -> Result<(), TdVmcallError> {
    let listener = TcpListener::bind(addr).map_err(|e| {
        error!("Failed to bind TCP listener to {}: {}", addr, e);
        TdVmcallError::Other
    })?;

    // Accept the first connection and store it globally
    let (stream, _peer_addr) = listener.accept().map_err(|e| {
        error!("Failed to accept TCP connection: {}", e);
        TdVmcallError::Other
    })?;

    // Store the stream globally for send/receive operations
    {
        let mut tcp_stream = TCP_STREAM.lock();
        *tcp_stream = Some(stream);
    }

    Ok(())
}

/// Establish TCP connection for client mode
pub fn connect_tcp_client() -> Result<(), TdVmcallError> {
    let addr = {
        let tcp_addr = TCP_ADDRESS.lock();
        match tcp_addr.as_ref() {
            Some(addr) => addr.clone(),
            None => {
                error!("TCP address not configured. Please set address before connecting.");
                return Err(TdVmcallError::Other);
            }
        }
    };

    let stream = TcpStream::connect(&addr).map_err(|e| {
        error!("Failed to connect to TCP server at {}: {}", addr, e);
        TdVmcallError::Other
    })?;

    // Store the stream globally for send/receive operations
    {
        let mut tcp_stream = TCP_STREAM.lock();
        *tcp_stream = Some(stream);
    }

    Ok(())
}

/// Send raw data over TCP connection
pub fn tcp_send_data(data: &[u8]) -> Result<(), TdVmcallError> {
    let mut stream_guard = TCP_STREAM.lock();
    let stream = stream_guard.as_mut().ok_or_else(|| {
        error!("No TCP connection available for sending data");
        TdVmcallError::Other
    })?;

    // Send data length first (4 bytes, little endian)
    let length = data.len() as u32;
    let len_bytes = length.to_le_bytes();
    stream.write_all(&len_bytes).map_err(|e| {
        error!("Failed to write length header: {}", e);
        TdVmcallError::Other
    })?;

    // Send raw data
    stream.write_all(data).map_err(|e| {
        error!("Failed to write data payload: {}", e);
        TdVmcallError::Other
    })?;

    stream.flush().map_err(|e| {
        error!("Failed to flush TCP stream: {}", e);
        TdVmcallError::Other
    })?;

    Ok(())
}

/// Receive raw data from TCP connection
pub fn tcp_receive_data() -> Result<Vec<u8>, TdVmcallError> {
    {
        let mut pending = PENDING_RECV_BUFFER.lock();
        if pending.is_some() {
            log::warn!("TCP: Clearing stale pending receive buffer");
            *pending = None;
        }
    }

    let mut stream_guard = TCP_STREAM.lock();
    let stream = stream_guard.as_mut().ok_or_else(|| {
        error!("No TCP connection available for receiving data");
        TdVmcallError::Other
    })?;

    // Read data length first (4 bytes, little endian)
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes).map_err(|e| {
        error!("Failed to read length header: {}", e);
        TdVmcallError::Other
    })?;

    let length = u32::from_le_bytes(length_bytes) as usize;

    // Read raw data
    let mut buffer = vec![0u8; length];
    stream.read_exact(&mut buffer).map_err(|e| {
        error!("Failed to read data payload: {}", e);
        TdVmcallError::Other
    })?;

    Ok(buffer)
}

/// Receive a chunk of data that fits within a GHCI buffer
fn tcp_receive_data_chunk(max_chunk_size: usize) -> Result<Vec<u8>, TdVmcallError> {
    let mut pending = PENDING_RECV_BUFFER.lock();

    if let Some(mut pending_data) = pending.take() {
        if pending_data.len() <= max_chunk_size {
            return Ok(pending_data);
        } else {
            let chunk = pending_data.drain(..max_chunk_size).collect::<Vec<u8>>();
            *pending = Some(pending_data);
            return Ok(chunk);
        }
    }

    drop(pending);
    let full_data = tcp_receive_data()?;

    if full_data.len() <= max_chunk_size {
        return Ok(full_data);
    }

    let mut data = full_data;
    let chunk = data.drain(..max_chunk_size).collect::<Vec<u8>>();

    let mut pending = PENDING_RECV_BUFFER.lock();
    *pending = Some(data);

    Ok(chunk)
}

/// Helper function to parse GHCI 1.5 buffer format
fn parse_ghci_buffer(buffer: &[u8]) -> (u64, u32, &[u8]) {
    if buffer.len() < 12 {
        return (0, 0, &[]);
    }

    let status = u64::from_le_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]);
    let length = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
    let max_payload_len = (buffer.len() - 12).min(length as usize);
    let payload = &buffer[12..12 + max_payload_len];

    (status, length, payload)
}

/// Helper function to format GHCI 1.5 buffer format
fn format_ghci_buffer(buffer: &mut [u8], status: u64, payload: &[u8]) {
    if buffer.len() < 12 {
        error!("GHCI buffer too small: need at least 12 bytes for header");
        return;
    }

    // Compute how much we can actually copy into the caller-provided buffer.
    let copy_len = (buffer.len() - 12).min(payload.len());

    if copy_len < payload.len() {
        error!(
            "GHCI buffer payload truncated: have space={} wanted={}",
            buffer.len() - 12,
            payload.len()
        );
    }

    // Write status (8 bytes) and the ACTUAL length we copied (4 bytes)
    let status_bytes = status.to_le_bytes();
    let length_bytes = (copy_len as u32).to_le_bytes();

    buffer[0..8].copy_from_slice(&status_bytes);
    buffer[8..12].copy_from_slice(&length_bytes);

    if copy_len > 0 {
        buffer[12..12 + copy_len].copy_from_slice(&payload[..copy_len]);
    }
}

/// TCP emulation for tdvmcall_migtd_send
pub fn tdvmcall_migtd_send_sync(
    _mig_request_id: u64,
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {
    // Parse GHCI 1.5 buffer format to extract payload
    let (_status, _length, payload) = parse_ghci_buffer(data_buffer);

    // Send payload over TCP
    tcp_send_data(payload)?;

    // Update buffer to indicate success (status = 1, no payload response for send)
    format_ghci_buffer(data_buffer, 1, &[]);

    // Read log entries from log area (VMM side behavior)
    crate::logging_emu::read_log_entries();

    // Trigger the registered interrupt callback to emulate VMM signaling
    intr::trigger(interrupt);
    Ok(())
}

/// TCP emulation for tdvmcall_migtd_receive
pub fn tdvmcall_migtd_receive_sync(
    _mig_request_id: u64,
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {
    if data_buffer.len() < 12 {
        error!(
            "GHCI buffer too small for receive: need at least 12 bytes, got {}",
            data_buffer.len()
        );
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    let max_payload_size = data_buffer.len() - 12;

    let received_payload = tcp_receive_data_chunk(max_payload_size)?;

    format_ghci_buffer(data_buffer, 1, &received_payload);

    // Read log entries from log area (VMM side behavior)
    crate::logging_emu::read_log_entries();

    intr::trigger(interrupt);
    Ok(())
}

/// TCP emulation for tdvmcall_migtd_waitforrequest
pub fn tdvmcall_migtd_waitforrequest(
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {
    // data_buffer uses the GHCI 1.5 buffer format:
    // Bytes 0-7: status (u64) - filled by VMM/emulation
    //   byte[0] = 1 (TDX_VMCALL_VMM_SUCCESS)
    //   byte[1] = operation type (1=StartMigration, 3=GetReportData, 4=EnableLogArea)
    // Bytes 8-11: length (u32) - filled by VMM/emulation
    // Bytes 12+: Request-specific payload

    const HEADER_LEN: usize = 12; // GHCI 1.5 header: 8-byte status + 4-byte length
    const START_MIGRATION_PAYLOAD_LEN: usize = 56; // MigtdMigrationInformation size
    const REPORT_DATA_PAYLOAD_LEN: usize = 72; // ReportInfo size (8 + 64)
    const ENABLE_LOG_AREA_PAYLOAD_LEN: usize = 16; // EnableLogAreaInfo size (8 + 1 + 7 reserved)

    // Take the first emulated request from the queue; if none, do not signal and let caller poll again
    let maybe_req = {
        let mut g = MIG_REQUEST.lock();
        if g.is_empty() {
            None
        } else {
            Some(g.remove(0))
        }
    };

    if let Some(req) = maybe_req {
        match req {
            EmuMigRequest::StartMigration {
                request_id,
                migration_source,
                target_td_uuid,
                binding_handle,
            } => {
                // DataStatusOperation::StartMigration = 1
                let status = 0x0000_0000_0000_0101u64; // byte[0]=1 (success), byte[1]=1 (StartMigration)
                let length = START_MIGRATION_PAYLOAD_LEN as u32;

                if data_buffer.len() < HEADER_LEN + START_MIGRATION_PAYLOAD_LEN {
                    error!(
                        "waitforrequest buffer too small for StartMigration: have={} need={}",
                        data_buffer.len(),
                        HEADER_LEN + START_MIGRATION_PAYLOAD_LEN
                    );
                    return Err(TdVmcallError::Other);
                }

                data_buffer[0..8].copy_from_slice(&status.to_le_bytes());
                data_buffer[8..12].copy_from_slice(&length.to_le_bytes());

                // Fill MigtdMigrationInformation payload
                let payload =
                    &mut data_buffer[HEADER_LEN..HEADER_LEN + START_MIGRATION_PAYLOAD_LEN];

                // mig_request_id
                payload[0..8].copy_from_slice(&request_id.to_le_bytes());
                // migration_source
                payload[8] = migration_source;
                // _pad [7 bytes]
                for b in &mut payload[9..16] {
                    *b = 0;
                }
                // target_td_uuid [u64; 4] - 32 bytes
                let mut off = 16usize;
                for v in target_td_uuid.iter() {
                    payload[off..off + 8].copy_from_slice(&v.to_le_bytes());
                    off += 8;
                }
                // binding_handle
                payload[48..56].copy_from_slice(&binding_handle.to_le_bytes());

                log::info!(
                    "tdvmcall_migtd_waitforrequest: StartMigration request_id={} source={}",
                    request_id,
                    migration_source
                );
            }
            EmuMigRequest::GetReportData {
                request_id,
                reportdata,
            } => {
                // DataStatusOperation::GetReportData = 3
                let status = 0x0000_0000_0000_0301u64; // byte[0]=1 (success), byte[1]=3 (GetReportData)
                let length = REPORT_DATA_PAYLOAD_LEN as u32;

                if data_buffer.len() < HEADER_LEN + REPORT_DATA_PAYLOAD_LEN {
                    error!(
                        "waitforrequest buffer too small for GetReportData: have={} need={}",
                        data_buffer.len(),
                        HEADER_LEN + REPORT_DATA_PAYLOAD_LEN
                    );
                    return Err(TdVmcallError::Other);
                }

                data_buffer[0..8].copy_from_slice(&status.to_le_bytes());
                data_buffer[8..12].copy_from_slice(&length.to_le_bytes());

                // Fill ReportInfo payload
                let payload = &mut data_buffer[HEADER_LEN..HEADER_LEN + REPORT_DATA_PAYLOAD_LEN];

                // mig_request_id
                payload[0..8].copy_from_slice(&request_id.to_le_bytes());
                // reportdata [u8; 64]
                payload[8..72].copy_from_slice(&reportdata);

                log::info!(
                    "tdvmcall_migtd_waitforrequest: GetReportData request_id={} reportdata[0..8]={:02x?}",
                    request_id, &reportdata[0..8]
                );
            }
            EmuMigRequest::EnableLogArea {
                request_id,
                log_max_level,
            } => {
                // DataStatusOperation::EnableLogArea = 4
                let status = 0x0000_0000_0000_0401u64; // byte[0]=1 (success), byte[1]=4 (EnableLogArea)
                let length = ENABLE_LOG_AREA_PAYLOAD_LEN as u32;

                if data_buffer.len() < HEADER_LEN + ENABLE_LOG_AREA_PAYLOAD_LEN {
                    error!(
                        "waitforrequest buffer too small for EnableLogArea: have={} need={}",
                        data_buffer.len(),
                        HEADER_LEN + ENABLE_LOG_AREA_PAYLOAD_LEN
                    );
                    return Err(TdVmcallError::Other);
                }

                data_buffer[0..8].copy_from_slice(&status.to_le_bytes());
                data_buffer[8..12].copy_from_slice(&length.to_le_bytes());

                // Fill EnableLogAreaInfo payload
                let payload =
                    &mut data_buffer[HEADER_LEN..HEADER_LEN + ENABLE_LOG_AREA_PAYLOAD_LEN];

                // mig_request_id
                payload[0..8].copy_from_slice(&request_id.to_le_bytes());
                // log_max_level
                payload[8] = log_max_level;
                // reserved [7 bytes]
                for b in &mut payload[9..16] {
                    *b = 0;
                }

                log::info!(
                    "tdvmcall_migtd_waitforrequest: EnableLogArea request_id={} log_max_level={}",
                    request_id,
                    log_max_level
                );
            }
        }

        // Signal completion via interrupt
        intr::trigger(interrupt);
        Ok(())
    } else {
        // No pending request yet; do not signal. Caller will poll again.
        Ok(())
    }
}

/// TCP emulation for tdvmcall_migtd_reportstatus  
pub fn tdvmcall_migtd_reportstatus(
    mig_request_id: u64,
    reportstatus: u64,
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {
    // Extract pre_migration_status from the reportstatus bitfield (lower byte)
    let pre_migration_status = (reportstatus & 0xFF) as u8;

    log::info!(
        "tdvmcall_migtd_reportstatus: request_id={} status={} interrupt=0x{:02x}",
        mig_request_id,
        pre_migration_status,
        interrupt
    );

    // Parse current buffer data to see what's being reported
    let (_status, length, payload_slice) = parse_ghci_buffer(data_buffer);

    log::info!(
        "tdvmcall_migtd_reportstatus: data_buffer length={}, payload length={}",
        data_buffer.len(),
        length
    );

    // Clone the payload to avoid borrow issues
    let payload_copy = payload_slice.to_vec();

    if length > 0 && payload_copy.len() > 0 {
        // Log information about the payload being returned
        let display_len = core::cmp::min(payload_copy.len(), 64);
        log::info!(
            "tdvmcall_migtd_reportstatus: returning {} bytes of data (first {} bytes): {:02x?}",
            payload_copy.len(),
            display_len,
            &payload_copy[0..display_len]
        );

        // Check if this is EnableLogArea response by examining the request_id
        // EnableLogArea uses high bit set (0x8000_0000_0000_0000) as a marker
        if (mig_request_id & 0x8000_0000_0000_0000) != 0 {
            // This is an EnableLogArea response
            log::info!(
                "tdvmcall_migtd_reportstatus: EnableLogArea response detected (request_id has high bit set)"
            );
            if pre_migration_status == 0 && payload_copy.len() >= 8 {
                // Status 0 = success, validate payload format
                let num_vcpus = u32::from_le_bytes(payload_copy[0..4].try_into().unwrap());
                let expected_len = 8 + (num_vcpus as usize * 16);
                if payload_copy.len() >= expected_len {
                    log::info!(
                        "tdvmcall_migtd_reportstatus: EnableLogArea payload valid ({} vCPUs)",
                        num_vcpus
                    );
                    // Initialize VMM-side log area manager with the buffer addresses
                    crate::logging_emu::enable_log_area(&payload_copy);
                } else {
                    log::warn!(
                        "tdvmcall_migtd_reportstatus: EnableLogArea payload size mismatch (expected {}, got {})",
                        expected_len,
                        payload_copy.len()
                    );
                }
            } else if pre_migration_status != 0 {
                log::warn!(
                    "tdvmcall_migtd_reportstatus: EnableLogArea failed with status {}",
                    pre_migration_status
                );
            }
        } else if (mig_request_id & 0x4000_0000_0000_0000) != 0 {
            // This is a GetReportData response (second-high bit set)
            log::info!(
                "tdvmcall_migtd_reportstatus: GetReportData response detected (request_id has second-high bit set)"
            );

            // If it looks like a TD report (1024 bytes), show some key fields
            if payload_copy.len() >= 1024 {
                log::info!("tdvmcall_migtd_reportstatus: TD report detected (1024 bytes)");
                // Report type is at offset 0
                log::info!("  Report type: 0x{:02x}", payload_copy[0]);
                // Report data is at offset 112 (after MAC)
                if payload_copy.len() >= 176 {
                    log::info!(
                        "  Report data (first 32 bytes): {:02x?}",
                        &payload_copy[112..144]
                    );
                }
            }
        } else {
            // This is a migration or report request response (high bit not set)
            log::info!(
                "tdvmcall_migtd_reportstatus: Migration/Report request response (request_id={})",
                mig_request_id
            );

            // If it looks like a TD report (1024 bytes), show some key fields
            if payload_copy.len() >= 1024 {
                log::info!("tdvmcall_migtd_reportstatus: TD report detected (1024 bytes)");
                // Report type is at offset 0
                log::info!("  Report type: 0x{:02x}", payload_copy[0]);
                // Report data is at offset 112 (after MAC)
                if payload_copy.len() >= 176 {
                    log::info!(
                        "  Report data (first 32 bytes): {:02x?}",
                        &payload_copy[112..144]
                    );
                }
            }
        }
    } else {
        log::info!("tdvmcall_migtd_reportstatus: no payload data (empty response)");
    }

    // Read log entries from log area (VMM side behavior)
    // This is triggered on every report_status call
    crate::logging_emu::read_log_entries();

    // For now, we'll simulate a successful status report
    // In a real implementation, this could send status over TCP if needed

    // Update buffer with success status (preserve the existing payload)
    format_ghci_buffer(data_buffer, 1, &payload_copy); // Status 1 = success

    // Emulate VMM signaling back to the TD that reportstatus completed
    log::info!(
        "tdvmcall_migtd_reportstatus: triggering interrupt 0x{:02x}",
        interrupt
    );
    intr::trigger(interrupt);
    Ok(())
}

/// Emulation for TDG.SERVTD.RD: read a metadata field of a target TD
pub fn tdcall_servtd_rd(
    binding_handle: u64,
    field_identifier: u64,
    target_td_uuid: &[u64],
) -> Result<ServtdRWResult, TdCallError> {
    if target_td_uuid.len() != 4 {
        return Err(TdCallError::TdxExitInvalidParameters);
    }

    let key = (
        binding_handle,
        [
            target_td_uuid[0],
            target_td_uuid[1],
            target_td_uuid[2],
            target_td_uuid[3],
        ],
        field_identifier,
    );
    let val = MSK_FIELDS.lock().get(&key).copied().unwrap_or(0);
    warn!(
        "AzCVMEmu: tdcall_servtd_rd emulated: bh=0x{:x} field=0x{:x} uuid=[{:x},{:x},{:x},{:x}] => 0x{:x}",
        binding_handle, field_identifier, key.1[0], key.1[1], key.1[2], key.1[3], val
    );
    Ok(ServtdRWResult {
        content: val,
        uuid: key.1,
    })
}

/// Emulation for TDG.SERVTD.WR: write a metadata field of a target TD
pub fn tdcall_servtd_wr(
    binding_handle: u64,
    field_identifier: u64,
    data: u64,
    target_td_uuid: &[u64],
) -> Result<ServtdRWResult, TdCallError> {
    if target_td_uuid.len() != 4 {
        return Err(TdCallError::TdxExitInvalidParameters);
    }

    let key = (
        binding_handle,
        [
            target_td_uuid[0],
            target_td_uuid[1],
            target_td_uuid[2],
            target_td_uuid[3],
        ],
        field_identifier,
    );
    warn!(
        "AzCVMEmu: tdcall_servtd_wr emulated: bh=0x{:x} field=0x{:x} uuid=[{:x},{:x},{:x},{:x}] <= 0x{:x}",
        binding_handle, field_identifier, key.1[0], key.1[1], key.1[2], key.1[3], data
    );
    MSK_FIELDS.lock().insert(key, data);
    Ok(ServtdRWResult {
        content: data,
        uuid: key.1,
    })
}

/// Emulation for TDG.SYS.RD: read a global-scope metadata field
pub fn tdcall_sys_rd(field_identifier: u64) -> core::result::Result<(u64, u64), TdCallError> {
    // If a value was previously written via tdcall_sys_wr, return it.
    if let Some(v) = SYS_FIELDS.lock().get(&field_identifier).copied() {
        warn!(
            "AzCVMEmu: tdcall_sys_rd emulated (stored): field=0x{:x} => 0x{:x}",
            field_identifier, v
        );
        return Ok((field_identifier, v));
    }

    // Provide sane defaults for min/max import/export versions; others return 0.
    // Caller expects (rdx=field_identifier, r8=value).
    const DEFAULT_MIN_VER: u64 = 1;
    const DEFAULT_MAX_VER: u64 = 1;
    let val = match field_identifier & 0xF {
        1 | 3 => DEFAULT_MIN_VER,
        2 | 4 => DEFAULT_MAX_VER,
        _ => 0,
    };
    warn!(
        "AzCVMEmu: tdcall_sys_rd emulated (default): field=0x{:x} => 0x{:x}",
        field_identifier, val
    );
    Ok((field_identifier, val))
}

/// Emulation for TDG.SYS.WR: write a global-scope metadata field
pub fn tdcall_sys_wr(field_identifier: u64, value: u64) -> core::result::Result<(), TdCallError> {
    warn!(
        "AzCVMEmu: tdcall_sys_wr emulated: field=0x{:x} <= 0x{:x}",
        field_identifier, value
    );
    SYS_FIELDS.lock().insert(field_identifier, value);
    Ok(())
}

/// Emulation for TDG.VM.WR: write a TD-scope metadata field
pub fn tdcall_vm_write(field_identifier: u64, value: u64, mask: u64) -> Result<u64, TdCallError> {
    warn!(
        "AzCVMEmu: tdcall_vm_write emulated: field=0x{:x} <= 0x{:x}",
        field_identifier, value
    );
    SYS_FIELDS.lock().insert(field_identifier, value);
    Ok(field_identifier)
}

/// Emulation for TDG.SERVTD.REBIND.APPROVE: called by the currently bound service TD to approve
/// a new Service TD to be bound to the target TD.
pub fn tdcall_servtd_rebind_approve(
    old_binding_handle: u64,
    rebind_session_token: &[u8],
    target_td_uuid: &[u64],
) -> Result<[u64; 4], TdCallError> {
    warn!(
        "AzCVMEmu: tdcall_servtd_rebind_approve emulated: old_binding_hanlde=0x{:x} target_td_uuid= 0x{:x?}",
        old_binding_handle, target_td_uuid
    );
    let uuid = [
            target_td_uuid[0],
            target_td_uuid[1],
            target_td_uuid[2],
            target_td_uuid[3],
        ];
    let key = (
        old_binding_handle,
        uuid,
    );
    let mut value = [0u8; 32];
    value.copy_from_slice(&rebind_session_token[..32]);

    REBIND_SESSION_TOKEN.lock().insert(key, value);
    Ok(uuid)
}

/// Emulation for TDG.VP.VMCALL<GetQuote>: Generate TD-Quote using vTPM or return hardcoded collateral
/// This mimics the exact API signature of tdx_tdcall::tdx::tdvmcall_get_quote
///
/// GHCI header (bytes 0-23, 24 bytes total):
///    - Offset 0-7:   Version (u64)
///    - Offset 8-15:  Status (u64)
///    - Offset 16-19: in_len (u32)
///    - Offset 20-23: out_len (u32)
///
/// Starting at offset 24, three scenarios are supported:
///
/// Scenario 1: Legacy quote request (TDREPORT only)
///    - Offset 24+:   TDREPORT (1024 bytes)
///    - in_len = 1024
///
/// Scenario 2: Collateral request (QGS_MSG for collateral)
///    - Offset 24+:   QGS_MSG (starts with 4-byte SERVTD_HEADER + QGS message content)
///    - in_len = QGS_MSG size (typically < 100 bytes)
///
/// Scenario 3: Quote request with QGS header (QGS_MSG + TDREPORT)
///    - Offset 24+:   QGS_MSG (starts with 4-byte SERVTD_HEADER + QGS message content)
///    - Offset N+:    TDREPORT (1024 bytes)
///    - in_len = QGS_MSG size + 1024
pub fn tdvmcall_get_quote(buffer: &mut [u8]) -> Result<(), original_tdx_tdcall::TdVmcallError> {
    use original_tdx_tdcall::TdVmcallError;

    log::info!("AzCVMEmu: tdvmcall_get_quote emulated");

    // TDX GHCI GetQuote buffer format:
    // Offset 0-7:   Version (u64, filled by TD)
    // Offset 8-15:  Status (u64, filled by VMM) - 0=success, 0xFFFFFFFFFFFFFFFF=in_flight
    // Offset 16-19: in_len (u32, filled by TD)
    // Offset 20-23: out_len (u32, filled by TD)
    // Offset 24+:   Data (TDREPORT for quote, or SERVTD_HEADER+QGS_MSG for collateral)

    if buffer.len() < 24 {
        error!("GetQuote buffer too small: need at least 24 bytes for header");
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    // Read in_len to determine the payload size (u32 at offset 16)
    let in_len = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]) as usize;

    if in_len == 0 || buffer.len() < 24 + in_len {
        error!(
            "GetQuote buffer invalid: in_len={} buffer_len={}",
            in_len,
            buffer.len()
        );
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    // Detect request type by checking the payload format:
    // Strategy: Assume QGS header first, validate version and type fields.
    // If validation fails, fall back to pure TDREPORT (legacy) scenario.
    // 1. Pure TDREPORT (1024 bytes): Legacy quote request (fallback)
    // 2. SERVTD_HEADER + QGS_MSG: Parse QGS message type field to distinguish:
    //    - GET_COLLATERAL_REQ (type=2): Collateral request
    //    - GET_QUOTE_REQ (type=0): Quote request with QGS header + TDREPORT
    const SERVTD_HEADER_SIZE: usize = 4;
    const TDREPORT_SIZE: usize = 1024;
    const QGS_MSG_HEADER_SIZE: usize = 16; // qgs_msg_header_t size

    // QGS message types and version from qgs_msg_lib.h
    const GET_QUOTE_REQ: u32 = 0;
    const GET_COLLATERAL_REQ: u32 = 2;
    const QGS_MSG_LIB_MAJOR_VER: u16 = 1;
    const QGS_MSG_LIB_MINOR_VER: u16 = 1;

    // Try to parse as QGS message with SERVTD_HEADER
    // Check if we have enough data for SERVTD_HEADER + QGS message header
    if buffer.len() >= 24 + SERVTD_HEADER_SIZE + QGS_MSG_HEADER_SIZE {
        // Parse SERVTD_HEADER to get QGS message size (big-endian)
        let qgs_msg_size =
            u32::from_be_bytes([buffer[24], buffer[25], buffer[26], buffer[27]]) as usize;

        // Parse QGS message header to get version and type fields
        // qgs_msg_header_t starts at offset 28 (after SERVTD_HEADER at 24-27):
        //   Offset 28-29: major_version (u16)
        //   Offset 30-31: minor_version (u16)
        //   Offset 32-35: type (u32)
        //   Offset 36-39: size (u32)
        //   Offset 40-43: error_code (u32)
        let qgs_major_version = u16::from_le_bytes([buffer[28], buffer[29]]);
        let qgs_minor_version = u16::from_le_bytes([buffer[30], buffer[31]]);
        let qgs_msg_type = u32::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35]]);

        // Validate QGS message version and type
        // If they match expected values, treat as QGS message
        // Otherwise, fall back to pure TDREPORT scenario
        let is_valid_qgs_version = qgs_major_version == QGS_MSG_LIB_MAJOR_VER
            && qgs_minor_version == QGS_MSG_LIB_MINOR_VER;
        let is_valid_qgs_type = qgs_msg_type == GET_QUOTE_REQ || qgs_msg_type == GET_COLLATERAL_REQ;

        if is_valid_qgs_version && is_valid_qgs_type {
            // Valid QGS message detected
            log::info!(
                "AzCVMEmu: QGS message detected - version={}.{}, type={}, msg_size={}",
                qgs_major_version,
                qgs_minor_version,
                qgs_msg_type,
                qgs_msg_size
            );

            match qgs_msg_type {
                GET_COLLATERAL_REQ => {
                    // Collateral request - just QGS message, no TDREPORT
                    log::info!(
                        "AzCVMEmu: GET_COLLATERAL_REQ detected, returning hardcoded collateral"
                    );
                    return handle_collateral_request(buffer, in_len);
                }
                GET_QUOTE_REQ => {
                    // Quote request with QGS header - QGS message followed by TDREPORT
                    log::info!("AzCVMEmu: GET_QUOTE_REQ detected, generating quote using vTPM");
                    return handle_quote_request(buffer, in_len, true);
                }
                _ => {
                    // Should not reach here due to is_valid_qgs_type check
                    error!("AzCVMEmu: Unexpected QGS message type: {}", qgs_msg_type);
                    let error_status = 0x8000000000000000u64;
                    buffer[8..16].copy_from_slice(&error_status.to_le_bytes());
                    return Err(TdVmcallError::VmcallOperandInvalid);
                }
            }
        } else {
            // Invalid QGS header - fall back to pure TDREPORT scenario
            log::info!(
                "AzCVMEmu: QGS header validation failed (version={}.{}, type={}), treating as pure TDREPORT",
                qgs_major_version,
                qgs_minor_version,
                qgs_msg_type
            );
        }
    }

    // Fall back to pure TDREPORT - legacy quote request
    log::info!(
        "AzCVMEmu: Detected legacy quote request (pure TDREPORT), generating quote using vTPM"
    );
    handle_quote_request(buffer, in_len, false)
}

/// Handle collateral request by returning hardcoded collateral data
fn handle_collateral_request(
    buffer: &mut [u8],
    _in_len: usize,
) -> Result<(), original_tdx_tdcall::TdVmcallError> {
    use original_tdx_tdcall::TdVmcallError;

    // Use the hardcoded collateral data from collateral_data module
    // This data is a PackedCollateral structure:
    // - First 20 bytes: header with size fields (u16 version, various u32 sizes)
    // - Remaining bytes: actual collateral data (certificates, CRLs, TCB info)
    let collateral = crate::collateral_data::HARDCODED_COLLATERAL;

    // The collateral data format from config/collateral_production_fmspc.json:
    // struct PackedCollateral {
    //     u16 major_version;           // offset 0-1
    //     u16 minor_version;           // offset 2-3
    //     u32 pck_crl_issuer_chain_size;    // offset 4-7
    //     u32 root_ca_crl_size;             // offset 8-11
    //     u32 pck_crl_size;                 // offset 12-15
    //     u32 tcb_info_issuer_chain_size;   // offset 16-19
    //     u32 tcb_info_size;                // offset 20-23
    //     u32 qe_identity_issuer_chain_size; // offset 24-27
    //     u32 qe_identity_size;             // offset 28-31
    //     u8[] data;                        // offset 32+
    // }
    const PACKED_COLLATERAL_HEADER_SIZE: usize = 32;

    if collateral.len() < PACKED_COLLATERAL_HEADER_SIZE {
        error!("Collateral data too small: {} bytes", collateral.len());
        let error_status = 0x8000000000000000u64;
        buffer[8..16].copy_from_slice(&error_status.to_le_bytes());
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    // Extract PackedCollateral header fields (little-endian)
    let major_version = u16::from_le_bytes([collateral[0], collateral[1]]);
    let minor_version = u16::from_le_bytes([collateral[2], collateral[3]]);
    let pck_crl_issuer_chain_size =
        u32::from_le_bytes([collateral[4], collateral[5], collateral[6], collateral[7]]);
    let root_ca_crl_size =
        u32::from_le_bytes([collateral[8], collateral[9], collateral[10], collateral[11]]);
    let pck_crl_size = u32::from_le_bytes([
        collateral[12],
        collateral[13],
        collateral[14],
        collateral[15],
    ]);
    let tcb_info_issuer_chain_size = u32::from_le_bytes([
        collateral[16],
        collateral[17],
        collateral[18],
        collateral[19],
    ]);
    let tcb_info_size = u32::from_le_bytes([
        collateral[20],
        collateral[21],
        collateral[22],
        collateral[23],
    ]);
    let qe_identity_issuer_chain_size = u32::from_le_bytes([
        collateral[24],
        collateral[25],
        collateral[26],
        collateral[27],
    ]);
    let qe_identity_size = u32::from_le_bytes([
        collateral[28],
        collateral[29],
        collateral[30],
        collateral[31],
    ]);

    let collaterals_data = &collateral[PACKED_COLLATERAL_HEADER_SIZE..];

    // Build GetCollateralResponse structure:
    // struct MsgHeader {        // 16 bytes
    //     u16 major_version;    // offset 0-1
    //     u16 minor_version;    // offset 2-3
    //     u32 type_;            // offset 4-7
    //     u32 size;             // offset 8-11
    //     u32 error_code;       // offset 12-15
    // }
    // struct GetCollateralResponse {
    //     MsgHeader header;     // 16 bytes
    //     u16 major_version;    // 16-17
    //     u16 minor_version;    // 18-19
    //     ... size fields ...   // 20-47 (7 * u32)
    //     u8[] collaterals;     // 48+
    // }
    const MSG_HEADER_SIZE: usize = 16;
    const GET_COLLATERAL_RESPONSE_HEADER: usize = 48; // MsgHeader + version fields + size fields
    const SERVTD_HEADER_SIZE: usize = 4;

    let msg_size = GET_COLLATERAL_RESPONSE_HEADER + collaterals_data.len();
    let total_size = msg_size + 2 * 2; // extra 2*sizeof(u16) as per original implementation
    let out_len = SERVTD_HEADER_SIZE + total_size;

    let data_start = 24;
    if buffer.len() < data_start + out_len {
        error!(
            "Buffer too small for collateral response: need {} bytes, have {}",
            data_start + out_len,
            buffer.len()
        );
        let error_status = 0x8000000000000000u64;
        buffer[8..16].copy_from_slice(&error_status.to_le_bytes());
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    // Write SERVTD_HEADER (4-byte big-endian size)
    buffer[data_start] = ((total_size >> 24) & 0xFF) as u8;
    buffer[data_start + 1] = ((total_size >> 16) & 0xFF) as u8;
    buffer[data_start + 2] = ((total_size >> 8) & 0xFF) as u8;
    buffer[data_start + 3] = (total_size & 0xFF) as u8;

    let rsp_start = data_start + SERVTD_HEADER_SIZE;

    // Write MsgHeader
    buffer[rsp_start..rsp_start + 2].copy_from_slice(&1u16.to_le_bytes()); // major_version = 1
    buffer[rsp_start + 2..rsp_start + 4].copy_from_slice(&0u16.to_le_bytes()); // minor_version = 0
    buffer[rsp_start + 4..rsp_start + 8].copy_from_slice(&3u32.to_le_bytes()); // type_ = 3
    buffer[rsp_start + 8..rsp_start + 12].copy_from_slice(&(total_size as u32).to_le_bytes()); // size
    buffer[rsp_start + 12..rsp_start + 16].copy_from_slice(&0u32.to_le_bytes()); // error_code = 0

    // Write GetCollateralResponse fields
    buffer[rsp_start + 16..rsp_start + 18].copy_from_slice(&major_version.to_le_bytes());
    buffer[rsp_start + 18..rsp_start + 20].copy_from_slice(&minor_version.to_le_bytes());
    buffer[rsp_start + 20..rsp_start + 24]
        .copy_from_slice(&pck_crl_issuer_chain_size.to_le_bytes());
    buffer[rsp_start + 24..rsp_start + 28].copy_from_slice(&root_ca_crl_size.to_le_bytes());
    buffer[rsp_start + 28..rsp_start + 32].copy_from_slice(&pck_crl_size.to_le_bytes());
    buffer[rsp_start + 32..rsp_start + 36]
        .copy_from_slice(&tcb_info_issuer_chain_size.to_le_bytes());
    buffer[rsp_start + 36..rsp_start + 40].copy_from_slice(&tcb_info_size.to_le_bytes());
    buffer[rsp_start + 40..rsp_start + 44]
        .copy_from_slice(&qe_identity_issuer_chain_size.to_le_bytes());
    buffer[rsp_start + 44..rsp_start + 48].copy_from_slice(&qe_identity_size.to_le_bytes());

    // Write collaterals data
    buffer[rsp_start + GET_COLLATERAL_RESPONSE_HEADER
        ..rsp_start + GET_COLLATERAL_RESPONSE_HEADER + collaterals_data.len()]
        .copy_from_slice(collaterals_data);

    // Update out_len field (u32 at offset 20)
    buffer[20..24].copy_from_slice(&(out_len as u32).to_le_bytes());

    // Set status to success (0)
    buffer[8..16].copy_from_slice(&0u64.to_le_bytes());

    log::info!(
        "AzCVMEmu: Returned wrapped collateral response, total size: {} bytes (msg_size={}, collaterals_data={})",
        out_len, msg_size, collaterals_data.len()
    );

    // Trigger event notification if a vector was registered
    if let Some(vector) = *EVENT_NOTIFY_VECTOR.lock() {
        log::info!("AzCVMEmu: Triggering interrupt vector {}", vector);
        intr::trigger(vector as u8);
    }

    Ok(())
}

/// Handle quote request by generating a quote using vTPM
///
/// # Parameters
/// - `buffer`: The GHCI buffer containing the request and will receive the response
/// - `in_len`: The input data length from the GHCI header
/// - `has_qgs_header`: If true, the request has SERVTD_HEADER + QGS message before TDREPORT
fn handle_quote_request(
    buffer: &mut [u8],
    in_len: usize,
    has_qgs_header: bool,
) -> Result<(), original_tdx_tdcall::TdVmcallError> {
    use original_tdx_tdcall::TdVmcallError;

    const SERVTD_HEADER_SIZE: usize = 4;
    const TDREPORT_SIZE: usize = 1024;

    // Determine where the TDREPORT starts based on whether there's a QGS header
    let tdreport_offset = if has_qgs_header {
        // Parse SERVTD_HEADER to get QGS message size (big-endian)
        let qgs_msg_size =
            u32::from_be_bytes([buffer[24], buffer[25], buffer[26], buffer[27]]) as usize;

        // Parse qgs_msg_get_quote_req_t structure:
        //   Offset 28-43: qgs_msg_header_t (16 bytes)
        //   Offset 44-47: report_size (u32)
        //   Offset 48-51: id_list_size (u32)
        //   Offset 52+:   report (1024 bytes) followed by optional id_list

        // The TDREPORT starts right after the QGS request header
        const QGS_GET_QUOTE_REQ_HEADER_SIZE: usize = 16 + 4 + 4; // qgs_msg_header_t + report_size + id_list_size
        let tdreport_start = 24 + SERVTD_HEADER_SIZE + QGS_GET_QUOTE_REQ_HEADER_SIZE;

        log::info!(
            "AzCVMEmu: Quote request with QGS header - qgs_msg_size={}, tdreport at offset {}",
            qgs_msg_size,
            tdreport_start
        );
        tdreport_start
    } else {
        // Legacy format: TDREPORT starts right after GHCI header
        log::info!("AzCVMEmu: Legacy quote request - tdreport at offset 24");
        24
    };

    // Validate we have enough data for the TDREPORT
    if buffer.len() < tdreport_offset + TDREPORT_SIZE {
        error!(
            "GetQuote buffer too small for TDREPORT: need {} bytes, have {}",
            tdreport_offset + TDREPORT_SIZE,
            buffer.len()
        );
        let error_status = 0x8000000000000000u64;
        buffer[8..16].copy_from_slice(&error_status.to_le_bytes());
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    // Extract TDREPORT data
    let tdreport_data = &buffer[tdreport_offset..tdreport_offset + TDREPORT_SIZE];

    // Pass the TDREPORT to quote generation
    let quote = match crate::tdreport_emu::get_quote_emulated(tdreport_data) {
        Ok(quote) => quote,
        Err(e) => {
            error!("Failed to generate quote in AzCVMEmu mode: {:?}", e);
            let error_status = 0x8000000000000000u64;
            buffer[8..16].copy_from_slice(&error_status.to_le_bytes());
            return Err(TdVmcallError::Other);
        }
    };

    // Prepare the response based on request format
    if has_qgs_header {
        // Response format: SERVTD_HEADER + qgs_msg_get_quote_resp_t
        // qgs_msg_get_quote_resp_t structure:
        //   - qgs_msg_header_t (16 bytes): major_version, minor_version, type, size, error_code
        //   - selected_id_size (4 bytes): 0 in our case
        //   - quote_size (4 bytes)
        //   - quote data
        const QGS_MSG_HEADER_SIZE: usize = 16;
        const QGS_GET_QUOTE_RESP_HEADER_SIZE: usize = QGS_MSG_HEADER_SIZE + 4 + 4; // header + selected_id_size + quote_size
        const GET_QUOTE_RESP: u32 = 1;
        const QGS_MSG_LIB_MAJOR_VER: u16 = 1;
        const QGS_MSG_LIB_MINOR_VER: u16 = 1;

        let qgs_response_size = QGS_GET_QUOTE_RESP_HEADER_SIZE + quote.len();
        let response_offset = 24; // Start of SERVTD_HEADER

        // Check if there's enough space for the response
        let required_space = SERVTD_HEADER_SIZE + qgs_response_size;
        if buffer.len() < response_offset + required_space {
            error!(
                "GetQuote buffer too small for quote response: need {} bytes, have {}",
                response_offset + required_space,
                buffer.len()
            );
            let error_status = 0x8000000000000000u64;
            buffer[8..16].copy_from_slice(&error_status.to_le_bytes());
            return Err(TdVmcallError::VmcallOperandInvalid);
        }

        // Write SERVTD_HEADER with QGS response message size (big-endian)
        buffer[response_offset] = ((qgs_response_size >> 24) & 0xFF) as u8;
        buffer[response_offset + 1] = ((qgs_response_size >> 16) & 0xFF) as u8;
        buffer[response_offset + 2] = ((qgs_response_size >> 8) & 0xFF) as u8;
        buffer[response_offset + 3] = (qgs_response_size & 0xFF) as u8;

        // Write qgs_msg_header_t (16 bytes) at offset 28
        let qgs_msg_offset = response_offset + SERVTD_HEADER_SIZE;

        // major_version (u16, little-endian)
        buffer[qgs_msg_offset..qgs_msg_offset + 2]
            .copy_from_slice(&QGS_MSG_LIB_MAJOR_VER.to_le_bytes());
        // minor_version (u16, little-endian)
        buffer[qgs_msg_offset + 2..qgs_msg_offset + 4]
            .copy_from_slice(&QGS_MSG_LIB_MINOR_VER.to_le_bytes());
        // type (u32, little-endian) = GET_QUOTE_RESP
        buffer[qgs_msg_offset + 4..qgs_msg_offset + 8]
            .copy_from_slice(&GET_QUOTE_RESP.to_le_bytes());
        // size (u32, little-endian) = total QGS message size
        buffer[qgs_msg_offset + 8..qgs_msg_offset + 12]
            .copy_from_slice(&(qgs_response_size as u32).to_le_bytes());
        // error_code (u32, little-endian) = 0 (success)
        buffer[qgs_msg_offset + 12..qgs_msg_offset + 16].copy_from_slice(&0u32.to_le_bytes());

        // Write selected_id_size (u32, little-endian) = 0
        buffer[qgs_msg_offset + 16..qgs_msg_offset + 20].copy_from_slice(&0u32.to_le_bytes());

        // Write quote_size (u32, little-endian)
        buffer[qgs_msg_offset + 20..qgs_msg_offset + 24]
            .copy_from_slice(&(quote.len() as u32).to_le_bytes());

        // Write the quote data after the QGS response header
        let quote_offset = qgs_msg_offset + QGS_GET_QUOTE_RESP_HEADER_SIZE;
        buffer[quote_offset..quote_offset + quote.len()].copy_from_slice(&quote);

        // Update out_len field (u32 at offset 20) - SERVTD_HEADER + QGS response
        buffer[20..24].copy_from_slice(&(required_space as u32).to_le_bytes());

        log::info!(
            "AzCVMEmu: Generated quote with QGS response header successfully - quote_size={}, qgs_response_size={}, total_response={}",
            quote.len(), qgs_response_size, required_space
        );
    } else {
        // Legacy response format: quote directly after header
        let quote_start_offset = 24;

        // Check if there's enough space after header for the quote
        if buffer.len() < quote_start_offset + quote.len() {
            error!(
                "GetQuote buffer too small for quote: need {} bytes, have {}",
                quote_start_offset + quote.len(),
                buffer.len()
            );
            let error_status = 0x8000000000000000u64;
            buffer[8..16].copy_from_slice(&error_status.to_le_bytes());
            return Err(TdVmcallError::VmcallOperandInvalid);
        }

        // Write the generated quote after the header
        buffer[quote_start_offset..quote_start_offset + quote.len()].copy_from_slice(&quote);

        // Update out_len field (u32 at offset 20) - just the quote size
        buffer[20..24].copy_from_slice(&(quote.len() as u32).to_le_bytes());

        log::info!(
            "AzCVMEmu: Generated quote successfully (legacy format), size: {}",
            quote.len()
        );
    }

    // Set status to success (0)
    buffer[8..16].copy_from_slice(&0u64.to_le_bytes());

    // Trigger event notification if a vector was registered
    if let Some(vector) = *EVENT_NOTIFY_VECTOR.lock() {
        log::info!("AzCVMEmu: Triggering interrupt vector {}", vector);
        intr::trigger(vector as u8);
    }

    Ok(())
}

/// Emulation for TDG.MR.EXTEND: extend a measurement into an RTMR
/// In AzCVMEmu mode, we simulate this operation by logging it
pub fn tdcall_extend_rtmr(
    digest: &original_tdx_tdcall::tdx::TdxDigest,
    mr_index: u32,
) -> Result<(), TdCallError> {
    log::info!(
        "AzCVMEmu: tdcall_extend_rtmr emulated - mr_index: {}, digest: {:02x?}",
        mr_index,
        &digest.data[..8]
    ); // Log first 8 bytes of digest

    // In a real implementation, this would extend the RTMR with the digest
    // For emulation, we just simulate success
    // The digest would be combined with the current RTMR value using SHA384

    // Validate mr_index (RTMRs are typically 0-3)
    if mr_index > 3 {
        log::warn!(
            "AzCVMEmu: Invalid RTMR index {} in tdcall_extend_rtmr",
            mr_index
        );
        return Err(TdCallError::TdxExitInvalidParameters);
    }

    log::debug!(
        "AzCVMEmu: Successfully emulated RTMR {} extension",
        mr_index
    );
    Ok(())
}

/// Emulation for tdvmcall_setup_event_notify
/// In AzCVMEmu mode, we store the vector so tdvmcall_get_quote can trigger it
pub fn tdvmcall_setup_event_notify(vector: u64) -> Result<(), original_tdx_tdcall::TdVmcallError> {
    log::info!(
        "AzCVMEmu: tdvmcall_setup_event_notify emulated - vector: {}",
        vector
    );

    // Store the notification vector so tdvmcall_get_quote can trigger it
    *EVENT_NOTIFY_VECTOR.lock() = Some(vector);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_large_payload_chunking() {
        *PENDING_RECV_BUFFER.lock() = None;

        let large_payload = vec![0x11; 200_000];
        *PENDING_RECV_BUFFER.lock() = Some(large_payload.clone());

        /// Maximum GHCI buffer payload size (buffer size - 12 byte header)
        /// Aligned with MAX_VMCALL_RAW_STREAM_MTU (64KB) used in vmcall_raw transport
        let max_ghci_payload = (0x1000 * 16) - 12;
        let mut received_data = Vec::new();

        for _ in 0..3 {
            let chunk = tcp_receive_data_chunk(max_ghci_payload).unwrap();
            assert_eq!(chunk.len(), max_ghci_payload);
            received_data.extend_from_slice(&chunk);
        }

        let chunk4 = tcp_receive_data_chunk(max_ghci_payload).unwrap();
        let expected_remainder = 200_000 - (max_ghci_payload * 3);
        assert_eq!(chunk4.len(), expected_remainder);
        received_data.extend_from_slice(&chunk4);

        assert_eq!(received_data, large_payload);
        assert!(PENDING_RECV_BUFFER.lock().is_none());
    }
}
