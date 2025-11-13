// Copyright (c) 2025 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! VMM-side logging emulation for AzCVMEmu mode
//! Handles reading log entries from the circular buffer and writing to file

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use zerocopy::{transmute_ref, AsBytes, FromBytes, FromZeroes};

const PAGE_SIZE: usize = 0x1000;
const LOG_ENTRY_HEADER_SIZE: usize = core::mem::size_of::<LogEntryHeader>();
const LOG_AREA_BUFFER_HEADER_SIZE: usize = core::mem::size_of::<LogAreaBufferHeader>();

pub const LOGAREA_SIGNATURE: [u8; 16] = [
    0x4d, 0x69, 0x67, 0x54, 0x44, 0x20, 0x4c, 0x6f, 0x67, 0x41, 0x72, 0x65, 0x61, 0x20, 0x31, 0x00,
];

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy)]
pub struct LogAreaBufferHeader {
    pub signature: [u8; 16],
    pub vcpuindex: u32,
    pub reserved: u32,
    pub startoffset: u64,
    pub endoffset: u64,
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy)]
pub struct LogEntryHeader {
    pub log_entry_id: u64,
    pub mig_request_id: u64,
    pub loglevel: u8,
    pub reserved: [u8; 3],
    pub length: u32,
}

/// Per-vCPU log area state
struct VcpuLogState {
    buffer_addr: usize,
    last_read_offset: usize,
}

/// VMM-side log area manager
pub struct LogAreaManager {
    vcpu_states: Vec<VcpuLogState>,
    log_file_path: Option<String>,
    log_file_handle: Option<BufWriter<File>>,
}

lazy_static::lazy_static! {
    static ref LOG_AREA_MANAGER: Mutex<Option<LogAreaManager>> = Mutex::new(None);
}

impl LogAreaManager {
    fn new() -> Self {
        // Get log file path from environment variable
        let log_file_path = env::var("MIGTD_LOG_FILE").ok();

        if let Some(ref path) = log_file_path {
            log::info!("VMM: MigTD logs will be written to: {}", path);
        } else {
            log::info!("VMM: MIGTD_LOG_FILE not set, logs will be printed to stdout");
        }

        LogAreaManager {
            vcpu_states: Vec::new(),
            log_file_path,
            log_file_handle: None,
        }
    }

    /// Initialize log areas from EnableLogArea response data
    pub fn initialize(&mut self, response_data: &[u8]) {
        if response_data.len() < 8 {
            log::error!("VMM: Invalid EnableLogArea response data (too short)");
            return;
        }

        let num_vcpus = u32::from_le_bytes(response_data[0..4].try_into().unwrap());
        log::info!("VMM: Initializing log areas for {} vCPUs", num_vcpus);

        // Clear the log file and open it for writing
        if let Some(ref path) = self.log_file_path {
            // Create/truncate the file and open it with buffered writer for efficient writing
            match OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
            {
                Ok(file) => {
                    self.log_file_handle = Some(BufWriter::new(file));
                    log::info!("VMM: Opened log file for writing: {}", path);
                }
                Err(e) => {
                    log::error!("VMM: Failed to open log file {}: {}", path, e);
                    self.log_file_handle = None;
                }
            }
        }

        self.vcpu_states.clear();

        let expected_len = 8 + (num_vcpus as usize * 16); // header + (addr + size) per vCPU
        if response_data.len() < expected_len {
            log::error!(
                "VMM: Invalid EnableLogArea response data (expected {}, got {})",
                expected_len,
                response_data.len()
            );
            return;
        }

        for i in 0..num_vcpus {
            let offset = 8 + (i as usize * 16);
            let buffer_addr =
                u64::from_le_bytes(response_data[offset..offset + 8].try_into().unwrap()) as usize;
            let _buffer_size =
                u64::from_le_bytes(response_data[offset + 8..offset + 16].try_into().unwrap())
                    as usize;

            log::info!("VMM: vCPU {} log area at address 0x{:x}", i, buffer_addr);

            self.vcpu_states.push(VcpuLogState {
                buffer_addr,
                last_read_offset: LOG_AREA_BUFFER_HEADER_SIZE,
            });
        }
    }

    /// Read and process log entries from all vCPU log areas
    pub fn read_log_entries(&mut self) {
        let num_vcpus = self.vcpu_states.len();
        for vcpu_idx in 0..num_vcpus {
            let buffer_addr = self.vcpu_states[vcpu_idx].buffer_addr;
            let last_read_offset = self.vcpu_states[vcpu_idx].last_read_offset;

            let new_offset =
                self.read_vcpu_log_entries_inner(vcpu_idx, buffer_addr, last_read_offset);
            self.vcpu_states[vcpu_idx].last_read_offset = new_offset;
        }
    }

    fn read_vcpu_log_entries_inner(
        &mut self,
        vcpu_idx: usize,
        buffer_addr: usize,
        last_read_offset: usize,
    ) -> usize {
        let buffer = unsafe { core::slice::from_raw_parts(buffer_addr as *const u8, PAGE_SIZE) };

        // Verify signature
        if &buffer[0..16] != LOGAREA_SIGNATURE {
            log::warn!("VMM: vCPU {} log area has invalid signature", vcpu_idx);
            return last_read_offset;
        }

        // Read header
        let header_bytes: [u8; LOG_AREA_BUFFER_HEADER_SIZE] = buffer
            [0..LOG_AREA_BUFFER_HEADER_SIZE]
            .try_into()
            .expect("incorrect size");
        let header: &LogAreaBufferHeader = transmute_ref!(&header_bytes);

        let start_offset = header.startoffset as usize;
        let end_offset = header.endoffset as usize;

        // Validate offsets
        if start_offset < LOG_AREA_BUFFER_HEADER_SIZE
            || start_offset >= PAGE_SIZE
            || end_offset < LOG_AREA_BUFFER_HEADER_SIZE
            || end_offset > PAGE_SIZE
        {
            log::warn!(
                "VMM: vCPU {} has invalid offsets (start: 0x{:x}, end: 0x{:x})",
                vcpu_idx,
                start_offset,
                end_offset
            );
            return last_read_offset;
        }

        // Check if there are new entries
        if last_read_offset == end_offset {
            // No new data
            return last_read_offset;
        }

        let mut current_offset = last_read_offset;

        // Handle wrap-around case
        if current_offset > end_offset {
            // Read from current_offset to end of buffer
            self.process_entries(vcpu_idx, buffer, current_offset, PAGE_SIZE);
            current_offset = LOG_AREA_BUFFER_HEADER_SIZE;
        }

        // Read from current_offset to end_offset
        if current_offset < end_offset {
            self.process_entries(vcpu_idx, buffer, current_offset, end_offset);
        }

        // Return new last read offset
        end_offset
    }

    fn process_entries(&mut self, vcpu_idx: usize, buffer: &[u8], start: usize, end: usize) {
        let mut offset = start;

        while offset + LOG_ENTRY_HEADER_SIZE <= end {
            // Read entry header
            let header_bytes: [u8; LOG_ENTRY_HEADER_SIZE] =
                match buffer[offset..offset + LOG_ENTRY_HEADER_SIZE].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => break,
                };
            let entry_header: &LogEntryHeader = transmute_ref!(&header_bytes);

            // Check if this is a valid entry
            if entry_header.length == 0 || entry_header.log_entry_id == 0 {
                break;
            }

            let msg_start = offset + LOG_ENTRY_HEADER_SIZE;
            let msg_end = msg_start + entry_header.length as usize;

            // Check if we have the full message
            if msg_end > end {
                break;
            }

            let message = &buffer[msg_start..msg_end];

            // Write the log entry
            self.write_log_entry(vcpu_idx, entry_header, message);

            offset = msg_end;
        }
    }

    fn write_log_entry(&mut self, vcpu_idx: usize, header: &LogEntryHeader, message: &[u8]) {
        // Copy packed struct fields to avoid unaligned reference errors
        let log_entry_id = header.log_entry_id;
        let mig_request_id = header.mig_request_id;
        let loglevel = header.loglevel;

        let level_str = match loglevel {
            1 => "ERROR",
            2 => "WARN",
            3 => "INFO",
            4 => "DEBUG",
            5 => "TRACE",
            _ => "UNKNOWN",
        };

        let msg_str = String::from_utf8_lossy(message);
        let log_line = format!(
            "[vCPU:{}][ID:{}][REQ:{}][{}] {}",
            vcpu_idx, log_entry_id, mig_request_id, level_str, msg_str
        );

        // Write to file handle or stdout
        let mut close_handle = false;
        if let Some(ref mut writer) = self.log_file_handle {
            if let Err(e) = writeln!(writer, "{}", log_line.trim_end()) {
                log::warn!("VMM: Failed to write to log file: {}", e);
                // Mark for closure and fall back to stdout
                close_handle = true;
                println!("{}", log_line.trim_end());
            } else {
                // Flush periodically for better real-time visibility
                let _ = writer.flush();
            }
        } else {
            // No file handle - write to stdout
            println!("{}", log_line.trim_end());
        }

        // Close the handle outside the borrow scope
        if close_handle {
            self.log_file_handle = None;
        }
    }
}

/// Initialize the VMM-side log area manager
pub fn init_log_area_manager() {
    let mut manager = LOG_AREA_MANAGER.lock().unwrap();
    *manager = Some(LogAreaManager::new());
}

/// Initialize log areas from EnableLogArea response
pub fn enable_log_area(response_data: &[u8]) {
    let mut manager_guard = LOG_AREA_MANAGER.lock().unwrap();
    if let Some(ref mut manager) = *manager_guard {
        manager.initialize(response_data);
    } else {
        log::error!("VMM: LogAreaManager not initialized");
    }
}

/// Read log entries from all vCPU log areas (called on each report_status)
pub fn read_log_entries() {
    let mut manager_guard = LOG_AREA_MANAGER.lock().unwrap();
    if let Some(ref mut manager) = *manager_guard {
        manager.read_log_entries();
    }
}
