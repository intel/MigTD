// Copyright (c) 2020 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Event log emulation module

// This module provides minimal emulation of td-shim event log functionality
// for Azure CVM environments, including file-based event log storage.

use cc_measurement::{
    log::{CcEventLogError, CcEventLogWriter},
    UefiPlatformFirmwareBlob2, EV_EFI_PLATFORM_FIRMWARE_BLOB2, EV_PLATFORM_CONFIG_FLAGS,
};
use core::{mem::size_of, ptr, ptr::slice_from_raw_parts, slice};

pub const CCEL_CC_TYPE_TDX: u8 = 2;

// Mock ACPI and CCEL structures to align with non-AzCVMEmu APIs
#[derive(Debug, Clone, Copy)]
pub struct MockCcel {
    pub lasa: u64, // Event log base address (points to our buffer)
    pub laml: u64, // Event log length (changed from u32 to u64 to match td-shim-interface)
}

// Re-export as Ccel to match td-shim-interface::acpi::Ccel
pub type Ccel = MockCcel;

impl MockCcel {
    pub fn new(buffer_ptr: *const u8, buffer_len: usize) -> Self {
        Self {
            lasa: buffer_ptr as u64,
            laml: buffer_len as u64,
        }
    }

    // Mock FromBytes::read_from for compatibility
    pub fn read_from(_bytes: &[u8]) -> Option<Self> {
        // Initialize the event log if needed and return a proper CCEL
        init_event_log();

        unsafe {
            let event_log_ptr = ptr::addr_of!(EVENT_LOG);
            if let Some(log) = (*event_log_ptr).as_ref() {
                Some(Self::new(log.data.as_ptr(), EVENT_LOG_BUFFER_SIZE))
            } else {
                None
            }
        }
    }
}

// Mock ACPI tables function
pub fn get_acpi_tables() -> Option<&'static [&'static [u8]]> {
    // Initialize the event log to get the CCEL
    init_event_log();

    // Create a proper CCEL table pointing to our event log buffer
    unsafe {
        let event_log_ptr = ptr::addr_of!(EVENT_LOG);
        if let Some(log) = (*event_log_ptr).as_ref() {
            // Use lazy static to store the CCEL bytes
            static mut MOCK_CCEL_BYTES: [u8; 64] = [0u8; 64]; // Large enough for full Ccel structure
            static mut INITIALIZED: bool = false;

            if !INITIALIZED {
                // Create a MockCcel with the event log buffer info
                let mock_ccel = MockCcel::new(log.data.as_ptr(), EVENT_LOG_BUFFER_SIZE);

                // Build a proper CCEL ACPI table structure
                // GenericSdtHeader (36 bytes) + cc_type (1) + cc_subtype (1) + reserved (2) + laml (8) + lasa (8) = 56 bytes

                // Signature: "CCEL"
                MOCK_CCEL_BYTES[0..4].copy_from_slice(b"CCEL");
                // Length: size of structure (56 bytes)
                MOCK_CCEL_BYTES[4..8].copy_from_slice(&56u32.to_le_bytes());
                // Revision: 1
                MOCK_CCEL_BYTES[8] = 1;
                // Checksum: 0 (we'll skip checksum for now)
                MOCK_CCEL_BYTES[9] = 0;
                // OEM ID: "INTEL "
                MOCK_CCEL_BYTES[10..16].copy_from_slice(b"INTEL ");
                // OEM Table ID: "EMULATED"
                MOCK_CCEL_BYTES[16..24].copy_from_slice(b"EMULATED");
                // OEM Revision: 1
                MOCK_CCEL_BYTES[24..28].copy_from_slice(&1u32.to_le_bytes());
                // Creator ID: "EMUL"
                MOCK_CCEL_BYTES[28..32].copy_from_slice(b"EMUL");
                // Creator Revision: 1
                MOCK_CCEL_BYTES[32..36].copy_from_slice(&1u32.to_le_bytes());

                // CC Type: TDX (2)
                MOCK_CCEL_BYTES[36] = CCEL_CC_TYPE_TDX;
                // CC Subtype: 0
                MOCK_CCEL_BYTES[37] = 0;
                // Reserved: 0
                MOCK_CCEL_BYTES[38..40].copy_from_slice(&0u16.to_le_bytes());
                // LAML (log area maximum length)
                MOCK_CCEL_BYTES[40..48].copy_from_slice(&mock_ccel.laml.to_le_bytes());
                // LASA (log area start address)
                MOCK_CCEL_BYTES[48..56].copy_from_slice(&mock_ccel.lasa.to_le_bytes());

                INITIALIZED = true;
            }

            // Return a slice of the initialized CCEL bytes
            let ccel_slice: &'static [u8] = &MOCK_CCEL_BYTES[..56];
            static mut TABLES_STORAGE: Option<[&'static [u8]; 1]> = None;
            if TABLES_STORAGE.is_none() {
                TABLES_STORAGE = Some([ccel_slice]);
            }
            return TABLES_STORAGE.as_ref().map(|t| &t[..]);
        }
    }
    None
}

pub const PLATFORM_CONFIG_HOB: &[u8] = b"td_hob\0";
pub const PLATFORM_CONFIG_PAYLOAD_PARAMETER: &[u8] = b"td_payload_info\0";
pub const PLATFORM_CONFIG_SECURE_POLICY_DB: &[u8] = b"secure_policy_db";
pub const PLATFORM_CONFIG_SECURE_AUTHORITY: &[u8] = b"secure_authority";
pub const PLATFORM_CONFIG_SVN: &[u8] = b"td_payload_svn\0";
pub const PLATFORM_FIRMWARE_BLOB2_PAYLOAD: &[u8] = b"td_payload\0";

/// Used to record configuration information into event log
///
/// Defined in td-shim spec 'Table 3.5-4 TD_SHIM_PLATFORM_CONFIG_INFO'
#[repr(C)]
#[derive(Debug, Default)]
pub struct TdShimPlatformConfigInfoHeader {
    pub descriptor: [u8; 16],
    pub info_length: u32,
}

impl TdShimPlatformConfigInfoHeader {
    pub fn new(descriptor: &[u8], info_length: u32) -> Option<Self> {
        if descriptor.len() > 16 {
            return None;
        }

        let mut header = Self {
            info_length,
            ..Default::default()
        };

        header.descriptor[..descriptor.len()].copy_from_slice(descriptor);
        Some(header)
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

pub fn create_event_log_platform_config(
    event_log: &mut CcEventLogWriter,
    mr_index: u32,
    descriptor: &[u8],
    data: &[u8],
) -> Result<(), CcEventLogError> {
    // Write the `TdShimPlatformConfigInfoHeader + data` into event log
    let config_header = TdShimPlatformConfigInfoHeader::new(descriptor, data.len() as u32)
        .ok_or(CcEventLogError::InvalidParameter)?;

    event_log.create_event_log(
        mr_index,
        EV_PLATFORM_CONFIG_FLAGS,
        &[config_header.as_bytes(), data],
        data,
    )?;

    Ok(())
}

pub fn log_hob_list(hob_list: &[u8], cc_event_log: &mut CcEventLogWriter) {
    create_event_log_platform_config(cc_event_log, 1, PLATFORM_CONFIG_HOB, hob_list)
        .expect("Failed to log HOB list to the td event log");
}

pub fn log_payload_binary(payload: &[u8], cc_event_log: &mut CcEventLogWriter) {
    let blob2 = UefiPlatformFirmwareBlob2::new(
        PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
        payload.as_ptr() as u64,
        payload.len() as u64,
    )
    .expect("Invalid payload binary information or descriptor");

    cc_event_log
        .create_event_log(
            2,
            EV_EFI_PLATFORM_FIRMWARE_BLOB2,
            &[blob2.as_bytes()],
            payload,
        )
        .expect("Failed to log HOB list to the td event log");
}

pub fn log_payload_parameter(payload_parameter: &[u8], cc_event_log: &mut CcEventLogWriter) {
    create_event_log_platform_config(
        cc_event_log,
        2,
        PLATFORM_CONFIG_PAYLOAD_PARAMETER,
        payload_parameter,
    )
    .expect("Failed to log HOB list to the td event log");
}

/// SHA384 hash size
pub const SHA384_DIGEST_SIZE: usize = 48;
/// SHA384 algorithm identifier
pub const TPML_ALG_SHA384: u16 = 0x000C;
/// Event tag for TXT events
pub const EV_EVENT_TAG: u32 = 0x00000006;

/// Emulated file-based event log
// Mock Once implementation to align with non-AzCVMEmu APIs
pub struct MockOnce<T> {
    value: Option<T>,
}

impl<T> MockOnce<T> {
    pub const fn new() -> Self {
        Self { value: None }
    }

    pub fn is_completed(&self) -> bool {
        true // Always return true for emulation
    }

    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub fn call_once<F>(&mut self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        if self.value.is_none() {
            self.value = Some(f());
        }
        self.value.as_ref().unwrap()
    }
}

// Define the size of the event log buffer as a constant for better maintainability
pub const EVENT_LOG_BUFFER_SIZE: usize = 32768; // Buffer size 32768 (32KB)

pub struct EventLogEmulator {
    data: [u8; EVENT_LOG_BUFFER_SIZE], // Fixed size buffer defined by constant
    ccel: MockCcel,                    // Mock CCEL pointing to our buffer
}

impl EventLogEmulator {
    /// Create a new empty event log
    pub fn new() -> Self {
        let mut emulator = Self {
            data: [0u8; EVENT_LOG_BUFFER_SIZE],
            ccel: MockCcel::new(ptr::null(), 0), // Will be updated below
        };

        // Update CCEL to point to our buffer
        emulator.ccel = MockCcel::new(emulator.data.as_ptr(), EVENT_LOG_BUFFER_SIZE);
        emulator
    }

    /// Get a reference to the full event log buffer
    pub fn full_buffer(&self) -> &[u8] {
        &self.data[..]
    }

    /// Get a mutable reference to the full event log buffer
    pub fn full_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.data[..]
    }

    /// Get the mock CCEL for this event log
    pub fn get_ccel(&mut self) -> &MockCcel {
        // Update the CCEL pointer in case the buffer was moved
        self.ccel = MockCcel::new(self.data.as_ptr(), EVENT_LOG_BUFFER_SIZE);
        &self.ccel
    }

    /// Get event log slice (mimics the non-AzCVMEmu API)
    pub fn event_log_slice(&mut self) -> &mut [u8] {
        &mut self.data[..]
    }
}

// Singleton instance of the event log
static mut EVENT_LOG: Option<EventLogEmulator> = None;

// Mock CCEL singleton to align with non-AzCVMEmu API
static mut MOCK_CCEL_ONCE: MockOnce<MockCcel> = MockOnce::new();

/// Mock get_ccel function to align with non-AzCVMEmu API
pub fn get_ccel() -> Option<&'static MockCcel> {
    unsafe {
        // Initialize if needed
        init_event_log();

        let event_log_ptr = ptr::addr_of_mut!(EVENT_LOG);
        if let Some(log) = (*event_log_ptr).as_mut() {
            let mock_ccel_ptr = ptr::addr_of_mut!(MOCK_CCEL_ONCE);
            Some(
                (*mock_ccel_ptr)
                    .call_once(|| MockCcel::new(log.data.as_ptr(), EVENT_LOG_BUFFER_SIZE)),
            )
        } else {
            None
        }
    }
}

/// Mock event_log_slice function to align with non-AzCVMEmu API
pub fn event_log_slice(_ccel: &MockCcel) -> &'static mut [u8] {
    unsafe {
        let event_log_ptr = ptr::addr_of_mut!(EVENT_LOG);
        if let Some(log) = (*event_log_ptr).as_mut() {
            log.event_log_slice()
        } else {
            // This shouldn't happen if properly initialized
            slice::from_raw_parts_mut(ptr::null_mut(), 0)
        }
    }
}

/// Initialize the event log emulator
pub fn init_event_log() {
    unsafe {
        let event_log_ptr = ptr::addr_of_mut!(EVENT_LOG);
        if (*event_log_ptr).is_none() {
            *event_log_ptr = Some(EventLogEmulator::new());
            // Add expected event at the beginning of the log
            // ToDo: Add MigTDCore event to support relevant policy rules
            populate_tcg_pcr_event_log();
        }
    }
}

/// Get a reference to the event log data (returns full buffer for parsing)
pub fn get_event_log() -> Option<&'static [u8]> {
    // Initialize the event log if needed
    init_event_log();

    unsafe {
        let event_log_ptr = ptr::addr_of!(EVENT_LOG);
        if let Some(log) = (*event_log_ptr).as_ref() {
            Some(log.full_buffer())
        } else {
            None
        }
    }
}

/// Get a mutable reference to the full event log buffer
pub fn get_event_log_mut() -> Option<&'static mut [u8]> {
    // Initialize the event log if needed
    init_event_log();

    unsafe {
        let event_log_ptr = ptr::addr_of_mut!(EVENT_LOG);
        if let Some(log) = (*event_log_ptr).as_mut() {
            Some(log.full_buffer_mut())
        } else {
            None
        }
    }
}

fn populate_tcg_pcr_event_log() {
    unsafe {
        let event_log_ptr = ptr::addr_of_mut!(EVENT_LOG);
        if let Some(log) = (*event_log_ptr).as_mut() {
            // Create a proper TCG event log starting with TcgPcrEventHeader
            // This is what the policy verification expects to find

            use cc_measurement::{TcgEfiSpecIdevent, TcgPcrEventHeader};
            use core::mem::size_of;
            use zerocopy::AsBytes;

            // Create the initial TCG_EfiSpecIDEvent using the default implementation
            let spec_id_event = TcgEfiSpecIdevent::default();

            // Create TcgPcrEventHeader for the first event
            let pcr_header = TcgPcrEventHeader {
                mr_index: 0,
                event_type: 0x80000003, // EV_NO_ACTION
                digest: [0u8; 20],      // SHA1 digest (zeros for EV_NO_ACTION)
                event_size: size_of::<TcgEfiSpecIdevent>() as u32,
            };

            // Write the headers to the event log
            let mut offset = 0;

            // Write TcgPcrEventHeader
            let pcr_header_bytes = pcr_header.as_bytes();
            log.data[offset..offset + pcr_header_bytes.len()].copy_from_slice(pcr_header_bytes);
            offset += pcr_header_bytes.len();

            // Write TcgEfiSpecIdevent
            let spec_id_bytes = spec_id_event.as_bytes();
            log.data[offset..offset + spec_id_bytes.len()].copy_from_slice(spec_id_bytes);

            // No need to track size - parsing logic will determine the written portion
        }
    }
}

#[cfg(test)]
mod test {
    use super::TdShimPlatformConfigInfoHeader;
    use core::mem::size_of;

    #[test]
    fn test_struct_size() {
        assert_eq!(size_of::<TdShimPlatformConfigInfoHeader>(), 20);
    }

    #[test]
    fn test_tdshim_platform_configinfo_header() {
        // descriptor length < 16
        let descriptor: [u8; 15] = [0; 15];
        assert!(TdShimPlatformConfigInfoHeader::new(&descriptor, 0).is_some());

        // descriptor length = 16
        let descriptor: [u8; 16] = [0; 16];
        assert!(TdShimPlatformConfigInfoHeader::new(&descriptor, 0).is_some());
        assert_eq!(
            TdShimPlatformConfigInfoHeader::new(&descriptor, 0)
                .unwrap()
                .as_bytes(),
            [0; 20]
        );

        // descriptor length > 16
        let descriptor: [u8; 17] = [0; 17];
        assert!(TdShimPlatformConfigInfoHeader::new(&descriptor, 0).is_none());
    }
}
