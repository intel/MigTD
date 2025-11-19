// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg(feature = "vmcall-raw")]

use crate::migration::MigrationResult;
#[cfg(test)]
use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use lazy_static::lazy_static;
use log::Level;
#[cfg(not(test))]
use raw_cpuid::CpuId;
use spin::Mutex;
#[cfg(not(test))]
use td_payload::mm::shared::alloc_shared_pages;
#[cfg(not(test))]
use tdx_tdcall::{td_call, TdcallArgs};
use zerocopy::{transmute_ref, AsBytes, FromBytes, FromZeroes};
const PAGE_SIZE: usize = 0x1_000;
#[cfg(not(test))]
const TDCALL_STATUS_SUCCESS: u64 = 0;

type Result<T> = core::result::Result<T, MigrationResult>;

struct LoggingInformation {
    num_vcpus: AtomicU32,
    logarea_created: AtomicBool,
    logarea_initialized: AtomicBool,
    logentry_id: AtomicU64,
    maxloglevel: AtomicU8,
}

pub const LOGAREA_SIGNATURE: [u8; 16] = [
    0x4d, 0x69, 0x67, 0x54, 0x44, 0x20, 0x4c, 0x6f, 0x67, 0x41, 0x72, 0x65, 0x61, 0x20, 0x31, 0x00,
];

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Debug)]
pub struct LogAreaBufferHeader {
    pub signature: [u8; 16],
    pub vcpuindex: u32,
    pub reserved: u32,
    pub startoffset: u64,
    pub endoffset: u64,
}

pub struct LogAreaBuffer<'a> {
    pub header: LogAreaBufferHeader,
    pub logdata: &'a [u8],
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Debug)]
#[cfg(feature = "vmcall-raw")]
pub struct LogEntryHeader {
    pub log_entry_id: u64,
    pub mig_request_id: u64,
    pub loglevel: u8,
    pub reserved: [u8; 3],
    pub length: u32,
}

pub struct LogEntry<'a> {
    pub header: LogEntryHeader,
    pub value: &'a [u8],
}

fn u8_to_loglevel(value: u8) -> Option<Level> {
    match value {
        1 => Some(Level::Error),
        2 => Some(Level::Warn),
        3 => Some(Level::Info),
        4 => Some(Level::Debug),
        5 => Some(Level::Trace),
        _ => None, // Handle cases where the u8 doesn't map to a valid Level
    }
}

fn loglevel_to_u8(level: Level) -> u8 {
    match level {
        Level::Error => 1,
        Level::Warn => 2,
        Level::Info => 3,
        Level::Debug => 4,
        Level::Trace => 5,
    }
}

lazy_static! {
    static ref LOGGING_INFORMATION: LoggingInformation = LoggingInformation {
        num_vcpus: AtomicU32::new(0),
        logarea_created: AtomicBool::new(false),
        logarea_initialized: AtomicBool::new(false),
        logentry_id: AtomicU64::new(0),
        maxloglevel: AtomicU8::new(0),
    };
    static ref LOGAREAPTR: Mutex<Vec<usize>> = Mutex::new(Vec::new());
}

pub fn create_logarea() -> Result<()> {
    let num_vcpus: u32;
    #[cfg(not(test))]
    {
        const TDVMCALL_TDINFO: u64 = 0x00001;
        let mut args = TdcallArgs {
            rax: TDVMCALL_TDINFO,
            ..Default::default()
        };

        let ret = td_call(&mut args);
        if ret != TDCALL_STATUS_SUCCESS {
            return Err(MigrationResult::TdxModuleError);
        }

        num_vcpus = args.r8 as u32;

        let mut logareavector = LOGAREAPTR.lock();
        for _index in 0..num_vcpus {
            let data_buffer =
                unsafe { alloc_shared_pages(1).ok_or(MigrationResult::OutOfResource)? };
            logareavector.push(data_buffer);
        }
    }
    #[cfg(test)]
    {
        num_vcpus = 1;
        let mut logareavector = LOGAREAPTR.lock();
        let databuffer: Box<[u8; PAGE_SIZE]> = Box::new([0; PAGE_SIZE]);
        let databuffer_ptr = Box::into_raw(databuffer) as *mut u8;
        logareavector.push(databuffer_ptr as usize);
    }

    LOGGING_INFORMATION
        .num_vcpus
        .store(num_vcpus, Ordering::SeqCst);

    LOGGING_INFORMATION
        .logarea_created
        .store(true, Ordering::SeqCst);

    Ok(())
}

pub async fn enable_logarea(log_max_level: u8, request_id: u64, data: &mut Vec<u8>) -> Result<()> {
    let padding: u32 = 0;
    let num_vcpus: u32 = LOGGING_INFORMATION.num_vcpus.load(Ordering::SeqCst);
    let logarea_created: bool = LOGGING_INFORMATION.logarea_created.load(Ordering::SeqCst);
    let logarea_initialized: bool = LOGGING_INFORMATION
        .logarea_initialized
        .load(Ordering::SeqCst);

    if !logarea_created {
        return Err(MigrationResult::UnsupportedOperationError);
    }

    if let Some(_log_level) = u8_to_loglevel(log_max_level) {
        LOGGING_INFORMATION
            .maxloglevel
            .store(log_max_level, Ordering::SeqCst);
        data.extend_from_slice(&num_vcpus.to_le_bytes());
        data.extend_from_slice(&padding.to_le_bytes());
        #[cfg(not(test))]
        {
            for index in 0..num_vcpus {
                let logareavector = LOGAREAPTR.lock();
                let data_buffer = logareavector[index as usize];
                let data_buffer =
                    unsafe { core::slice::from_raw_parts_mut(data_buffer as *mut u8, PAGE_SIZE) };
                let data_buffer_as_u64 = data_buffer.as_ptr() as u64;
                if !logarea_initialized {
                    let logareabuffheader = LogAreaBufferHeader {
                        signature: LOGAREA_SIGNATURE,
                        vcpuindex: index,
                        reserved: 0,
                        startoffset: size_of::<LogAreaBufferHeader>() as u64,
                        endoffset: size_of::<LogAreaBufferHeader>() as u64,
                    };
                    let bytes: &[u8] = logareabuffheader.as_bytes();
                    data_buffer[0..size_of::<LogAreaBufferHeader>()]
                        .copy_from_slice(&bytes[0..bytes.len()]);
                    LOGGING_INFORMATION
                        .logarea_initialized
                        .store(true, Ordering::SeqCst);
                }
                data.extend_from_slice(&data_buffer_as_u64.to_le_bytes());
                data.extend_from_slice(&PAGE_SIZE.to_le_bytes());
            }

            log::info!(
                "enable_logarea: Logging has been enabled with MaxLevel: {}\n",
                log_max_level
            );
            entrylog(
                &format!(
                    "enable_logarea: Logging has been enabled with MaxLevel: {}\n",
                    log_max_level
                )
                .into_bytes(),
                Level::Info,
                request_id,
            );
        }
        #[cfg(test)]
        {
            let logareavector = LOGAREAPTR.lock();
            let data_buffer = logareavector[0] as *mut u8;
            let data_buffer = unsafe { core::slice::from_raw_parts_mut(data_buffer, PAGE_SIZE) };
            let data_buffer_as_u64 = data_buffer.as_ptr() as u64;
            if !logarea_initialized {
                let logareabuffheader = LogAreaBufferHeader {
                    signature: LOGAREA_SIGNATURE,
                    vcpuindex: 0,
                    reserved: 0,
                    startoffset: size_of::<LogAreaBufferHeader>() as u64,
                    endoffset: size_of::<LogAreaBufferHeader>() as u64,
                };
                let bytes: &[u8] = logareabuffheader.as_bytes();
                data_buffer[0..size_of::<LogAreaBufferHeader>()]
                    .copy_from_slice(&bytes[0..bytes.len()]);
                LOGGING_INFORMATION
                    .logarea_initialized
                    .store(true, Ordering::SeqCst);
            }
            data.extend_from_slice(&data_buffer_as_u64.to_le_bytes());
            data.extend_from_slice(&PAGE_SIZE.to_le_bytes());
        }
        Ok(())
    } else {
        entrylog(
            &format!("enable_logarea: Invalid MaxLogLevel: {:x}\n", log_max_level).into_bytes(),
            Level::Error,
            request_id,
        );
        return Err(MigrationResult::InvalidParameter);
    }
}

pub fn entrylog(msg: &Vec<u8>, loglevel: Level, request_id: u64) {
    let logarea_created: bool = LOGGING_INFORMATION.logarea_created.load(Ordering::SeqCst);
    let log_max_level: u8 = LOGGING_INFORMATION.maxloglevel.load(Ordering::SeqCst);
    let log_level = loglevel_to_u8(loglevel);

    if logarea_created {
        if log_level <= log_max_level {
            const LOGENTRYHEADERSIZE: usize = size_of::<LogEntryHeader>();
            const LOGAREABUFFERHEADERSIZE: usize = size_of::<LogAreaBufferHeader>();
            if msg.len() > PAGE_SIZE - (LOGAREABUFFERHEADERSIZE + LOGENTRYHEADERSIZE) {
                return;
            }
            #[cfg(not(test))]
            {
                let cpuid = CpuId::new();
                if let Some(feature_info) = cpuid.get_feature_info() {
                    let currvcpuindex: u32 = feature_info.initial_local_apic_id().into();
                    let logareavector = LOGAREAPTR.lock();
                    let data_buffer = logareavector[currvcpuindex as usize];
                    let data_buffer = unsafe {
                        core::slice::from_raw_parts_mut(data_buffer as *mut u8, PAGE_SIZE)
                    };
                    let vcpuindex: u32 =
                        u32::from_le_bytes(data_buffer[16..20].try_into().unwrap());
                    if currvcpuindex == vcpuindex {
                        LOGGING_INFORMATION
                            .logentry_id
                            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                                Some(if v == u64::MAX { 1 } else { v + 1 })
                            })
                            .unwrap();
                        let start_offset: u64 =
                            u64::from_le_bytes(data_buffer[24..32].try_into().unwrap());
                        let end_offset: u64 =
                            u64::from_le_bytes(data_buffer[32..40].try_into().unwrap());
                        let mut currentstartoffset: usize = start_offset as usize;
                        let mut currentendoffset: usize = end_offset as usize;
                        if currentendoffset + LOGENTRYHEADERSIZE + msg.len() > PAGE_SIZE
                            || currentendoffset < currentstartoffset
                        {
                            if currentendoffset + LOGENTRYHEADERSIZE + msg.len() > PAGE_SIZE {
                                data_buffer[currentendoffset..PAGE_SIZE].fill(0);
                                currentendoffset = LOGAREABUFFERHEADERSIZE;
                            }
                            if currentendoffset < currentstartoffset {
                                data_buffer[currentendoffset..currentstartoffset].fill(0);
                                if currentendoffset + LOGENTRYHEADERSIZE + msg.len()
                                    > currentstartoffset
                                {
                                    let mut reqdatasize = LOGENTRYHEADERSIZE + msg.len();
                                    reqdatasize = reqdatasize
                                        .saturating_sub(currentstartoffset - currentendoffset);
                                    while reqdatasize > 0 {
                                        if currentstartoffset + LOGENTRYHEADERSIZE >= PAGE_SIZE {
                                            currentstartoffset = LOGAREABUFFERHEADERSIZE;
                                        }
                                        let logentrybytes: [u8; LOGENTRYHEADERSIZE] = data_buffer
                                            [currentstartoffset
                                                ..currentstartoffset + LOGENTRYHEADERSIZE]
                                            .try_into()
                                            .expect("incorrect size");
                                        let logentryhdr: &LogEntryHeader =
                                            transmute_ref!(&logentrybytes);
                                        let totallength: usize =
                                            logentryhdr.length as usize + LOGENTRYHEADERSIZE;
                                        data_buffer
                                            [currentstartoffset..currentstartoffset + totallength]
                                            .fill(0);
                                        currentstartoffset += totallength;
                                        reqdatasize = reqdatasize.saturating_sub(totallength);
                                    }
                                }
                            }
                        }

                        // Reset startoffset if no message is available at the end of buffer
                        if currentstartoffset + LOGENTRYHEADERSIZE >= PAGE_SIZE {
                            data_buffer[currentstartoffset..PAGE_SIZE].fill(0);
                            currentstartoffset = LOGAREABUFFERHEADERSIZE;
                        }

                        // Reset startoffset if no valid message is available
                        if currentstartoffset != LOGAREABUFFERHEADERSIZE {
                            let logentrybytes: [u8; LOGENTRYHEADERSIZE] = data_buffer
                                [currentstartoffset..currentstartoffset + LOGENTRYHEADERSIZE]
                                .try_into()
                                .expect("incorrect size");
                            let logentryhdr: &LogEntryHeader = transmute_ref!(&logentrybytes);
                            if logentryhdr.length == 0 && logentryhdr.log_entry_id == 0 {
                                currentstartoffset = LOGAREABUFFERHEADERSIZE;
                            }
                        }

                        data_buffer
                            [currentendoffset..currentendoffset + LOGENTRYHEADERSIZE + msg.len()]
                            .fill(0);
                        let logentryhdr = LogEntryHeader {
                            log_entry_id: LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst),
                            mig_request_id: request_id,
                            loglevel: log_level,
                            reserved: [0, 0, 0],
                            length: msg.len() as u32,
                        };

                        let bytes: &[u8] = logentryhdr.as_bytes();
                        data_buffer[currentendoffset..currentendoffset + LOGENTRYHEADERSIZE]
                            .copy_from_slice(&bytes[0..bytes.len()]);
                        currentendoffset += LOGENTRYHEADERSIZE;
                        data_buffer[currentendoffset..currentendoffset + msg.len()]
                            .copy_from_slice(&msg[0..msg.len()]);
                        currentendoffset += msg.len();

                        data_buffer[24..32].copy_from_slice(&currentstartoffset.to_le_bytes());
                        data_buffer[32..40].copy_from_slice(&currentendoffset.to_le_bytes());
                    }
                }
            }
            #[cfg(test)]
            {
                let logareavector = LOGAREAPTR.lock();
                let data_buffer = logareavector[0];
                let data_buffer =
                    unsafe { core::slice::from_raw_parts_mut(data_buffer as *mut u8, PAGE_SIZE) };
                LOGGING_INFORMATION
                    .logentry_id
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                        Some(if v == u64::MAX { 1 } else { v + 1 })
                    })
                    .unwrap();
                let start_offset: u64 = u64::from_le_bytes(data_buffer[24..32].try_into().unwrap());
                let end_offset: u64 = u64::from_le_bytes(data_buffer[32..40].try_into().unwrap());
                let mut currentstartoffset: usize = start_offset as usize;
                let mut currentendoffset: usize = end_offset as usize;

                if currentendoffset + LOGENTRYHEADERSIZE + msg.len() > PAGE_SIZE
                    || currentendoffset < currentstartoffset
                {
                    if currentendoffset + LOGENTRYHEADERSIZE + msg.len() > PAGE_SIZE {
                        data_buffer[currentendoffset..PAGE_SIZE].fill(0);
                        currentendoffset = LOGAREABUFFERHEADERSIZE;
                    }
                    if currentendoffset < currentstartoffset {
                        data_buffer[currentendoffset..currentstartoffset].fill(0);
                        if currentendoffset + LOGENTRYHEADERSIZE + msg.len() > currentstartoffset {
                            let mut reqdatasize = LOGENTRYHEADERSIZE + msg.len();
                            reqdatasize =
                                reqdatasize.saturating_sub(currentstartoffset - currentendoffset);
                            while reqdatasize > 0 {
                                println!(
                                    "Entry_Log: start_offset {:x} end_offset {:x} ",
                                    currentstartoffset, currentendoffset
                                );
                                if currentstartoffset + LOGENTRYHEADERSIZE >= PAGE_SIZE {
                                    currentstartoffset = LOGAREABUFFERHEADERSIZE;
                                }
                                let logentrybytes: [u8; LOGENTRYHEADERSIZE] = data_buffer
                                    [currentstartoffset..currentstartoffset + LOGENTRYHEADERSIZE]
                                    .try_into()
                                    .expect("incorrect size");
                                let logentryhdr: &LogEntryHeader = transmute_ref!(&logentrybytes);
                                let totallength: usize =
                                    logentryhdr.length as usize + LOGENTRYHEADERSIZE;
                                data_buffer[currentstartoffset..currentstartoffset + totallength]
                                    .fill(0);
                                currentstartoffset += totallength;
                                reqdatasize = reqdatasize.saturating_sub(totallength);
                            }
                        }
                    }
                }

                // Reset startoffset if no message is available at the end of buffer
                if currentstartoffset + LOGENTRYHEADERSIZE >= PAGE_SIZE {
                    data_buffer[currentstartoffset..PAGE_SIZE].fill(0);
                    currentstartoffset = LOGAREABUFFERHEADERSIZE;
                }

                // Reset startoffset if no valid message is available
                if currentstartoffset != LOGAREABUFFERHEADERSIZE {
                    let logentrybytes: [u8; LOGENTRYHEADERSIZE] = data_buffer
                        [currentstartoffset..currentstartoffset + LOGENTRYHEADERSIZE]
                        .try_into()
                        .expect("incorrect size");
                    let logentryhdr: &LogEntryHeader = transmute_ref!(&logentrybytes);
                    if logentryhdr.length == 0 && logentryhdr.log_entry_id == 0 {
                        currentstartoffset = LOGAREABUFFERHEADERSIZE;
                    }
                }

                data_buffer[currentendoffset..currentendoffset + LOGENTRYHEADERSIZE + msg.len()]
                    .fill(0);

                let logentryhdr = LogEntryHeader {
                    log_entry_id: LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst),
                    mig_request_id: request_id,
                    loglevel: log_level,
                    reserved: [0, 0, 0],
                    length: msg.len() as u32,
                };

                let bytes: &[u8] = logentryhdr.as_bytes();
                data_buffer[currentendoffset..currentendoffset + LOGENTRYHEADERSIZE]
                    .copy_from_slice(&bytes[0..bytes.len()]);
                currentendoffset += LOGENTRYHEADERSIZE;
                data_buffer[currentendoffset..currentendoffset + msg.len()]
                    .copy_from_slice(&msg[0..msg.len()]);
                currentendoffset += msg.len();

                data_buffer[24..32].copy_from_slice(&currentstartoffset.to_le_bytes());
                data_buffer[32..40].copy_from_slice(&currentendoffset.to_le_bytes());
                println!(
                    "Entry_Log: Message length {:x} start_offset {:x} end_offset {:x} ",
                    msg.len(),
                    currentstartoffset,
                    currentendoffset
                );
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_logarea() {
        // Reset the global state for testing
        LOGGING_INFORMATION.num_vcpus.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_created
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_initialized
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION.logentry_id.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION.maxloglevel.store(0, Ordering::SeqCst);

        let result = create_logarea();
        assert!(result.is_ok());
        assert!(matches!(
            LOGGING_INFORMATION.num_vcpus.load(Ordering::SeqCst),
            1
        ));
        assert!(matches!(
            LOGGING_INFORMATION.logarea_created.load(Ordering::SeqCst),
            true
        ));

        // Test utility functions
        assert_eq!(loglevel_to_u8(Level::Error), 1);
        assert_eq!(loglevel_to_u8(Level::Info), 3);

        // Test that u8_to_loglevel works
        assert_eq!(u8_to_loglevel(3), Some(Level::Info));
        assert_eq!(u8_to_loglevel(99), None);

        let mut logareavector = LOGAREAPTR.lock();
        let data_buffer = logareavector[0];
        logareavector.clear();
        unsafe {
            let _ = Box::from_raw(data_buffer as *mut [u8; PAGE_SIZE]);
        }
    }

    #[tokio::test]
    async fn test_enable_logarea() {
        let mut data: Vec<u8> = Vec::new();
        let log_max_level: u8 = 5;

        // Reset the global state for testing
        LOGGING_INFORMATION.num_vcpus.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_created
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_initialized
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION.logentry_id.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION.maxloglevel.store(0, Ordering::SeqCst);

        let result = enable_logarea(log_max_level, 0, &mut data).await;
        assert!(!result.is_ok());

        let mut result = create_logarea();
        assert!(result.is_ok());

        result = enable_logarea(log_max_level, 0, &mut data).await;
        assert!(result.is_ok());

        let mut logareavector = LOGAREAPTR.lock();
        let data_buffer = logareavector[0];
        logareavector.clear();
        unsafe {
            let _ = Box::from_raw(data_buffer as *mut [u8; PAGE_SIZE]);
        }
    }

    #[tokio::test]
    async fn test_entrylog() {
        // Reset the global state for testing
        LOGGING_INFORMATION.num_vcpus.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_created
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_initialized
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION.logentry_id.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION.maxloglevel.store(0, Ordering::SeqCst);

        let mut data: Vec<u8> = Vec::new();
        let log_max_level: u8 = 5;

        let initial_entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);

        // Try to log without creating log area - should be ignored
        entrylog(
            &"This should be ignored\n".to_string().into_bytes(),
            Level::Info,
            u64::MAX,
        );

        // Entry ID should not have changed
        let final_entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);
        assert_eq!(final_entry_id, initial_entry_id);

        // Create and enable log area
        let result = create_logarea();
        assert!(result.is_ok());

        let result = enable_logarea(log_max_level, 0, &mut data).await;
        assert!(result.is_ok());

        // Add a log entry
        entrylog(
            &"Test message\n".to_string().into_bytes(),
            Level::Trace,
            u64::MAX,
        );

        // Validate buffer structure
        let mut logareavector = LOGAREAPTR.lock();
        let data_buffer_ptr = logareavector[0];
        let data_buffer =
            unsafe { core::slice::from_raw_parts(data_buffer_ptr as *const u8, PAGE_SIZE) };

        // Check buffer header
        let header_bytes = &data_buffer[0..size_of::<LogAreaBufferHeader>()];
        let header: &LogAreaBufferHeader =
            unsafe { &*(header_bytes.as_ptr() as *const LogAreaBufferHeader) };
        let signature = header.signature;
        let vcpuindex = header.vcpuindex;
        let reserved = header.reserved;
        let startoffset = header.startoffset;
        let endoffset = header.endoffset;

        assert_eq!(signature, LOGAREA_SIGNATURE);
        assert_eq!(vcpuindex, 0);
        assert_eq!(reserved, 0);
        assert!(startoffset == size_of::<LogAreaBufferHeader>() as u64);
        assert!(endoffset > startoffset);

        // Check that there's a valid log entry
        let entry_bytes =
            &data_buffer[startoffset as usize..startoffset as usize + size_of::<LogEntryHeader>()];
        let entry: &LogEntryHeader = unsafe { &*(entry_bytes.as_ptr() as *const LogEntryHeader) };
        let log_entry_id = entry.log_entry_id;
        let mig_request_id = entry.mig_request_id;
        let loglevel = entry.loglevel;
        let length = entry.length;

        assert_eq!(log_entry_id, 1);
        assert_eq!(mig_request_id, u64::MAX);
        assert_eq!(loglevel, loglevel_to_u8(Level::Trace));
        assert_eq!(length, "Test message\n".len() as u32);

        logareavector.clear();
        unsafe {
            let _ = Box::from_raw(data_buffer_ptr as *mut [u8; PAGE_SIZE]);
        }
    }

    #[tokio::test]
    async fn test_entrylog_message_max_buffersize() {
        // Reset the global state for testing
        LOGGING_INFORMATION.num_vcpus.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_created
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_initialized
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION.logentry_id.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION.maxloglevel.store(0, Ordering::SeqCst);

        let mut data: Vec<u8> = Vec::new();
        let log_max_level: u8 = 5;
        let max_size = PAGE_SIZE - (size_of::<LogAreaBufferHeader>() + size_of::<LogEntryHeader>());

        // Create and enable log area
        let result = create_logarea();
        assert!(result.is_ok());

        let result = enable_logarea(log_max_level, 0, &mut data).await;
        assert!(result.is_ok());

        let max_message = "A".repeat(max_size);

        entrylog(&max_message.into_bytes(), Level::Info, 1);
        let after_entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);

        // Validate buffer structure
        let mut logareavector = LOGAREAPTR.lock();
        let data_buffer_ptr = logareavector[0];
        let data_buffer =
            unsafe { core::slice::from_raw_parts(data_buffer_ptr as *const u8, PAGE_SIZE) };

        // Check buffer header
        let header_bytes = &data_buffer[0..size_of::<LogAreaBufferHeader>()];
        let header: &LogAreaBufferHeader =
            unsafe { &*(header_bytes.as_ptr() as *const LogAreaBufferHeader) };
        let startoffset = header.startoffset;
        let endoffset = header.endoffset;
        let entry_bytes =
            &data_buffer[startoffset as usize..startoffset as usize + size_of::<LogEntryHeader>()];
        let entry: &LogEntryHeader = unsafe { &*(entry_bytes.as_ptr() as *const LogEntryHeader) };
        let length = entry.length;

        assert!(startoffset as usize == size_of::<LogAreaBufferHeader>());
        assert!(endoffset as usize == PAGE_SIZE);
        assert!(after_entry_id == 1);
        assert!(length as usize == max_size);

        logareavector.clear();
        unsafe {
            let _ = Box::from_raw(data_buffer_ptr as *mut [u8; PAGE_SIZE]);
        }
    }

    #[tokio::test]
    async fn test_entrylog_message_greaterthan_buffersize() {
        // Reset the global state for testing
        LOGGING_INFORMATION.num_vcpus.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_created
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_initialized
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION.logentry_id.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION.maxloglevel.store(0, Ordering::SeqCst);

        let mut data: Vec<u8> = Vec::new();
        let log_max_level: u8 = 5;

        // Create and enable log area
        let result = create_logarea();
        assert!(result.is_ok());

        let result = enable_logarea(log_max_level, 0, &mut data).await;
        assert!(result.is_ok());

        let before_entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);
        let oversized_message = "A".repeat(PAGE_SIZE);
        entrylog(&oversized_message.into_bytes(), Level::Info, 1);

        let after_entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);
        assert!(after_entry_id == 0);
        assert!(before_entry_id == after_entry_id);

        let mut logareavector = LOGAREAPTR.lock();
        let free_data_buffer = logareavector[0];
        logareavector.clear();
        unsafe {
            let _ = Box::from_raw(free_data_buffer as *mut [u8; PAGE_SIZE]);
        }
    }

    #[tokio::test]
    async fn test_entrylog_message_with_headerlen_left_at_bottom() {
        // Reset the global state for testing
        LOGGING_INFORMATION.num_vcpus.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_created
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_initialized
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION.logentry_id.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION.maxloglevel.store(0, Ordering::SeqCst);

        let mut data: Vec<u8> = Vec::new();
        let log_max_level: u8 = 5;

        // Create and enable log area
        let result = create_logarea();
        assert!(result.is_ok());

        let result = enable_logarea(log_max_level, 0, &mut data).await;
        assert!(result.is_ok());

        let headersizeleft =
            PAGE_SIZE - (size_of::<LogAreaBufferHeader>() + 2 * size_of::<LogEntryHeader>());

        // Fill the circular Buffer with message that leaves LogEntryHeaderSize at the end of Page
        let message = "Z".repeat(headersizeleft);
        entrylog(&message.into_bytes(), Level::Info, 1);
        let mut entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);

        // Validate buffer structure
        let logareavector = LOGAREAPTR.lock();
        let data_buffer_ptr = logareavector[0];
        let data_buffer =
            unsafe { core::slice::from_raw_parts(data_buffer_ptr as *const u8, PAGE_SIZE) };

        // Check buffer header
        let header_bytes = &data_buffer[0..size_of::<LogAreaBufferHeader>()];
        let header: &LogAreaBufferHeader =
            unsafe { &*(header_bytes.as_ptr() as *const LogAreaBufferHeader) };
        let startoffset = header.startoffset;
        let endoffset = header.endoffset;
        let entry_bytes =
            &data_buffer[startoffset as usize..startoffset as usize + size_of::<LogEntryHeader>()];
        let entry: &LogEntryHeader = unsafe { &*(entry_bytes.as_ptr() as *const LogEntryHeader) };
        let length = entry.length;

        assert!(entry_id == 1);
        assert!(length as usize == headersizeleft);
        assert!(startoffset as usize == size_of::<LogAreaBufferHeader>());
        assert!(endoffset as usize == PAGE_SIZE - size_of::<LogEntryHeader>());

        // Release the lock before calling entrylog to avoid deadlock
        drop(logareavector);

        // Fill new message with 1 byte, ideally this should start from beginning of circular buffer
        let newmessage = "Y".repeat(1);
        entrylog(&newmessage.into_bytes(), Level::Info, 2);
        entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);

        // Validate buffer structure
        let mut logareavector_2 = LOGAREAPTR.lock();
        let data_buffer_ptr_2 = logareavector_2[0];
        let data_buffer_2 =
            unsafe { core::slice::from_raw_parts(data_buffer_ptr_2 as *const u8, PAGE_SIZE) };

        // Check buffer header
        // Check buffer header
        let header_bytes_2 = &data_buffer_2[0..size_of::<LogAreaBufferHeader>()];
        let header_2: &LogAreaBufferHeader =
            unsafe { &*(header_bytes_2.as_ptr() as *const LogAreaBufferHeader) };
        let startoffset_2 = header_2.startoffset;
        let endoffset_2 = header_2.endoffset;
        let entry_bytes_2 = &data_buffer_2
            [startoffset_2 as usize..startoffset_2 as usize + size_of::<LogEntryHeader>()];
        let entry_2: &LogEntryHeader =
            unsafe { &*(entry_bytes_2.as_ptr() as *const LogEntryHeader) };
        let length_2 = entry_2.length;

        assert!(entry_id == 2);
        assert!(length_2 as usize == 1);
        assert!(startoffset_2 as usize == size_of::<LogAreaBufferHeader>());
        assert!(
            endoffset_2 as usize
                == size_of::<LogAreaBufferHeader>()
                    + size_of::<LogEntryHeader>()
                    + length_2 as usize
        );
        logareavector_2.clear();
        unsafe {
            let _ = Box::from_raw(data_buffer_ptr_2 as *mut [u8; PAGE_SIZE]);
        }
    }

    #[tokio::test]
    async fn test_entrylog_message_with_lessthan_headerlen_at_bottom() {
        // Reset the global state for testing
        LOGGING_INFORMATION.num_vcpus.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_created
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_initialized
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION.logentry_id.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION.maxloglevel.store(0, Ordering::SeqCst);

        let mut data: Vec<u8> = Vec::new();
        let log_max_level: u8 = 5;

        // Create and enable log area
        let result = create_logarea();
        assert!(result.is_ok());

        let result = enable_logarea(log_max_level, 0, &mut data).await;
        assert!(result.is_ok());

        let headersizeleft_10bytes =
            PAGE_SIZE - (size_of::<LogAreaBufferHeader>() + size_of::<LogEntryHeader>()) - 10;

        // Fill the circular Buffer with message that leaves 10 bytes at the end of Page
        let message = "Z".repeat(headersizeleft_10bytes);
        entrylog(&message.into_bytes(), Level::Info, 1);
        let mut entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);

        // Validate buffer structure
        let logareavector = LOGAREAPTR.lock();
        let data_buffer_ptr = logareavector[0];
        let data_buffer =
            unsafe { core::slice::from_raw_parts(data_buffer_ptr as *const u8, PAGE_SIZE) };

        // Check buffer header
        let header_bytes = &data_buffer[0..size_of::<LogAreaBufferHeader>()];
        let header: &LogAreaBufferHeader =
            unsafe { &*(header_bytes.as_ptr() as *const LogAreaBufferHeader) };
        let startoffset = header.startoffset;
        let endoffset = header.endoffset;
        let entry_bytes =
            &data_buffer[startoffset as usize..startoffset as usize + size_of::<LogEntryHeader>()];
        let entry: &LogEntryHeader = unsafe { &*(entry_bytes.as_ptr() as *const LogEntryHeader) };
        let length = entry.length;

        assert!(entry_id == 1);
        assert!(length as usize == headersizeleft_10bytes);
        assert!(startoffset as usize == size_of::<LogAreaBufferHeader>());
        assert!(endoffset as usize == PAGE_SIZE - 10);

        // Release the lock before calling entrylog to avoid deadlock
        drop(logareavector);

        // Fill new message with 1 byte, ideally this should start from beginning of circular buffer
        let newmessage = "Y".repeat(1);
        entrylog(&newmessage.into_bytes(), Level::Info, 2);
        entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);

        // Validate buffer structure
        let mut logareavector_2 = LOGAREAPTR.lock();
        let data_buffer_ptr_2 = logareavector_2[0];
        let data_buffer_2 =
            unsafe { core::slice::from_raw_parts(data_buffer_ptr_2 as *const u8, PAGE_SIZE) };

        // Check buffer header
        let header_bytes_2 = &data_buffer_2[0..size_of::<LogAreaBufferHeader>()];
        let header_2: &LogAreaBufferHeader =
            unsafe { &*(header_bytes_2.as_ptr() as *const LogAreaBufferHeader) };
        let startoffset_2 = header_2.startoffset;
        let endoffset_2 = header_2.endoffset;
        let entry_bytes_2 = &data_buffer_2
            [startoffset_2 as usize..startoffset_2 as usize + size_of::<LogEntryHeader>()];
        let entry_2: &LogEntryHeader =
            unsafe { &*(entry_bytes_2.as_ptr() as *const LogEntryHeader) };
        let length_2 = entry_2.length;

        assert!(entry_id == 2);
        assert!(length_2 as usize == 1);
        assert!(startoffset_2 as usize == size_of::<LogAreaBufferHeader>());
        assert!(
            endoffset_2 as usize
                == size_of::<LogAreaBufferHeader>()
                    + size_of::<LogEntryHeader>()
                    + length_2 as usize
        );
        logareavector_2.clear();
        unsafe {
            let _ = Box::from_raw(data_buffer_ptr_2 as *mut [u8; PAGE_SIZE]);
        }
    }

    #[tokio::test]
    async fn test_entrylog_message_with_startoffset_at_invalid_message() {
        // Reset the global state for testing
        LOGGING_INFORMATION.num_vcpus.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_created
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION
            .logarea_initialized
            .store(false, Ordering::SeqCst);
        LOGGING_INFORMATION.logentry_id.store(0, Ordering::SeqCst);
        LOGGING_INFORMATION.maxloglevel.store(0, Ordering::SeqCst);

        let mut data: Vec<u8> = Vec::new();
        let log_max_level: u8 = 5;

        // Create and enable log area
        let result = create_logarea();
        assert!(result.is_ok());

        let result = enable_logarea(log_max_level, 0, &mut data).await;
        assert!(result.is_ok());

        let headersizeleft_50bytes =
            PAGE_SIZE - (size_of::<LogAreaBufferHeader>() + size_of::<LogEntryHeader>()) - 50;

        // Fill the circular Buffer with message that leaves 50 bytes at the end of Page
        let message = "Z".repeat(headersizeleft_50bytes);
        entrylog(&message.into_bytes(), Level::Info, 1);
        let mut entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);

        // Validate buffer structure
        let logareavector = LOGAREAPTR.lock();
        let data_buffer_ptr = logareavector[0];
        let data_buffer =
            unsafe { core::slice::from_raw_parts(data_buffer_ptr as *const u8, PAGE_SIZE) };

        // Check buffer header
        let header_bytes = &data_buffer[0..size_of::<LogAreaBufferHeader>()];
        let header: &LogAreaBufferHeader =
            unsafe { &*(header_bytes.as_ptr() as *const LogAreaBufferHeader) };
        let startoffset = header.startoffset;
        let endoffset = header.endoffset;
        let entry_bytes =
            &data_buffer[startoffset as usize..startoffset as usize + size_of::<LogEntryHeader>()];
        let entry: &LogEntryHeader = unsafe { &*(entry_bytes.as_ptr() as *const LogEntryHeader) };
        let length = entry.length;

        assert!(entry_id == 1);
        assert!(length as usize == headersizeleft_50bytes);
        assert!(startoffset as usize == size_of::<LogAreaBufferHeader>());
        assert!(endoffset as usize == PAGE_SIZE - 50);

        // Release the lock before calling entrylog to avoid deadlock
        drop(logareavector);

        // Fill new message with 100 byte, ideally this should start from beginning of circular buffer
        let newmessage = "Y".repeat(100);
        entrylog(&newmessage.into_bytes(), Level::Info, 2);
        entry_id = LOGGING_INFORMATION.logentry_id.load(Ordering::SeqCst);

        // Validate buffer structure
        let mut logareavector_2 = LOGAREAPTR.lock();
        let data_buffer_ptr_2 = logareavector_2[0];
        let data_buffer_2 =
            unsafe { core::slice::from_raw_parts(data_buffer_ptr_2 as *const u8, PAGE_SIZE) };

        // Check buffer header
        let header_bytes_2 = &data_buffer_2[0..size_of::<LogAreaBufferHeader>()];
        let header_2: &LogAreaBufferHeader =
            unsafe { &*(header_bytes_2.as_ptr() as *const LogAreaBufferHeader) };
        let startoffset_2 = header_2.startoffset;
        let endoffset_2 = header_2.endoffset;
        let entry_bytes_2 = &data_buffer_2
            [startoffset_2 as usize..startoffset_2 as usize + size_of::<LogEntryHeader>()];
        let entry_2: &LogEntryHeader =
            unsafe { &*(entry_bytes_2.as_ptr() as *const LogEntryHeader) };
        let length_2 = entry_2.length;

        assert!(entry_id == 2);
        assert!(length_2 as usize == 100);
        assert!(startoffset_2 as usize == size_of::<LogAreaBufferHeader>());
        assert!(
            endoffset_2 as usize
                == size_of::<LogAreaBufferHeader>()
                    + size_of::<LogEntryHeader>()
                    + length_2 as usize
        );
        logareavector_2.clear();
        unsafe {
            let _ = Box::from_raw(data_buffer_ptr_2 as *mut [u8; PAGE_SIZE]);
        }
    }
}
