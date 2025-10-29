// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg(feature = "vmcall-raw")]

use crate::migration::MigrationResult;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use lazy_static::lazy_static;
use log::Level;
use raw_cpuid::CpuId;
use spin::Mutex;
use td_payload::mm::shared::alloc_shared_pages;
use tdx_tdcall::{td_call, TdcallArgs};
use zerocopy::{transmute_ref, AsBytes, FromBytes, FromZeroes};
const PAGE_SIZE: usize = 0x1_000;
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
    const TDVMCALL_TDINFO: u64 = 0x00001;
    let mut args = TdcallArgs {
        rax: TDVMCALL_TDINFO,
        ..Default::default()
    };

    let ret = td_call(&mut args);
    if ret != TDCALL_STATUS_SUCCESS {
        return Err(MigrationResult::TdxModuleError);
    }

    let num_vcpus = args.r8 as u32;

    LOGGING_INFORMATION
        .num_vcpus
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            v.checked_add(num_vcpus)
        })
        .unwrap();
    let mut logareavector = LOGAREAPTR.lock();
    for _index in 0..num_vcpus {
        let data_buffer = unsafe { alloc_shared_pages(1).ok_or(MigrationResult::OutOfResource)? };
        logareavector.push(data_buffer);
    }
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
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                v.checked_add(log_max_level)
            })
            .unwrap();
        data.extend_from_slice(&num_vcpus.to_le_bytes());
        data.extend_from_slice(&padding.to_le_bytes());
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
            let cpuid = CpuId::new();
            if let Some(feature_info) = cpuid.get_feature_info() {
                let currvcpuindex: u32 = feature_info.initial_local_apic_id().into();
                let logareavector = LOGAREAPTR.lock();
                let data_buffer = logareavector[currvcpuindex as usize];
                let data_buffer =
                    unsafe { core::slice::from_raw_parts_mut(data_buffer as *mut u8, PAGE_SIZE) };
                let vcpuindex: u32 = u32::from_le_bytes(data_buffer[16..20].try_into().unwrap());
                if currvcpuindex == vcpuindex {
                    LOGGING_INFORMATION
                        .logentry_id
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
                        .unwrap();
                    let start_offset: u64 =
                        u64::from_le_bytes(data_buffer[24..32].try_into().unwrap());
                    let end_offset: u64 =
                        u64::from_le_bytes(data_buffer[32..40].try_into().unwrap());
                    let mut currentstartoffset: usize = start_offset as usize;
                    let mut currentendoffset: usize = end_offset as usize;
                    if currentendoffset + LOGENTRYHEADERSIZE + msg.len() > PAGE_SIZE - 1
                        || currentendoffset < currentstartoffset
                    {
                        if currentendoffset + LOGENTRYHEADERSIZE + msg.len() > PAGE_SIZE - 1 {
                            data_buffer[currentendoffset..PAGE_SIZE - 1].fill(0);
                            currentendoffset = LOGAREABUFFERHEADERSIZE;
                        }
                        let mut reqdatasize = LOGENTRYHEADERSIZE + msg.len();
                        while reqdatasize > 0 {
                            if currentstartoffset + LOGENTRYHEADERSIZE > PAGE_SIZE - 1 {
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
    }
}
