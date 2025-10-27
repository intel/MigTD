// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "vmcall-raw")]
use crate::migration::event::VMCALL_MIG_REPORTSTATUS_FLAGS;
use alloc::collections::BTreeSet;
#[cfg(feature = "policy_v2")]
use async_io::{AsyncRead, AsyncWrite};
#[cfg(feature = "vmcall-raw")]
use core::sync::atomic::AtomicBool;
#[cfg(any(feature = "vmcall-interrupt", feature = "vmcall-raw"))]
use core::sync::atomic::Ordering;
use core::{future::poll_fn, mem::size_of, task::Poll};
#[cfg(any(feature = "vmcall-interrupt", feature = "vmcall-raw"))]
use event::VMCALL_SERVICE_FLAG;
use lazy_static::lazy_static;
use spin::Mutex;
use td_payload::mm::shared::SharedMemory;
use tdx_tdcall::{
    td_call,
    tdx::{self, tdcall_servtd_wr},
    TdcallArgs,
};
#[cfg(feature = "vmcall-raw")]
use tdx_tdcall::{tdreport::TdxReport, tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE};
use zerocopy::AsBytes;

type Result<T> = core::result::Result<T, MigrationResult>;

use super::{data::*, *};
#[cfg(not(feature = "spdm_attestation"))]
use crate::ratls;
#[cfg(feature = "spdm_attestation")]
use crate::spdm;

const TDCALL_STATUS_SUCCESS: u64 = 0;
#[cfg(feature = "vmcall-raw")]
const PAGE_SIZE: usize = 0x1_000;
const TDCS_FIELD_MIG_DEC_KEY: u64 = 0x9810_0003_0000_0010;
const TDCS_FIELD_MIG_ENC_KEY: u64 = 0x9810_0003_0000_0018;
const TDCS_FIELD_MIG_VERSION: u64 = 0x9810_0001_0000_0020;
// TDX Module global-scope metadata field
const GSM_FIELD_MIN_EXPORT_VERSION: u64 = 0x2000000100000001;
const GSM_FIELD_MAX_EXPORT_VERSION: u64 = 0x2000000100000002;
const GSM_FIELD_MIN_IMPORT_VERSION: u64 = 0x2000000100000003;
const GSM_FIELD_MAX_IMPORT_VERSION: u64 = 0x2000000100000004;

#[cfg(feature = "vmcall-raw")]
#[repr(C, align(1024))]
#[derive(Debug)]
struct TdxReportBuf(TdxReport);

#[cfg(feature = "vmcall-raw")]
#[repr(C, align(64))]
struct AdditionalDataBuf([u8; TD_REPORT_ADDITIONAL_DATA_SIZE]);

#[cfg(feature = "vmcall-raw")]
const TDX_VMCALL_VMM_SUCCESS: u8 = 1;

#[cfg(feature = "vmcall-raw")]
#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
pub enum DataStatusOperation {
    StartMigration = 1,
    GetReportData = 3,
    EnableLogArea = 4,
}

#[cfg(feature = "vmcall-raw")]
fn u8_to_migration_result(value: u8) -> Option<MigrationResult> {
    match value {
        0 => Some(MigrationResult::Success),
        1 => Some(MigrationResult::InvalidParameter),
        2 => Some(MigrationResult::Unsupported),
        3 => Some(MigrationResult::OutOfResource),
        4 => Some(MigrationResult::TdxModuleError),
        5 => Some(MigrationResult::NetworkError),
        6 => Some(MigrationResult::SecureSessionError),
        7 => Some(MigrationResult::MutualAttestationError),
        8 => Some(MigrationResult::PolicyUnsatisfiedError),
        9 => Some(MigrationResult::InvalidPolicyError),
        10 => Some(MigrationResult::VmmCanceled),
        11 => Some(MigrationResult::VmmInternalError),
        12 => Some(MigrationResult::UnsupportedOperationError),
        _ => None, // Handle cases where the u8 doesn't map to a valid Level
    }
}

#[cfg(feature = "vmcall-raw")]
fn parse_uuid(buf: &[u8]) -> [u64; 4] {
    [
        u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        u64::from_le_bytes(buf[24..32].try_into().unwrap()),
    ]
}

lazy_static! {
    pub static ref REQUESTS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
}

pub struct ExchangeInformation {
    pub min_ver: u16,
    pub max_ver: u16,
    pub key: MigrationSessionKey,
}

impl Default for ExchangeInformation {
    fn default() -> Self {
        Self {
            key: MigrationSessionKey::new(),
            min_ver: 0,
            max_ver: 0,
        }
    }
}

#[cfg(not(feature = "spdm_attestation"))]
impl ExchangeInformation {
    fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, size_of::<Self>()) }
    }
}

pub fn query() -> Result<()> {
    // Allocate one shared page for command and response buffer
    let mut cmd_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
    let mut rsp_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

    // Set Migration query command buffer
    let mut cmd = VmcallServiceCommand::new(cmd_mem.as_mut_bytes(), VMCALL_SERVICE_COMMON_GUID)
        .ok_or(MigrationResult::InvalidParameter)?;
    let query = ServiceMigWaitForReqCommand {
        version: 0,
        command: QUERY_COMMAND,
        reserved: [0; 2],
    };
    cmd.write(query.as_bytes())?;
    cmd.write(VMCALL_SERVICE_MIGTD_GUID.as_bytes())?;
    let _ = VmcallServiceResponse::new(rsp_mem.as_mut_bytes(), VMCALL_SERVICE_COMMON_GUID)
        .ok_or(MigrationResult::InvalidParameter)?;

    #[cfg(feature = "vmcall-interrupt")]
    {
        tdx::tdvmcall_service(
            cmd_mem.as_bytes(),
            rsp_mem.as_mut_bytes(),
            event::VMCALL_SERVICE_VECTOR as u64,
            0,
        )?;
        event::wait_for_event(&event::VMCALL_SERVICE_FLAG);
    }
    #[cfg(not(feature = "vmcall-interrupt"))]
    tdx::tdvmcall_service(cmd_mem.as_bytes(), rsp_mem.as_mut_bytes(), 0, 0)?;

    let private_mem = rsp_mem
        .copy_to_private_shadow()
        .ok_or(MigrationResult::OutOfResource)?;

    // Parse the response data
    // Check the GUID of the reponse
    let rsp =
        VmcallServiceResponse::try_read(private_mem).ok_or(MigrationResult::InvalidParameter)?;
    if rsp.read_guid() != VMCALL_SERVICE_COMMON_GUID.as_bytes() {
        return Err(MigrationResult::InvalidParameter);
    }
    let query = rsp
        .read_data::<ServiceQueryResponse>(0)
        .ok_or(MigrationResult::InvalidParameter)?;

    if query.command != QUERY_COMMAND || &query.guid != VMCALL_SERVICE_MIGTD_GUID.as_bytes() {
        return Err(MigrationResult::InvalidParameter);
    }
    if query.status != 0 {
        return Err(MigrationResult::Unsupported);
    }

    log::info!("Migration is supported by VMM\n");
    Ok(())
}

#[cfg(feature = "vmcall-raw")]
fn process_buffer(buffer: &mut [u8]) -> (u64, u32) {
    assert!(buffer.len() >= 12, "Buffer too small!");
    let (header, _payload_buffer) = buffer.split_at_mut(12); // Split at 12th byte

    let data_status = u64::from_le_bytes(header[0..8].try_into().unwrap()); // First 8 bytes
    let data_length = u32::from_le_bytes(header[8..12].try_into().unwrap()); // Next 4 bytes

    (data_status, data_length)
}

#[cfg(feature = "vmcall-raw")]
pub async fn wait_for_request() -> Result<WaitForRequestResponse> {
    let data_status: u64 = 0;
    let data_length: u32 = 0;

    let mut data_buffer = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

    let data_buffer = data_buffer.as_mut_bytes();

    data_buffer[0..8].copy_from_slice(&u64::to_le_bytes(data_status));
    data_buffer[8..12].copy_from_slice(&u32::to_le_bytes(data_length));

    tdx::tdvmcall_migtd_waitforrequest(data_buffer, event::VMCALL_SERVICE_VECTOR)?;

    poll_fn(|_cx| {
        if VMCALL_SERVICE_FLAG.load(Ordering::SeqCst) {
            VMCALL_SERVICE_FLAG.store(false, Ordering::SeqCst);
        } else {
            return Poll::Pending;
        }

        let (data_status, data_length) = process_buffer(data_buffer);

        let data_status_bytes = data_status.to_le_bytes();
        if data_status_bytes[0] != TDX_VMCALL_VMM_SUCCESS {
            return Poll::Pending;
        }

        let operation: u8 = data_status_bytes[1];
        if operation == DataStatusOperation::StartMigration as u8 {
            // data_length should be MigtdMigrationInformation
            let expected_datalength = size_of::<MigtdMigrationInformation>();
            if data_length != expected_datalength as u32 {
                return Poll::Pending;
            }
            let slice = &data_buffer[12..12 + data_length as usize];
            let mig_request_id = u64::from_le_bytes(slice[0..8].try_into().unwrap());

            VMCALL_MIG_REPORTSTATUS_FLAGS
                .lock()
                .insert(mig_request_id, AtomicBool::new(false));

            let wfr_info = MigtdMigrationInformation {
                mig_request_id,
                migration_source: slice[8],
                _pad: slice[9..16].try_into().unwrap(),
                target_td_uuid: parse_uuid(&slice[16..48]),
                binding_handle: u64::from_le_bytes(slice[48..56].try_into().unwrap()),
            };

            let wfr_info = MigrationInformation { mig_info: wfr_info };

            if REQUESTS.lock().contains(&mig_request_id) {
                Poll::Pending
            } else {
                REQUESTS.lock().insert(mig_request_id);
                Poll::Ready(Ok(WaitForRequestResponse::StartMigration(wfr_info)))
            }
        } else if operation == DataStatusOperation::GetReportData as u8 {
            let mut reportdata: [u8; 64] = [0; 64];
            let mut mig_request_id: u64 = 0;
            // data_length should MigRequestID (+ optional REPORTDATA)
            if data_length != size_of_val(&mig_request_id) as u32
                && data_length
                    != (size_of_val(&mig_request_id) + TD_REPORT_ADDITIONAL_DATA_SIZE) as u32
            {
                return Poll::Pending;
            }
            let slice = &data_buffer[12..12 + data_length as usize];
            mig_request_id = u64::from_le_bytes(slice[0..8].try_into().unwrap());

            if data_length == (size_of_val(&mig_request_id) + TD_REPORT_ADDITIONAL_DATA_SIZE) as u32
            {
                reportdata = slice[8..72].try_into().unwrap();
            }

            VMCALL_MIG_REPORTSTATUS_FLAGS
                .lock()
                .insert(mig_request_id, AtomicBool::new(false));

            let wfr_info = ReportInfo {
                mig_request_id,
                reportdata,
            };

            if REQUESTS.lock().contains(&mig_request_id) {
                Poll::Pending
            } else {
                REQUESTS.lock().insert(mig_request_id);
                Poll::Ready(Ok(WaitForRequestResponse::GetTdReport(wfr_info)))
            }
        } else if operation == DataStatusOperation::EnableLogArea as u8 {
            let expected_datalength = size_of::<EnableLogAreaInfo>();
            if data_length != expected_datalength as u32 {
                return Poll::Pending;
            }

            let slice = &data_buffer[12..12 + data_length as usize];
            let mig_request_id = u64::from_le_bytes(slice[0..8].try_into().unwrap());

            let wfr_info = EnableLogAreaInfo {
                mig_request_id,
                log_max_level: slice[8],
                reserved: slice[9..16].try_into().unwrap(),
            };

            if REQUESTS.lock().contains(&mig_request_id) {
                Poll::Pending
            } else {
                REQUESTS.lock().insert(mig_request_id);
                Poll::Ready(Ok(WaitForRequestResponse::EnableLogArea(wfr_info)))
            }
        } else {
            Poll::Pending
        }
    })
    .await
}

#[cfg(not(feature = "vmcall-raw"))]
pub async fn wait_for_request() -> Result<MigrationInformation> {
    // Allocate shared page for command and response buffer
    let mut cmd_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
    let mut rsp_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

    // Set Migration wait for request command buffer
    let mut cmd = VmcallServiceCommand::new(cmd_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
        .ok_or(MigrationResult::InvalidParameter)?;
    let wfr = ServiceMigWaitForReqCommand {
        version: 0,
        command: MIG_COMMAND_WAIT,
        reserved: [0; 2],
    };
    cmd.write(wfr.as_bytes())?;
    let _ = VmcallServiceResponse::new(rsp_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
        .ok_or(MigrationResult::InvalidParameter)?;

    #[cfg(feature = "vmcall-interrupt")]
    {
        tdx::tdvmcall_service(
            cmd_mem.as_bytes(),
            rsp_mem.as_mut_bytes(),
            event::VMCALL_SERVICE_VECTOR as u64,
            0,
        )?;
    }

    poll_fn(|_cx| {
        #[cfg(not(feature = "vmcall-interrupt"))]
        tdx::tdvmcall_service(cmd_mem.as_bytes(), rsp_mem.as_mut_bytes(), 0, 0)?;

        #[cfg(feature = "vmcall-interrupt")]
        if VMCALL_SERVICE_FLAG.load(Ordering::SeqCst) {
            VMCALL_SERVICE_FLAG.store(false, Ordering::SeqCst);
        } else {
            return Poll::Pending;
        }

        let private_mem = rsp_mem
            .copy_to_private_shadow()
            .ok_or(MigrationResult::OutOfResource)?;

        // Parse out the response data
        let rsp = VmcallServiceResponse::try_read(private_mem)
            .ok_or(MigrationResult::InvalidParameter)?;
        // Check the GUID of the reponse
        if rsp.read_guid() != VMCALL_SERVICE_MIGTD_GUID.as_bytes() {
            return Poll::Ready(Err(MigrationResult::InvalidParameter));
        }
        let wfr = rsp
            .read_data::<ServiceMigWaitForReqResponse>(0)
            .ok_or(MigrationResult::InvalidParameter)?;
        if wfr.command != MIG_COMMAND_WAIT {
            return Poll::Ready(Err(MigrationResult::InvalidParameter));
        }
        if wfr.operation == 1 {
            let mig_info =
                read_mig_info(&private_mem[24 + size_of::<ServiceMigWaitForReqResponse>()..])
                    .ok_or(MigrationResult::InvalidParameter)?;
            let request_id = mig_info.mig_info.mig_request_id;

            if REQUESTS.lock().contains(&request_id) {
                Poll::Pending
            } else {
                REQUESTS.lock().insert(request_id);
                Poll::Ready(Ok(mig_info))
            }
        } else if wfr.operation == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Err(MigrationResult::InvalidParameter))
        }
    })
    .await
}

pub fn shutdown() -> Result<()> {
    // Allocate shared page for command and response buffer
    let mut cmd_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
    let mut rsp_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

    // Set Command
    let mut cmd = VmcallServiceCommand::new(cmd_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
        .ok_or(MigrationResult::InvalidParameter)?;

    let sd = ServiceMigWaitForReqShutdown {
        version: 0,
        command: MIG_COMMAND_SHUT_DOWN,
        reserved: [0; 2],
    };
    cmd.write(sd.as_bytes())?;
    tdx::tdvmcall_service(cmd_mem.as_bytes(), rsp_mem.as_mut_bytes(), 0, 0)?;
    Ok(())
}

#[cfg(feature = "vmcall-raw")]
pub async fn get_tdreport(
    additional_data: &[u8; TD_REPORT_ADDITIONAL_DATA_SIZE],
    data: &mut Vec<u8>,
) -> Result<()> {
    const TDVMCALL_TDREPORT: u64 = 0x00004;
    let mut report_buf = TdxReportBuf(TdxReport::default());
    let additional_data_buf = AdditionalDataBuf(*additional_data);
    let tdreportsize = size_of::<TdxReport>();

    let mut args = TdcallArgs {
        rax: TDVMCALL_TDREPORT,
        rcx: &mut report_buf as *mut _ as u64,
        rdx: &additional_data_buf as *const _ as u64,
        ..Default::default()
    };

    let ret = td_call(&mut args);
    if ret != TDCALL_STATUS_SUCCESS {
        return Err(MigrationResult::TdxModuleError);
    }

    data.extend_from_slice(report_buf.0.as_bytes());
    if data.len() != tdreportsize {
        return Err(MigrationResult::InvalidParameter);
    }
    Ok(())
}

#[cfg(feature = "vmcall-raw")]
pub async fn report_status(status: u8, request_id: u64, data: &Vec<u8>) -> Result<()> {
    let data_status: u64 = 0;
    let mut reportstatus = ReportStatusResponse::new()
        .with_pre_migration_status(0)
        .with_error_code(0)
        .with_reserved(0);
    let mut data_length: u32 = 0;
    let mut data_buffer = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

    if let Some(value) = u8_to_migration_result(status) {
        if value != MigrationResult::Success {
            reportstatus = reportstatus
                .with_pre_migration_status(1)
                .with_error_code(status);
        }
    } else {
        return Err(MigrationResult::InvalidParameter);
    }

    if data.len() > 0 && data.len() < (PAGE_SIZE - 12) {
        data_length += data.len() as u32;
    }

    let data_buffer = data_buffer.as_mut_bytes();
    data_buffer[0..8].copy_from_slice(&u64::to_le_bytes(data_status));
    data_buffer[8..12].copy_from_slice(&u32::to_le_bytes(data_length));
    if data.len() > 0 && data.len() < (PAGE_SIZE - 12) {
        data_buffer[12..data.len() + 12].copy_from_slice(&data[0..data.len()]);
    }

    tdx::tdvmcall_migtd_reportstatus(
        request_id,
        reportstatus.into(),
        data_buffer,
        event::VMCALL_SERVICE_VECTOR,
    )?;

    poll_fn(|_cx| -> Poll<Result<()>> {
        if let Some(flag) = VMCALL_MIG_REPORTSTATUS_FLAGS.lock().get(&request_id) {
            if flag.load(Ordering::SeqCst) {
                flag.store(false, Ordering::SeqCst);
            } else {
                return Poll::Pending;
            }
        } else {
            return Poll::Pending;
        }

        let (data_status, _data_length) = process_buffer(data_buffer);
        let data_status_bytes = data_status.to_le_bytes();

        if data_status_bytes[0] != TDX_VMCALL_VMM_SUCCESS {
            return Poll::Pending;
        }

        VMCALL_MIG_REPORTSTATUS_FLAGS.lock().remove(&request_id);

        Poll::Ready(Ok(()))
    })
    .await
}

#[cfg(not(feature = "vmcall-raw"))]
pub fn report_status(status: u8, request_id: u64) -> Result<()> {
    // Allocate shared page for command and response buffer
    let mut cmd_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
    let mut rsp_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

    // Set Command
    let mut cmd = VmcallServiceCommand::new(cmd_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
        .ok_or(MigrationResult::InvalidParameter)?;

    let rs = ServiceMigReportStatusCommand {
        version: 0,
        command: MIG_COMMAND_REPORT_STATUS,
        operation: 1,
        status,
        mig_request_id: request_id,
    };

    cmd.write(rs.as_bytes())?;

    let _ = VmcallServiceResponse::new(rsp_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
        .ok_or(MigrationResult::InvalidParameter)?;

    tdx::tdvmcall_service(cmd_mem.as_bytes(), rsp_mem.as_mut_bytes(), 0, 0)?;

    let private_mem = rsp_mem
        .copy_to_private_shadow()
        .ok_or(MigrationResult::OutOfResource)?;

    // Parse the response data
    // Check the GUID of the reponse
    let rsp =
        VmcallServiceResponse::try_read(private_mem).ok_or(MigrationResult::InvalidParameter)?;

    if rsp.read_guid() != VMCALL_SERVICE_MIGTD_GUID.as_bytes() {
        return Err(MigrationResult::InvalidParameter);
    }
    let query = rsp
        .read_data::<ServiceMigReportStatusResponse>(0)
        .ok_or(MigrationResult::InvalidParameter)?;

    // Ensure the response matches the command
    if query.command != MIG_COMMAND_REPORT_STATUS {
        return Err(MigrationResult::InvalidParameter);
    }
    Ok(())
}

#[cfg(feature = "policy_v2")]
#[repr(C)]
struct MigtdMessageHeader {
    pub r#type: u8,
    pub reserved: [u8; 3],
    pub length: u32, // Length of the command data
}

#[cfg(feature = "policy_v2")]
impl MigtdMessageHeader {
    const EXCHANGE_POLICY_TYPE: u8 = 1;
    const START_SESSION_TYPE: u8 = 2;

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    pub fn read_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        let header = MigtdMessageHeader {
            r#type: bytes[0],
            reserved: bytes[1..4].try_into().unwrap(),
            length: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        };
        Some(header)
    }
}

#[cfg(feature = "policy_v2")]
async fn send_policy<T: AsyncRead + AsyncWrite + Unpin>(
    policy: &[u8],
    transport: &mut T,
) -> Result<()> {
    let header = MigtdMessageHeader {
        r#type: MigtdMessageHeader::EXCHANGE_POLICY_TYPE,
        reserved: [0u8; 3],
        length: policy.len() as u32,
    };

    let mut sent = 0;
    while sent < header.as_bytes().len() {
        let n = transport
            .write(header.as_bytes())
            .await
            .map_err(|_| MigrationResult::NetworkError)?;
        sent += n;
    }

    sent = 0;
    while sent < policy.len() {
        let n = transport
            .write(&policy[sent..])
            .await
            .map_err(|_| MigrationResult::NetworkError)?;
        sent += n;
    }
    Ok(())
}

#[cfg(feature = "policy_v2")]
async fn receive_policy<T: AsyncRead + AsyncWrite + Unpin>(transport: &mut T) -> Result<Vec<u8>> {
    let mut header_buffer = [0u8; size_of::<MigtdMessageHeader>()];

    let mut recvd = 0;
    while recvd < header_buffer.len() {
        let n = transport
            .read(&mut header_buffer[recvd..])
            .await
            .map_err(|_| MigrationResult::NetworkError)?;
        recvd += n;
    }

    let header = MigtdMessageHeader::read_from_bytes(&header_buffer)
        .ok_or(MigrationResult::InvalidParameter)?;
    if header.r#type != MigtdMessageHeader::EXCHANGE_POLICY_TYPE {
        return Err(MigrationResult::InvalidParameter);
    }

    let policy_size = header.length as usize;
    let mut policy = vec![0u8; policy_size];
    recvd = 0;
    while recvd < policy_size {
        let n = transport
            .read(&mut policy[recvd..])
            .await
            .map_err(|_| MigrationResult::NetworkError)?;
        recvd += n;
    }
    Ok(policy)
}

#[cfg(feature = "policy_v2")]
async fn send_start_session_command<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
) -> Result<()> {
    let header = MigtdMessageHeader {
        r#type: MigtdMessageHeader::START_SESSION_TYPE,
        reserved: [0u8; 3],
        length: 0,
    };

    let mut sent = 0;
    while sent < header.as_bytes().len() {
        let n = transport
            .write(header.as_bytes())
            .await
            .map_err(|_| MigrationResult::NetworkError)?;
        sent += n;
    }
    Ok(())
}

#[cfg(feature = "policy_v2")]
async fn receive_start_session_command<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
) -> Result<()> {
    let mut header_buffer = [0u8; size_of::<MigtdMessageHeader>()];

    let mut recvd = 0;
    while recvd < header_buffer.len() {
        let n = transport
            .read(&mut header_buffer[recvd..])
            .await
            .map_err(|_| MigrationResult::NetworkError)?;
        recvd += n;
    }

    let command = MigtdMessageHeader::read_from_bytes(&header_buffer)
        .ok_or(MigrationResult::InvalidParameter)?;
    if command.r#type != MigtdMessageHeader::START_SESSION_TYPE {
        return Err(MigrationResult::InvalidParameter);
    }
    Ok(())
}

#[cfg(feature = "policy_v2")]
async fn pre_session_data_exchange<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
) -> Result<Vec<u8>> {
    use crate::config;

    let policy = config::get_policy().ok_or(MigrationResult::InvalidParameter)?;
    send_policy(policy, transport).await?;
    let remote_policy = receive_policy(transport).await?;

    send_start_session_command(transport).await?;
    receive_start_session_command(transport).await?;

    Ok(remote_policy)
}

#[cfg(feature = "main")]
pub async fn exchange_msk(info: &MigrationInformation) -> Result<()> {
    #[cfg(feature = "policy_v2")]
    let mut transport;
    #[cfg(not(feature = "policy_v2"))]
    let transport;

    #[cfg(feature = "vmcall-raw")]
    {
        use vmcall_raw::stream::VmcallRaw;
        let mut vmcall_raw_instance = VmcallRaw::new_with_mid(info.mig_info.mig_request_id)
            .map_err(|_e| MigrationResult::InvalidParameter)?;

        vmcall_raw_instance
            .connect()
            .await
            .map_err(|_e| MigrationResult::InvalidParameter)?;
        transport = vmcall_raw_instance;
    }

    #[cfg(feature = "virtio-serial")]
    {
        use virtio_serial::VirtioSerialPort;
        const VIRTIO_SERIAL_PORT_ID: u32 = 1;

        let port = VirtioSerialPort::new(VIRTIO_SERIAL_PORT_ID);
        port.open()?;
        transport = port;
    };

    #[cfg(not(feature = "virtio-serial"))]
    #[cfg(not(feature = "vmcall-raw"))]
    {
        use vsock::{stream::VsockStream, VsockAddr};

        #[cfg(feature = "virtio-vsock")]
        let mut vsock = VsockStream::new()?;

        #[cfg(feature = "vmcall-vsock")]
        let mut vsock = VsockStream::new_with_cid(
            info.mig_socket_info.mig_td_cid,
            info.mig_info.mig_request_id,
        )?;

        // Establish the vsock connection with host
        vsock
            .connect(&VsockAddr::new(
                info.mig_socket_info.mig_td_cid as u32,
                info.mig_socket_info.mig_channel_port,
            ))
            .await?;
        transport = vsock;
    };

    // Exchange policy firstly because of the message size limitation of TLS protocol
    #[cfg(feature = "policy_v2")]
    let remote_policy = pre_session_data_exchange(&mut transport).await?;

    #[cfg(not(feature = "spdm_attestation"))]
    {
        use crate::driver::ticks::with_timeout;
        use core::time::Duration;

        const TLS_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds

        let mut remote_information = ExchangeInformation::default();
        let mut exchange_information = exchange_info(&info.mig_info, info.is_src())?;

        // Establish TLS layer connection and negotiate the MSK
        if info.is_src() {
            // TLS client
            let mut ratls_client = ratls::client(
                transport,
                #[cfg(feature = "policy_v2")]
                remote_policy,
            )
            .map_err(|_| MigrationResult::SecureSessionError)?;

            // MigTD-S send Migration Session Forward key to peer
            with_timeout(
                TLS_TIMEOUT,
                ratls_client.write(exchange_information.as_bytes()),
            )
            .await??;
            let size = with_timeout(
                TLS_TIMEOUT,
                ratls_client.read(remote_information.as_bytes_mut()),
            )
            .await??;
            if size < size_of::<ExchangeInformation>() {
                return Err(MigrationResult::NetworkError);
            }
            #[cfg(all(not(feature = "virtio-serial"), not(feature = "vmcall-raw")))]
            ratls_client.transport_mut().shutdown().await?;

            #[cfg(feature = "vmcall-raw")]
            ratls_client
                .transport_mut()
                .shutdown()
                .await
                .map_err(|_e| MigrationResult::InvalidParameter)?;
        } else {
            // TLS server
            let mut ratls_server = ratls::server(
                transport,
                #[cfg(feature = "policy_v2")]
                remote_policy,
            )
            .map_err(|_| MigrationResult::SecureSessionError)?;

            with_timeout(
                TLS_TIMEOUT,
                ratls_server.write(exchange_information.as_bytes()),
            )
            .await??;
            let size = with_timeout(
                TLS_TIMEOUT,
                ratls_server.read(remote_information.as_bytes_mut()),
            )
            .await??;
            if size < size_of::<ExchangeInformation>() {
                return Err(MigrationResult::NetworkError);
            }
            #[cfg(all(not(feature = "virtio-serial"), not(feature = "vmcall-raw")))]
            ratls_server.transport_mut().shutdown().await?;

            #[cfg(feature = "vmcall-raw")]
            ratls_server
                .transport_mut()
                .shutdown()
                .await
                .map_err(|_e| MigrationResult::InvalidParameter)?;
        }

        let mig_ver = cal_mig_version(info.is_src(), &exchange_information, &remote_information)?;
        set_mig_version(&info.mig_info, mig_ver)?;
        write_msk(&info.mig_info, &remote_information.key)?;

        log::info!("Set MSK and report status\n");
        exchange_information.key.clear();
        remote_information.key.clear();
    }

    #[cfg(feature = "spdm_attestation")]
    if info.is_src() {
        let mut spdm_requester =
            spdm::spdm_requester(transport).map_err(|_| MigrationResult::SecureSessionError)?;

        spdm::spdm_requester_transfer_msk(
            &mut spdm_requester,
            &info.mig_info,
            #[cfg(feature = "policy_v2")]
            remote_policy,
        )
        .await
        .map_err(|_| MigrationResult::MutualAttestationError)?;
        log::info!("MSK exchange completed\n");
    } else {
        let mut spdm_responder =
            spdm::spdm_responder(transport).map_err(|_| MigrationResult::SecureSessionError)?;

        spdm::spdm_responder_transfer_msk(
            &mut spdm_responder,
            &info.mig_info,
            #[cfg(feature = "policy_v2")]
            remote_policy,
        )
        .await
        .map_err(|_| MigrationResult::MutualAttestationError)?;
        log::info!("MSK exchange completed\n");
    }

    Ok(())
}

pub fn exchange_info(
    mig_info: &MigtdMigrationInformation,
    is_src: bool,
) -> Result<ExchangeInformation> {
    let mut exchange_info = ExchangeInformation::default();
    read_msk(mig_info, &mut exchange_info.key)?;

    let (field_min, field_max) = if is_src {
        (GSM_FIELD_MIN_EXPORT_VERSION, GSM_FIELD_MAX_EXPORT_VERSION)
    } else {
        (GSM_FIELD_MIN_IMPORT_VERSION, GSM_FIELD_MAX_IMPORT_VERSION)
    };
    let min_version = tdcall_sys_rd(field_min)?.1;
    let max_version = tdcall_sys_rd(field_max)?.1;
    if min_version > u16::MAX as u64 || max_version > u16::MAX as u64 {
        return Err(MigrationResult::InvalidParameter);
    }
    exchange_info.min_ver = min_version as u16;
    exchange_info.max_ver = max_version as u16;

    Ok(exchange_info)
}

fn read_msk(mig_info: &MigtdMigrationInformation, msk: &mut MigrationSessionKey) -> Result<()> {
    for idx in 0..msk.fields.len() {
        let ret = tdx::tdcall_servtd_rd(
            mig_info.binding_handle,
            TDCS_FIELD_MIG_ENC_KEY + idx as u64,
            &mig_info.target_td_uuid,
        )?;
        msk.fields[idx] = ret.content;
    }
    Ok(())
}

pub fn write_msk(mig_info: &MigtdMigrationInformation, msk: &MigrationSessionKey) -> Result<()> {
    for idx in 0..msk.fields.len() {
        tdx::tdcall_servtd_wr(
            mig_info.binding_handle,
            TDCS_FIELD_MIG_DEC_KEY + idx as u64,
            msk.fields[idx],
            &mig_info.target_td_uuid,
        )
        .map_err(|_| MigrationResult::TdxModuleError)?;
    }

    Ok(())
}

/// Used to read a TDX Module global-scope metadata field.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.SYS.RD Leaf'.
pub fn tdcall_sys_rd(field_identifier: u64) -> core::result::Result<(u64, u64), TdCallError> {
    const TDVMCALL_SYS_RD: u64 = 0x0000b;

    let mut args = TdcallArgs {
        rax: TDVMCALL_SYS_RD,
        rdx: field_identifier,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok((args.rdx, args.r8))
}

pub fn cal_mig_version(
    is_src: bool,
    local_info: &ExchangeInformation,
    remote_info: &ExchangeInformation,
) -> Result<u16> {
    let (min_export, max_export, min_import, max_import) = if is_src {
        (
            local_info.min_ver,
            local_info.max_ver,
            remote_info.min_ver,
            remote_info.max_ver,
        )
    } else {
        (
            remote_info.min_ver,
            remote_info.max_ver,
            local_info.min_ver,
            local_info.max_ver,
        )
    };

    if min_export > max_export
        || min_import > max_import
        || max_export < min_import
        || max_import < min_export
    {
        return Err(MigrationResult::InvalidParameter);
    }

    Ok(core::cmp::min(max_export, max_import))
}

pub fn set_mig_version(mig_info: &MigtdMigrationInformation, mig_ver: u16) -> Result<()> {
    tdcall_servtd_wr(
        mig_info.binding_handle,
        TDCS_FIELD_MIG_VERSION,
        mig_ver as u64,
        &mig_info.target_td_uuid,
    )?;
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::migration::{session::cal_mig_version, MigrationResult};

    use super::ExchangeInformation;

    #[test]
    fn test_cal_mig_version() {
        let mut local_info = ExchangeInformation::default();
        let mut remote_info = ExchangeInformation::default();

        // local: [0, 0], remote: [0, 0]
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Ok(0)));

        // local: [1, 0], remote: [0, 0]
        local_info.min_ver = 1;
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Err(MigrationResult::InvalidParameter)));

        // local: [0, 0], remote: [1, 0]
        local_info.min_ver = 0;
        remote_info.min_ver = 1;
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Err(MigrationResult::InvalidParameter)));

        // local: [4, 4], remote: [1, 3]
        remote_info.max_ver = 3;
        local_info.min_ver = 4;
        local_info.max_ver = 4;
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Err(MigrationResult::InvalidParameter)));

        // local: [4, 4], remote: [5, 6]
        remote_info.min_ver = 5;
        remote_info.max_ver = 6;
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Err(MigrationResult::InvalidParameter)));

        // local: [4, 5], remote: [5, 6]
        local_info.max_ver = 5;
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Ok(5)));

        // local: [4, 6], remote: [5, 6]
        local_info.max_ver = 6;
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Ok(6)));

        // local: [5, 5], remote: [5, 6]
        local_info.min_ver = 5;
        local_info.max_ver = 5;
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Ok(5)));

        // local: [5, 6], remote: [5, 6]
        local_info.max_ver = 6;
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Ok(6)));

        // local: [6, 7], remote: [5, 6]
        local_info.min_ver = 6;
        local_info.max_ver = 7;
        let result = cal_mig_version(true, &local_info, &remote_info);
        assert!(matches!(result, Ok(6)));
    }
}
