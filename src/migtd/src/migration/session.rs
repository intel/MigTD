// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "policy_v2")]
use crate::migration::pre_session_data::pre_session_data_exchange;
#[cfg(all(feature = "vmcall-raw", feature = "policy_v2"))]
use crate::migration::rebinding::RebindingInfo;
use crate::migration::transport::setup_transport;
use crate::migration::transport::shutdown_transport;
use crate::migration::transport::TransportType;
#[cfg(feature = "policy_v2")]
use alloc::boxed::Box;
use alloc::collections::BTreeSet;

#[cfg(any(feature = "vmcall-interrupt", feature = "vmcall-raw"))]
use core::sync::atomic::Ordering;
use core::time::Duration;
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
use zerocopy::IntoBytes;
type Result<T> = core::result::Result<T, MigrationResult>;

use super::{data::*, *};
use crate::driver::ticks::with_timeout;
#[cfg(not(feature = "spdm_attestation"))]
use crate::ratls;
#[cfg(feature = "spdm_attestation")]
use crate::spdm;

#[cfg(feature = "vmcall-raw")]
const PAGE_SIZE: usize = 0x1_000;
const TDCALL_STATUS_SUCCESS: u64 = 0;

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
    StartRebinding = 2,
    GetTDReport = 3,
    EnableLogArea = 4,
    GetMigtdData = 5,
}

#[cfg(feature = "vmcall-raw")]
impl TryFrom<u8> for DataStatusOperation {
    type Error = u8;
    fn try_from(value: u8) -> core::result::Result<Self, u8> {
        match value {
            1 => Ok(Self::StartMigration),
            2 => Ok(Self::StartRebinding),
            3 => Ok(Self::GetTDReport),
            4 => Ok(Self::EnableLogArea),
            5 => Ok(Self::GetMigtdData),
            unknown => Err(unknown),
        }
    }
}

lazy_static! {
    pub static ref REQUESTS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
}

#[derive(Default)]
pub struct ExchangeInformation {
    pub min_ver: u16,
    pub max_ver: u16,
    pub key: MigrationSessionKey,
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
    let mut cmd_mem = SharedMemory::new(1).ok_or_else(|| {
        log::error!("query: Failed to allocate command shared memory\n");
        MigrationResult::OutOfResource
    })?;
    let mut rsp_mem = SharedMemory::new(1).ok_or_else(|| {
        log::error!("query: Failed to allocate response shared memory\n");
        MigrationResult::OutOfResource
    })?;

    // Set Migration query command buffer
    let mut cmd = VmcallServiceCommand::new(cmd_mem.as_mut_bytes(), VMCALL_SERVICE_COMMON_GUID)
        .ok_or_else(|| {
            log::error!("query: Failed to create VmcallServiceCommand\n");
            MigrationResult::InvalidParameter
        })?;
    let query = ServiceMigWaitForReqCommand {
        version: 0,
        command: QUERY_COMMAND,
        reserved: [0; 2],
    };
    cmd.write(query.as_bytes()).map_err(|e| {
        log::error!("query: Failed to write query to command buffer\n");
        e
    })?;
    cmd.write(VMCALL_SERVICE_MIGTD_GUID.as_bytes())
        .map_err(|e| {
            log::error!("query: Failed to write MIGTD GUID to command buffer\n");
            e
        })?;
    let _ = VmcallServiceResponse::new(rsp_mem.as_mut_bytes(), VMCALL_SERVICE_COMMON_GUID)
        .ok_or_else(|| {
            log::error!("query: Failed to create VmcallServiceResponse\n");
            MigrationResult::InvalidParameter
        })?;

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
    tdx::tdvmcall_service(cmd_mem.as_bytes(), rsp_mem.as_mut_bytes(), 0, 0).map_err(|e| {
        log::error!("query: tdvmcall_service failure {:?}\n", e);
        e
    })?;

    let private_mem = rsp_mem.copy_to_private_shadow().ok_or_else(|| {
        log::error!("query: Failed to copy response to private shadow\n");
        MigrationResult::OutOfResource
    })?;

    // Parse the response data
    // Check the GUID of the reponse
    let rsp = VmcallServiceResponse::try_read(private_mem).ok_or_else(|| {
        log::error!("query: Failed to read VmcallServiceResponse from response\n");
        MigrationResult::InvalidParameter
    })?;
    if rsp.read_guid() != VMCALL_SERVICE_COMMON_GUID.as_bytes() {
        log::error!(
            "query: GUID mismatch in response rsp.read_guid() = {:?}\n",
            rsp.read_guid()
        );
        return Err(MigrationResult::InvalidParameter);
    }
    let query = rsp.read_data::<ServiceQueryResponse>(0).ok_or_else(|| {
        log::error!("query: Failed to read ServiceQueryResponse from response\n");
        MigrationResult::InvalidParameter
    })?;

    if query.command != QUERY_COMMAND || &query.guid != VMCALL_SERVICE_MIGTD_GUID.as_bytes() {
        log::error!(
            "query: Command or GUID mismatch in response query.command = {}, query.guid = {:?}\n",
            query.command,
            query.guid
        );
        return Err(MigrationResult::InvalidParameter);
    }
    if query.status != 0 {
        log::error!("query: query.status != 0, status = {:x}\n", query.status);
        return Err(MigrationResult::Unsupported);
    }

    log::info!("Migration is supported by VMM\n");
    Ok(())
}

#[cfg(feature = "vmcall-raw")]
fn process_buffer(buffer: &[u8]) -> RequestDataBufferHeader {
    let length = size_of::<RequestDataBufferHeader>();
    let mut outputbuffer = RequestDataBufferHeader {
        datastatus: 0,
        length: 0,
    };
    if buffer.len() < length {
        log::debug!(
            "process_buffer: Buffer too small! - buffer.len = {}, length = {}\n",
            buffer.len(),
            length
        );
        return outputbuffer;
    }
    let (header, _payload_buffer) = buffer.split_at(length); // Split at 12th byte

    outputbuffer = RequestDataBufferHeader {
        datastatus: u64::from_le_bytes(header[0..8].try_into().unwrap()),
        length: u32::from_le_bytes(header[8..12].try_into().unwrap()),
    };

    outputbuffer
}

#[cfg(feature = "vmcall-raw")]
fn calculate_shared_page_nums(reqbufferhdrlen: usize) -> Result<usize> {
    let init_data_header_size = 44; // size of MIGTD_DATA_STRUCT header + MIGTD_DATA_ENTRY_STRUCT header
    let policy_size = crate::config::get_policy()
        .ok_or(MigrationResult::InvalidParameter)?
        .len();
    let event_log_size = crate::event_log::get_event_log()
        .ok_or(MigrationResult::InvalidParameter)?
        .len();
    let report_size = 1024;
    let total_size =
        reqbufferhdrlen + init_data_header_size + policy_size + event_log_size + report_size;
    Ok((total_size + PAGE_SIZE - 1) / PAGE_SIZE)
}

#[cfg(feature = "vmcall-raw")]
fn try_accept_request(
    mig_request_id: u64,
    response: WaitForRequestResponse,
) -> Poll<Result<WaitForRequestResponse>> {
    let inserted = REQUESTS.lock().insert(mig_request_id);
    if inserted {
        Poll::Ready(Ok(response))
    } else {
        Poll::Pending
    }
}

#[cfg(feature = "vmcall-raw")]
fn get_request_payload<'a>(
    data_buffer: &'a [u8],
    reqbufferhdrlen: usize,
    data_length: u32,
) -> Result<&'a [u8]> {
    let end = reqbufferhdrlen
        .checked_add(data_length as usize)
        .ok_or(MigrationResult::InvalidParameter)?;
    data_buffer
        .get(reqbufferhdrlen..end)
        .ok_or(MigrationResult::InvalidParameter)
}

#[cfg(feature = "vmcall-raw")]
fn read_request_id(data_buffer: &[u8], reqbufferhdrlen: usize) -> Option<u64> {
    let end = reqbufferhdrlen.checked_add(size_of::<u64>())?;
    let bytes: [u8; 8] = data_buffer.get(reqbufferhdrlen..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

#[cfg(feature = "vmcall-raw")]
fn reject_request(
    pending_error_report: &mut Option<(u64, MigrationResult)>,
    request_id: Option<u64>,
    status: MigrationResult,
) -> Poll<Result<WaitForRequestResponse>> {
    if let Some(request_id) = request_id {
        *pending_error_report = Some((request_id, status));
    }
    Poll::Ready(Err(status))
}

/// Log an error with an optional `migration_request_id` structured field.
macro_rules! log_request_error {
    ($request_id:expr, $($arg:tt)*) => {
        if let Some(mig_request_id) = $request_id {
            log::error!(migration_request_id = mig_request_id; $($arg)*);
        } else {
            log::error!($($arg)*);
        }
    };
}

#[cfg(feature = "vmcall-raw")]
async fn report_wait_for_request_error(request_id: u64, status: MigrationResult) {
    let data = Vec::new();
    if let Err(e) = report_status(status as u8, request_id, &data).await {
        log::error!(migration_request_id = request_id;
            "wait_for_request: failed to report error status {:?} to host: {:?}\n",
            status,
            e
        );
    }
}

/// Parse a raw request buffer into a typed WaitForRequestResponse.
///
#[cfg(feature = "vmcall-raw")]
fn parse_request(
    data_buffer: &[u8],
    reqbufferhdrlen: usize,
    pending_error_report: &mut Option<(u64, MigrationResult)>,
) -> Poll<Result<WaitForRequestResponse>> {
    let reqbufferhdr = process_buffer(data_buffer);
    let data_status = reqbufferhdr.datastatus;
    let data_length = reqbufferhdr.length;
    if (data_status == 0) && (data_length == 0) {
        return Poll::Pending;
    }

    let data_status_bytes = &data_status.to_le_bytes();
    let request_id = read_request_id(data_buffer, reqbufferhdrlen);
    if data_status_bytes[0] != TDX_VMCALL_VMM_SUCCESS {
        log_request_error!(
            request_id,
            "wait_for_request: data_status byte[0] failure, data_status = {:x}\n",
            data_status
        );
        return reject_request(
            pending_error_report,
            request_id,
            MigrationResult::VmmInternalError,
        );
    }

    let operation: u8 = data_status_bytes[1];
    log::trace!(
        "wait_for_request: Received operation {} with data length {}\n",
        operation,
        data_length
    );

    // Step 1: Convert operation byte to typed enum, reject unknown immediately
    let op = match DataStatusOperation::try_from(operation).map_err(|unknown| {
        log_request_error!(
            request_id,
            "wait_for_request: unknown operation {} received\n",
            unknown
        );
        reject_request(
            pending_error_report,
            request_id,
            MigrationResult::UnsupportedOperationError,
        )
    }) {
        Ok(op) => op,
        Err(poll) => return poll,
    };

    // Step 2: Extract payload bytes based on data_length
    let slice = match get_request_payload(data_buffer, reqbufferhdrlen, data_length) {
        Ok(s) => s,
        Err(status) => {
            log::error!("wait_for_request: {:?} payload out of bounds\n", op);
            return reject_request(pending_error_report, request_id, status);
        }
    };

    // Step 3: Decode payload into operation-specific data and dispatch
    // Each read_from_bytes() validates data_length == expected size.
    macro_rules! decode_and_dispatch {
        ($type:ty, |$info:ident| $response:expr) => {
            match <$type>::read_from_bytes(data_length, slice) {
                Ok($info) => try_accept_request($info.mig_request_id, $response),
                Err(status) => {
                    log_request_error!(
                        request_id,
                        "wait_for_request: {:?} failed to decode payload\n",
                        op
                    );
                    reject_request(pending_error_report, request_id, status)
                }
            }
        };
    }

    match op {
        DataStatusOperation::StartMigration => {
            decode_and_dispatch!(MigtdMigrationInformation, |mig_info| {
                WaitForRequestResponse::StartMigration(MigrationInformation { mig_info })
            })
        }
        DataStatusOperation::StartRebinding => {
            #[cfg(all(feature = "vmcall-raw", feature = "policy_v2"))]
            {
                decode_and_dispatch!(RebindingInfo, |info| {
                    WaitForRequestResponse::StartRebinding(info)
                })
            }
            #[cfg(not(all(feature = "vmcall-raw", feature = "policy_v2")))]
            {
                log_request_error!(
                    request_id,
                    "wait_for_request: unsupported operation {:?} received\n",
                    op
                );
                reject_request(
                    pending_error_report,
                    request_id,
                    MigrationResult::UnsupportedOperationError,
                )
            }
        }
        DataStatusOperation::GetTDReport => {
            decode_and_dispatch!(ReportInfo, |info| WaitForRequestResponse::GetTdReport(info))
        }
        DataStatusOperation::EnableLogArea => {
            decode_and_dispatch!(EnableLogAreaInfo, |info| {
                WaitForRequestResponse::EnableLogArea(info)
            })
        }
        DataStatusOperation::GetMigtdData => {
            #[cfg(all(feature = "vmcall-raw", feature = "policy_v2"))]
            {
                decode_and_dispatch!(MigtdDataInfo, |info| WaitForRequestResponse::GetMigtdData(
                    info
                ))
            }
            #[cfg(not(all(feature = "vmcall-raw", feature = "policy_v2")))]
            {
                log_request_error!(
                    request_id,
                    "wait_for_request: unsupported operation {:?} received\n",
                    op
                );
                reject_request(
                    pending_error_report,
                    request_id,
                    MigrationResult::UnsupportedOperationError,
                )
            }
        }
    }
}

#[cfg(feature = "vmcall-raw")]
pub async fn wait_for_request() -> Result<WaitForRequestResponse> {
    let mut reqbufferhdr = RequestDataBufferHeader {
        datastatus: 0,
        length: 0,
    };
    let reqbufferhdrlen = size_of::<RequestDataBufferHeader>();
    let shared_page_nums = calculate_shared_page_nums(reqbufferhdrlen)?;

    let mut data_buffer = SharedMemory::new(shared_page_nums).ok_or_else(|| {
        log::error!("wait_for_request: Failed to allocate shared memory\n");
        MigrationResult::OutOfResource
    })?;

    let shared_data_buffer = data_buffer.as_mut_bytes();

    shared_data_buffer[0..reqbufferhdrlen].copy_from_slice(&reqbufferhdr.as_bytes());

    tdx::tdvmcall_migtd_waitforrequest(shared_data_buffer, event::VMCALL_SERVICE_VECTOR).map_err(
        |e| {
            log::error!(
                "wait_for_request: tdvmcall_migtd_waitforrequest failure {:?}\n",
                e
            );
            e
        },
    )?;

    let mut pending_error_report: Option<(u64, MigrationResult)> = None;
    let result = poll_fn(|_cx| {
        if VMCALL_SERVICE_FLAG.load(Ordering::SeqCst) {
            VMCALL_SERVICE_FLAG.store(false, Ordering::SeqCst);
        } else {
            return Poll::Pending;
        }

        let data_buffer = if let Some(private_buffer) = data_buffer.copy_to_private_shadow() {
            private_buffer
        } else {
            log::error!("wait_for_request: copy_to_private_shadow failure\n");
            return Poll::Ready(Err(MigrationResult::OutOfResource));
        };

        parse_request(data_buffer, reqbufferhdrlen, &mut pending_error_report)
    })
    .await;

    if let Err(status) = result {
        if let Some((request_id, report_status_code)) = pending_error_report.take() {
            report_wait_for_request_error(request_id, report_status_code).await;
        }
        return Err(status);
    }

    result
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
            log::error!(
                "wait_for_request: GUID mismatch in response rsp.read_guid() = {:?}\n",
                rsp.read_guid()
            );
            return Poll::Ready(Err(MigrationResult::InvalidParameter));
        }
        let wfr = rsp
            .read_data::<ServiceMigWaitForReqResponse>(0)
            .ok_or(MigrationResult::InvalidParameter)?;
        if wfr.command != MIG_COMMAND_WAIT {
            log::error!(
                "wait_for_request: command mismatch in response wfr.command = {:?}\n",
                wfr.command
            );
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
    let mut cmd_mem = SharedMemory::new(1).ok_or_else(|| {
        log::error!("shutdown: Failed to allocate command shared memory\n");
        MigrationResult::OutOfResource
    })?;
    let mut rsp_mem = SharedMemory::new(1).ok_or_else(|| {
        log::error!("shutdown: Failed to allocate response shared memory\n");
        MigrationResult::OutOfResource
    })?;

    // Set Command
    let mut cmd = VmcallServiceCommand::new(cmd_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
        .ok_or_else(|| {
            log::error!("shutdown: Invalid parameter for VmcallServiceCommand\n");
            MigrationResult::InvalidParameter
        })?;

    let sd = ServiceMigWaitForReqShutdown {
        version: 0,
        command: MIG_COMMAND_SHUT_DOWN,
        reserved: [0; 2],
    };
    cmd.write(sd.as_bytes()).map_err(|e| {
        log::error!("shutdown: Failed to write shutdown command to command buffer\n");
        e
    })?;
    tdx::tdvmcall_service(cmd_mem.as_bytes(), rsp_mem.as_mut_bytes(), 0, 0).map_err(|e| {
        log::error!("shutdown: tdvmcall_service failed: {:?}\n", e);
        e
    })?;
    Ok(())
}

#[cfg(feature = "vmcall-raw")]
pub async fn get_tdreport(
    additional_data: &[u8; TD_REPORT_ADDITIONAL_DATA_SIZE],
    data: &mut Vec<u8>,
    request_id: u64,
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
        log::error!(migration_request_id = request_id; "get_tdreport: TDG.MR.REPORT failure {:x}\n", ret);
        return Err(MigrationResult::TdxModuleError);
    }

    data.extend_from_slice(report_buf.0.as_bytes());
    if data.len() != tdreportsize {
        log::error!( migration_request_id = request_id;
            "get_tdreport: tdreport incorrect data length - expected {} actual {}\n",
            tdreportsize,
            data.len()
        );
        return Err(MigrationResult::InvalidParameter);
    }
    Ok(())
}

#[cfg(all(feature = "vmcall-raw", feature = "policy_v2"))]
pub async fn get_migtd_data(
    additional_data: &[u8; TD_REPORT_ADDITIONAL_DATA_SIZE],
    data: &mut Vec<u8>,
    request_id: u64,
) -> Result<()> {
    use crate::migration::rebinding::InitData;

    let init_data = InitData::get_from_local(additional_data).ok_or_else(|| {
        log::error!( migration_request_id = request_id;
            "Failed to get init migtd data from local\n",
        );
        MigrationResult::InvalidParameter
    })?;

    init_data.write_into_bytes(data);
    Ok(())
}

#[cfg(feature = "vmcall-raw")]
pub async fn report_status(status: u8, request_id: u64, data: &Vec<u8>) -> Result<()> {
    let mut reportstatus = ReportStatusResponse::new()
        .with_pre_migration_status(0)
        .with_error_code(0)
        .with_reserved(0);
    let mut reqbufferhdr = RequestDataBufferHeader {
        datastatus: 0,
        length: 0,
    };
    let reqbufferhdrlen = size_of::<RequestDataBufferHeader>();

    let shared_page_nums = (reqbufferhdrlen + data.len() + PAGE_SIZE - 1) / PAGE_SIZE;
    let mut data_buffer = SharedMemory::new(shared_page_nums).ok_or_else(|| {
        log::error!(migration_request_id = request_id; "report_status: Failed to allocate shared memory for data buffer\n");
        MigrationResult::OutOfResource
    })?;

    if let Ok(value) = MigrationResult::try_from(status) {
        if value != MigrationResult::Success {
            reportstatus = reportstatus
                .with_pre_migration_status(1)
                .with_error_code(status);
        }
    } else {
        log::error!( migration_request_id = request_id;
            "report_status: Invalid Migration Status code: {:x}\n",
            status
        );
        return Err(MigrationResult::InvalidParameter);
    }

    if data.len() > 0 {
        reqbufferhdr.length += data.len() as u32;
    }

    let data_buffer = data_buffer.as_mut_bytes();
    data_buffer[0..reqbufferhdrlen].copy_from_slice(&reqbufferhdr.as_bytes());
    if data.len() > 0 {
        data_buffer[reqbufferhdrlen..data.len() + reqbufferhdrlen]
            .copy_from_slice(&data[0..data.len()]);
    }

    tdx::tdvmcall_migtd_reportstatus(
        request_id,
        reportstatus.into(),
        data_buffer,
        event::VMCALL_SERVICE_VECTOR,
    )
    .map_err(|e| {
        log::error!(migration_request_id = request_id;
            "report_status: tdvmcall_migtd_reportstatus failure {:?}\n",
            e
        );
        e
    })?;

    poll_fn(|_cx| -> Poll<Result<()>> {
        reqbufferhdr = process_buffer(data_buffer);
        let data_status_bytes = &reqbufferhdr.datastatus.to_le_bytes();
        if data_status_bytes[0] != TDX_VMCALL_VMM_SUCCESS {
            log::info!(migration_request_id = request_id; "report_status: Pending confirmation\n");
            return Poll::Pending;
        }

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

#[cfg(not(feature = "spdm_attestation"))]
async fn migration_src_exchange_msk(
    transport: TransportType,
    info: &MigrationInformation,
    exchange_information: &ExchangeInformation,
    remote_information: &mut ExchangeInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<()> {
    const TLS_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds

    // TLS client
    let mut ratls_client = ratls::client(
        transport,
        #[cfg(feature = "policy_v2")]
        remote_policy,
    )
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk(): Failed in ratls client setup. Error: {:?}\n", e
        );
        e
    })?;

    // MigTD-S send Migration Session Forward key to peer
    with_timeout(
        TLS_TIMEOUT,
        ratls_client.write(exchange_information.as_bytes()),
    )
    .await
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk: ratls_client.write timeout error: {:?}\n", e);
        e
    })?
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk: ratls_client.write error: {:?}\n", e);
        e
    })?;
    let size = with_timeout(
        TLS_TIMEOUT,
        ratls_client.read(remote_information.as_bytes_mut()),
    )
    .await
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk: ratls_client.read timeout error: {:?}\n", e);
        e
    })?
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk: ratls_client.read error: {:?}\n", e);
        e
    })?;
    if size < size_of::<ExchangeInformation>() {
        log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk(): Incorrect ExchangeInformation size Size - Expected: {} Actual: {}\n", size_of::<ExchangeInformation>(), size);
        return Err(MigrationResult::NetworkError);
    }
    shutdown_transport(ratls_client.transport_mut(), info.mig_info.mig_request_id).await?;
    Ok(())
}

#[cfg(not(feature = "spdm_attestation"))]
async fn migration_dst_exchange_msk(
    transport: TransportType,
    info: &MigrationInformation,
    exchange_information: &ExchangeInformation,
    remote_information: &mut ExchangeInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<()> {
    const TLS_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds

    // TLS server
    let mut ratls_server = ratls::server(
        transport,
        #[cfg(feature = "policy_v2")]
        remote_policy,
    )
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk(): Failed in ratls server setup. Error: {:?}\n", e
        );
        e
    })?;

    with_timeout(
        TLS_TIMEOUT,
        ratls_server.write(exchange_information.as_bytes()),
    )
    .await
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk: ratls_server.write timeout error: {:?}\n", e);
        e
    })?
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk: ratls_server.write error: {:?}\n", e);
        e
    })?;
    let size = with_timeout(
        TLS_TIMEOUT,
        ratls_server.read(remote_information.as_bytes_mut()),
    )
    .await
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk: ratls_server.read timeout error: {:?}\n", e);
        e
    })?
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk: ratls_server.read error: {:?}\n", e);
        e
    })?;
    if size < size_of::<ExchangeInformation>() {
        log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk(): Incorrect ExchangeInformation size. Size - Expected: {} Actual: {}\n", size_of::<ExchangeInformation>(), size);
        return Err(MigrationResult::NetworkError);
    }
    shutdown_transport(ratls_server.transport_mut(), info.mig_info.mig_request_id).await?;
    Ok(())
}

#[cfg(feature = "spdm_attestation")]
async fn migration_src_exchange_msk(
    transport: TransportType,
    info: &MigrationInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<()> {
    use core::ops::DerefMut;

    const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    let (mut spdm_requester, device_io_ref) = spdm::spdm_requester(transport).map_err(|_e| {
        log::error!(
            "exchange_msk(): Failed in spdm_requester transport. Migration ID: {}\n",
            info.mig_info.mig_request_id
        );
        MigrationResult::SecureSessionError
    })?;
    with_timeout(
        SPDM_TIMEOUT,
        spdm::spdm_requester_transfer_msk(
            &mut spdm_requester,
            &info.mig_info,
            #[cfg(feature = "policy_v2")]
            remote_policy,
        ),
    )
    .await
    .map_err(|e| {
        log::error!(
            "exchange_msk: spdm_requester_transfer_msk timeout error: {:?}\n",
            e
        );
        e
    })?
    .map_err(|e| {
        log::error!("exchange_msk: spdm_requester_transfer_msk error: {:?}\n", e);
        e
    })?;
    log::info!("MSK exchange completed\n");

    let mut transport_lock = device_io_ref.lock();
    let transport = transport_lock.deref_mut();
    shutdown_transport(&mut transport.transport, info.mig_info.mig_request_id).await?;
    Ok(())
}

#[cfg(feature = "spdm_attestation")]
async fn migration_dst_exchange_msk(
    transport: TransportType,
    info: &MigrationInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<()> {
    use core::ops::DerefMut;

    const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    let (mut spdm_responder, device_io_ref) = spdm::spdm_responder(transport).map_err(|_e| {
        log::error!(
            "exchange_msk(): Failed in spdm_responder transport. Migration ID: {}\n",
            info.mig_info.mig_request_id
        );
        MigrationResult::SecureSessionError
    })?;

    with_timeout(
        SPDM_TIMEOUT,
        spdm::spdm_responder_transfer_msk(
            &mut spdm_responder,
            &info.mig_info,
            #[cfg(feature = "policy_v2")]
            remote_policy,
        ),
    )
    .await
    .map_err(|e| {
        log::error!(
            "exchange_msk: spdm_responder_transfer_msk timeout error: {:?}\n",
            e
        );
        e
    })?
    .map_err(|e| {
        log::error!("exchange_msk: spdm_responder_transfer_msk error: {:?}\n", e);
        e
    })?;
    log::info!("MSK exchange completed\n");

    let mut transport_lock = device_io_ref.lock();
    let transport = transport_lock.deref_mut();
    shutdown_transport(&mut transport.transport, info.mig_info.mig_request_id).await?;
    Ok(())
}

#[cfg(feature = "main")]
pub async fn exchange_msk(info: &MigrationInformation) -> Result<()> {
    let mut transport = setup_transport(
        info.mig_info.mig_request_id,
        #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))]
        info.mig_socket_info.mig_td_cid,
        #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))]
        info.mig_socket_info.mig_channel_port,
    )
    .await?;

    // Exchange policy firstly because of the message size limitation of TLS protocol
    #[cfg(feature = "policy_v2")]
    const PRE_SESSION_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    #[cfg(feature = "policy_v2")]
    let policy = crate::config::get_policy()
        .ok_or(MigrationResult::InvalidParameter)
        .map_err(|e| {
            log::error!("pre_session_data_exchange: get_policy error: {:?}\n", e);
            e
        })?;
    #[cfg(feature = "policy_v2")]
    let remote_policy = Box::pin(with_timeout(
        PRE_SESSION_TIMEOUT,
        pre_session_data_exchange(&mut transport, policy),
    ))
    .await
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk: pre_session_data_exchange timeout error: {:?}\n",
            e
        );
        e
    })?
    .map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk: pre_session_data_exchange error: {:?}\n", e);
        e
    })?;

    #[cfg(not(feature = "spdm_attestation"))]
    {
        let mut remote_information = ExchangeInformation::default();
        let exchange_information =
            exchange_info(&info.mig_info, info.is_src()).map_err(|e| {
                log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk: exchange_info error: {:?}\n", e);
                e
            })?;

        // Establish TLS layer connection and negotiate the MSK
        if info.is_src() {
            migration_src_exchange_msk(
                transport,
                info,
                &exchange_information,
                &mut remote_information,
                #[cfg(feature = "policy_v2")]
                remote_policy,
            )
            .await?;
        } else {
            migration_dst_exchange_msk(
                transport,
                info,
                &exchange_information,
                &mut remote_information,
                #[cfg(feature = "policy_v2")]
                remote_policy,
            )
            .await?;
        }

        let mig_ver = cal_mig_version(info.is_src(), &exchange_information, &remote_information)
            .map_err(|e| {
                log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk: cal_mig_version error: {:?}\n", e);
                e
            })?;
        set_mig_version(&info.mig_info, mig_ver).map_err(|e| {
            log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk: set_mig_version error: {:?}\n", e);
            e
        })?;
        write_msk(&info.mig_info, &remote_information.key).map_err(|e| {
            log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk: write_msk error: {:?}\n", e);
            e
        })?;

        log::info!(migration_request_id = info.mig_info.mig_request_id; "Set MSK and report status\n");
    }

    #[cfg(feature = "spdm_attestation")]
    {
        if info.is_src() {
            migration_src_exchange_msk(
                transport,
                info,
                #[cfg(feature = "policy_v2")]
                remote_policy,
            )
            .await?;
        } else {
            migration_dst_exchange_msk(
                transport,
                info,
                #[cfg(feature = "policy_v2")]
                remote_policy,
            )
            .await?;
        }
    }

    Ok(())
}

pub fn exchange_info(
    mig_info: &MigtdMigrationInformation,
    is_src: bool,
) -> Result<ExchangeInformation> {
    let mut exchange_info = ExchangeInformation::default();
    read_msk(mig_info, &mut exchange_info.key).map_err(|e| {
        log::error!(migration_request_id = mig_info.mig_request_id; "exchange_info: read_msk failed with error: {:?} for mig_info.binding_handle = {}\n", e, mig_info.binding_handle);
        e
    })?;

    let (field_min, field_max) = if is_src {
        (GSM_FIELD_MIN_EXPORT_VERSION, GSM_FIELD_MAX_EXPORT_VERSION)
    } else {
        (GSM_FIELD_MIN_IMPORT_VERSION, GSM_FIELD_MAX_IMPORT_VERSION)
    };
    let min_version = tdcall_sys_rd(field_min)
        .map_err(|e| {
            log::error!(migration_request_id = mig_info.mig_request_id; "exchange_info: tdcall_sys_rd failed with error: {:?} for field_min = {}\n", e, field_min);
            e
        })?
        .1;
    let max_version = tdcall_sys_rd(field_max)
        .map_err(|e| {
            log::error!(migration_request_id = mig_info.mig_request_id; "exchange_info: tdcall_sys_rd failed with error: {:?} for field_max = {}\n", e, field_max);
            e
        })?
        .1;
    if min_version > u16::MAX as u64 || max_version > u16::MAX as u64 {
        log::error!(migration_request_id = mig_info.mig_request_id; "exchange_info: Migration version out of range. is_src = {}, min_version = {}, max_version = {}\n", is_src, min_version, max_version);
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
        ).map_err(|e|{
            log::error!(migration_request_id = mig_info.mig_request_id; "read_msk: tdcall_servtd_rd failed with error: {:?} for mig_info.binding_handle = {}, idx = {}\n", e, mig_info.binding_handle, idx);
            e
        })?;
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
        .map_err(|e| {
            log::error!(migration_request_id = mig_info.mig_request_id; "write_msk: tdcall_servtd_wr failed with error: {:?} for mig_info.binding_handle = {}, idx = {}\n", e, mig_info.binding_handle, idx);
            MigrationResult::TdxModuleError
        })?;
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
        log::error!(
            "tdcall_sys_rd failed with error: {:?} for field_identifier = {}\n",
            ret,
            field_identifier
        );
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
        log::error!(
            "cal_mig_version: No compatible migration version found. is_src = {}, local_info = {:?}, remote_info = {:?}\n",
            is_src,
            local_info.min_ver..=local_info.max_ver,
            remote_info.min_ver..=remote_info.max_ver,
        );
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
    ).map_err(|e|{
        log::error!(migration_request_id = mig_info.mig_request_id; "set_mig_version: tdcall_servtd_wr failed with error: {:?} for mig_info.binding_handle = {}, mig_ver = {}\n", e, mig_info.binding_handle, mig_ver);
        e
    })?;
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

    // ---- parse_request-level tests: simulate host data buffers ----

    #[cfg(feature = "vmcall-raw")]
    mod parse_request_tests {
        use super::super::{parse_request, REQUESTS};
        use crate::migration::{
            data::{RequestDataBufferHeader, WaitForRequestResponse},
            EnableLogAreaInfo, MigrationResult, MigtdMigrationInformation, ReportInfo,
        };
        use core::mem::size_of;
        use core::task::Poll;

        const HDR_LEN: usize = size_of::<RequestDataBufferHeader>();

        /// Build a raw request buffer: header (datastatus + length) + payload.
        fn build_request_buffer(operation: u8, payload: &[u8]) -> Vec<u8> {
            let mut datastatus = [0u8; 8];
            datastatus[0] = super::super::TDX_VMCALL_VMM_SUCCESS;
            datastatus[1] = operation;
            let length = payload.len() as u32;
            let mut buf = Vec::with_capacity(HDR_LEN + payload.len());
            buf.extend_from_slice(&datastatus);
            buf.extend_from_slice(&length.to_le_bytes());
            buf.extend_from_slice(payload);
            buf
        }

        fn build_raw_buffer(datastatus: u64, length: u32, payload: &[u8]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(HDR_LEN + payload.len());
            buf.extend_from_slice(&datastatus.to_le_bytes());
            buf.extend_from_slice(&length.to_le_bytes());
            buf.extend_from_slice(payload);
            buf
        }

        fn build_migration_payload(request_id: u64, is_source: u8) -> Vec<u8> {
            let mut payload = vec![0u8; size_of::<MigtdMigrationInformation>()];
            payload[0..8].copy_from_slice(&request_id.to_le_bytes());
            payload[8] = is_source;
            payload
        }

        fn cleanup_request(request_id: u64) {
            REQUESTS.lock().remove(&request_id);
        }

        #[test]
        fn test_parse_empty_buffer_returns_pending() {
            let buf = build_raw_buffer(0, 0, &[]);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            assert!(matches!(result, Poll::Pending));
        }

        #[test]
        fn test_parse_vmm_failure_status() {
            let mut buf = vec![0u8; HDR_LEN + 8];
            buf[0] = 0; // NOT success
            buf[1] = 1;
            let length = 8u32;
            buf[8..12].copy_from_slice(&length.to_le_bytes());
            buf[12..20].copy_from_slice(&42u64.to_le_bytes());
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            assert!(matches!(
                result,
                Poll::Ready(Err(MigrationResult::VmmInternalError))
            ));
            assert_eq!(pending, Some((42, MigrationResult::VmmInternalError)));
        }

        #[test]
        fn test_parse_unknown_operation() {
            let payload = 99u64.to_le_bytes();
            let buf = build_request_buffer(255, &payload);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            assert!(matches!(
                result,
                Poll::Ready(Err(MigrationResult::UnsupportedOperationError))
            ));
        }

        #[test]
        fn test_parse_start_migration_success() {
            let request_id: u64 = 0xAA00_0000_0000_0001;
            let payload = build_migration_payload(request_id, 1);
            let buf = build_request_buffer(1, &payload);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            match result {
                Poll::Ready(Ok(WaitForRequestResponse::StartMigration(info))) => {
                    assert_eq!(info.mig_info.mig_request_id, request_id);
                    assert_eq!(info.mig_info.migration_source, 1);
                }
                _ => panic!("Expected StartMigration, got unexpected variant"),
            }
            assert!(pending.is_none());
            cleanup_request(request_id);
        }

        #[test]
        fn test_parse_start_migration_truncated_payload() {
            // Payload is too short and data_length != expected size
            let buf = build_request_buffer(1, &[0u8; 8]);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            assert!(matches!(
                result,
                Poll::Ready(Err(MigrationResult::InvalidParameter))
            ));
        }

        #[test]
        fn test_parse_start_migration_trailing_bytes_rejected() {
            // Payload has correct data but data_length is too large (trailing bytes)
            let request_id: u64 = 0xAA00_0000_0000_0099;
            let mut payload = build_migration_payload(request_id, 1);
            payload.extend_from_slice(&[0xFF; 8]); // trailing garbage
            let buf = build_request_buffer(1, &payload);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            // read_from_bytes rejects because data_length != size_of::<MigtdMigrationInformation>()
            assert!(matches!(
                result,
                Poll::Ready(Err(MigrationResult::InvalidParameter))
            ));
        }

        #[test]
        fn test_parse_get_td_report_full() {
            let request_id: u64 = 0xBB00_0000_0000_0002;
            let mut payload = vec![0u8; size_of::<ReportInfo>()];
            payload[0..8].copy_from_slice(&request_id.to_le_bytes());
            payload[8..72].fill(0xCC);
            let buf = build_request_buffer(3, &payload);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            match result {
                Poll::Ready(Ok(WaitForRequestResponse::GetTdReport(info))) => {
                    assert_eq!(info.mig_request_id, request_id);
                    assert_eq!(info.reportdata[0], 0xCC);
                }
                _ => panic!("Expected GetTdReport, got unexpected variant"),
            }
            cleanup_request(request_id);
        }

        #[test]
        fn test_parse_get_td_report_request_id_only() {
            let request_id: u64 = 0xCC00_0000_0000_0003;
            let payload = request_id.to_le_bytes();
            let buf = build_request_buffer(3, &payload);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            match result {
                Poll::Ready(Ok(WaitForRequestResponse::GetTdReport(info))) => {
                    assert_eq!(info.mig_request_id, request_id);
                    assert_eq!(info.reportdata, [0u8; 64]);
                }
                _ => panic!("Expected GetTdReport with zero reportdata, got unexpected variant"),
            }
            cleanup_request(request_id);
        }

        #[test]
        fn test_parse_get_td_report_wrong_size_rejected() {
            // 16 bytes is neither 8 nor 72 → read_from_bytes rejects
            let buf = build_request_buffer(3, &[0u8; 16]);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            assert!(matches!(
                result,
                Poll::Ready(Err(MigrationResult::InvalidParameter))
            ));
        }

        #[test]
        fn test_parse_enable_log_area_success() {
            let request_id: u64 = 0xDD00_0000_0000_0004;
            let mut payload = vec![0u8; size_of::<EnableLogAreaInfo>()];
            payload[0..8].copy_from_slice(&request_id.to_le_bytes());
            payload[8] = 4;
            let buf = build_request_buffer(4, &payload);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            match result {
                Poll::Ready(Ok(WaitForRequestResponse::EnableLogArea(info))) => {
                    assert_eq!(info.mig_request_id, request_id);
                    assert_eq!(info.log_max_level, 4);
                }
                _ => panic!("Expected EnableLogArea, got unexpected variant"),
            }
            cleanup_request(request_id);
        }

        #[test]
        fn test_parse_enable_log_area_truncated() {
            let buf = build_request_buffer(4, &[0u8; 4]);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            assert!(matches!(
                result,
                Poll::Ready(Err(MigrationResult::InvalidParameter))
            ));
        }

        #[test]
        fn test_parse_duplicate_request_returns_pending() {
            let request_id: u64 = 0xEE00_0000_0000_0005;
            let payload = build_migration_payload(request_id, 0);
            let buf = build_request_buffer(1, &payload);
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            assert!(matches!(
                result,
                Poll::Ready(Ok(WaitForRequestResponse::StartMigration(_)))
            ));
            // Second call: duplicate → Pending
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            assert!(matches!(result, Poll::Pending));
            cleanup_request(request_id);
        }

        #[test]
        fn test_parse_payload_out_of_bounds() {
            let mut buf = vec![0u8; HDR_LEN + 8];
            buf[0] = super::super::TDX_VMCALL_VMM_SUCCESS;
            buf[1] = 1;
            let fake_length = 100u32;
            buf[8..12].copy_from_slice(&fake_length.to_le_bytes());
            buf[12..20].copy_from_slice(&42u64.to_le_bytes());
            let mut pending = None;
            let result = parse_request(&buf, HDR_LEN, &mut pending);
            assert!(matches!(
                result,
                Poll::Ready(Err(MigrationResult::InvalidParameter))
            ));
        }
    }
}
