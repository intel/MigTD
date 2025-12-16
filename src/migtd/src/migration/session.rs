// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "vmcall-raw")]
use crate::migration::event::VMCALL_MIG_REPORTSTATUS_FLAGS;
#[cfg(feature = "policy_v2")]
use crate::migration::pre_session_data::pre_session_data_exchange;
use crate::migration::transport::setup_transport;
use crate::migration::transport::shutdown_transport;
use crate::migration::transport::TransportType;
#[cfg(feature = "policy_v2")]
use alloc::boxed::Box;
use alloc::collections::BTreeSet;
#[cfg(feature = "vmcall-raw")]
use core::sync::atomic::AtomicBool;
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
use zerocopy::AsBytes;
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
    GetReportData = 3,
    EnableLogArea = 4,
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
fn process_buffer(buffer: &mut [u8]) -> RequestDataBufferHeader {
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
    let (header, _payload_buffer) = buffer.split_at_mut(length); // Split at 12th byte

    outputbuffer = RequestDataBufferHeader {
        datastatus: u64::from_le_bytes(header[0..8].try_into().unwrap()),
        length: u32::from_le_bytes(header[8..12].try_into().unwrap()),
    };

    outputbuffer
}

#[cfg(feature = "vmcall-raw")]
pub async fn wait_for_request() -> Result<WaitForRequestResponse> {
    let mut reqbufferhdr = RequestDataBufferHeader {
        datastatus: 0,
        length: 0,
    };
    let reqbufferhdrlen = size_of::<RequestDataBufferHeader>();
    let mut data_buffer = SharedMemory::new(1).ok_or_else(|| {
        log::error!("wait_for_request: Failed to allocate shared memory\n");
        MigrationResult::OutOfResource
    })?;

    let data_buffer = data_buffer.as_mut_bytes();

    data_buffer[0..reqbufferhdrlen].copy_from_slice(&reqbufferhdr.as_bytes());

    tdx::tdvmcall_migtd_waitforrequest(data_buffer, event::VMCALL_SERVICE_VECTOR).map_err(|e| {
        log::error!(
            "wait_for_request: tdvmcall_migtd_waitforrequest failure {:?}\n",
            e
        );
        e
    })?;

    poll_fn(|_cx| {
        if VMCALL_SERVICE_FLAG.load(Ordering::SeqCst) {
            VMCALL_SERVICE_FLAG.store(false, Ordering::SeqCst);
        } else {
            return Poll::Pending;
        }

        reqbufferhdr = process_buffer(data_buffer);
        let data_status = reqbufferhdr.datastatus;
        let data_length = reqbufferhdr.length;
        if (data_status == 0) && (data_length == 0) {
            return Poll::Pending;
        }
        let data_status_bytes = &data_status.to_le_bytes();
        if data_status_bytes[0] != TDX_VMCALL_VMM_SUCCESS {
            log::error!("wait_for_request: data_status byte[0] failure\n");
            return Poll::Pending;
        }

        let operation: u8 = data_status_bytes[1];
        if operation == DataStatusOperation::StartMigration as u8 {
            // data_length should be MigtdMigrationInformation
            let expected_datalength = size_of::<MigtdMigrationInformation>();
            if data_length != expected_datalength as u32 {
                if data_length >= size_of::<u64>() as u32 {
                    let slice = &data_buffer[reqbufferhdrlen..reqbufferhdrlen + data_length as usize];
                    let mig_request_id = u64::from_le_bytes(slice[0..8].try_into().unwrap());
                    log::error!(migration_request_id = mig_request_id; "wait_for_request: StartMigration operation incorrect data length - expected {} actual {}\n", expected_datalength, data_length);
                } else {
                    log::error!("wait_for_request: StartMigration operation incorrect data length - expected {} actual {}\n", expected_datalength, data_length);
                }
                return Poll::Pending;
            }
            let slice = &data_buffer[reqbufferhdrlen..reqbufferhdrlen + data_length as usize];
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
            // data length should MigRequestID (+ optional REPORTDATA)
            if data_length != size_of_val(&mig_request_id) as u32
                && data_length
                    != size_of::<ReportInfo>() as u32
            {
                if data_length >= size_of::<u64>() as u32 {
                    let slice = &data_buffer[reqbufferhdrlen..reqbufferhdrlen + data_length as usize];
                    let mig_request_id = u64::from_le_bytes(slice[0..8].try_into().unwrap());
                    log::error!(migration_request_id = mig_request_id; "wait_for_request: StartMigration operation incorrect data length - expected {} actual {}\n", size_of::<ReportInfo>(), data_length);
                } else {
                    log::error!("wait_for_request: StartMigration operation incorrect data length - expected {} actual {}\n", size_of::<ReportInfo>(), data_length);
                }
                return Poll::Pending;
            }
            let slice = &data_buffer[reqbufferhdrlen..reqbufferhdrlen + data_length as usize];
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
                if data_length >= size_of::<u64>() as u32 {
                    let slice = &data_buffer[reqbufferhdrlen..reqbufferhdrlen + data_length as usize];
                    let mig_request_id = u64::from_le_bytes(slice[0..8].try_into().unwrap());
                    log::error!(migration_request_id = mig_request_id; "wait_for_request: EnableLogArea operation incorrect data length - expected {} actual {}\n", expected_datalength, data_length);
                } else {
                    log::error!("wait_for_request: EnableLogArea operation incorrect data length - expected {} actual {}\n", expected_datalength, data_length);
                }
                return Poll::Pending;
            }

            let slice = &data_buffer[reqbufferhdrlen..reqbufferhdrlen + data_length as usize];
            let mig_request_id = u64::from_le_bytes(slice[0..8].try_into().unwrap());

            VMCALL_MIG_REPORTSTATUS_FLAGS
                .lock()
                .insert(mig_request_id, AtomicBool::new(false));

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
    let mut data_buffer = SharedMemory::new(1).ok_or_else(|| {
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

    if data.len() > 0 && data.len() < (PAGE_SIZE - reqbufferhdrlen) {
        reqbufferhdr.length += data.len() as u32;
    }

    let data_buffer = data_buffer.as_mut_bytes();
    data_buffer[0..reqbufferhdrlen].copy_from_slice(&reqbufferhdr.as_bytes());
    if data.len() > 0 && data.len() < (PAGE_SIZE - reqbufferhdrlen) {
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
        if let Some(flag) = VMCALL_MIG_REPORTSTATUS_FLAGS.lock().get(&request_id) {
            if flag.load(Ordering::SeqCst) {
                flag.store(false, Ordering::SeqCst);
            } else {
                return Poll::Pending;
            }
        } else {
            return Poll::Pending;
        }

        reqbufferhdr = process_buffer(data_buffer);
        let data_status_bytes = &reqbufferhdr.datastatus.to_le_bytes();
        if data_status_bytes[0] != TDX_VMCALL_VMM_SUCCESS {
            log::error!(migration_request_id = request_id; "report_status: data_status byte[0] failure\n");            
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

#[cfg(not(feature = "spdm_attestation"))]
async fn migration_src_exchange_msk(
    transport: TransportType,
    info: &MigrationInformation,
    data: &mut Vec<u8>,
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
        #[cfg(feature = "vmcall-raw")]
        data,
    )
    .map_err(|_| {
        #[cfg(feature = "vmcall-raw")]
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk(): Failed in ratls transport.\n"
        );
        MigrationResult::SecureSessionError
    })?;

    // MigTD-S send Migration Session Forward key to peer
    with_timeout(
        TLS_TIMEOUT,
        ratls_client.write(exchange_information.as_bytes()),
    )
    .await
    .map_err(|e| {
        log::error!("exchange_msk: ratls_client.write timeout error: {:?}\n", e);
        e
    })?
    .map_err(|e| {
        log::error!("exchange_msk: ratls_client.write error: {:?}\n", e);
        e
    })?;
    let size = with_timeout(
        TLS_TIMEOUT,
        ratls_client.read(remote_information.as_bytes_mut()),
    )
    .await
    .map_err(|e| {
        log::error!("exchange_msk: ratls_client.read timeout error: {:?}\n", e);
        e
    })?
    .map_err(|e| {
        log::error!("exchange_msk: ratls_client.read error: {:?}\n", e);
        e
    })?;
    if size < size_of::<ExchangeInformation>() {
        #[cfg(feature = "vmcall-raw")]
        log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk(): Incorrect ExchangeInformation size Size - Expected: {} Actual: {}\n", size_of::<ExchangeInformation>(), size);
        return Err(MigrationResult::NetworkError);
    }
    shutdown_transport(ratls_client.transport_mut(), info, data).await?;
    Ok(())
}

#[cfg(not(feature = "spdm_attestation"))]
async fn migration_dst_exchange_msk(
    transport: TransportType,
    info: &MigrationInformation,
    data: &mut Vec<u8>,
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
    .map_err(|_| {
        #[cfg(feature = "vmcall-raw")]
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "exchange_msk(): Failed in ratls transport.\n"
        );
        MigrationResult::SecureSessionError
    })?;

    with_timeout(
        TLS_TIMEOUT,
        ratls_server.write(exchange_information.as_bytes()),
    )
    .await
    .map_err(|e| {
        log::error!("exchange_msk: ratls_server.write timeout error: {:?}\n", e);
        e
    })?
    .map_err(|e| {
        log::error!("exchange_msk: ratls_server.write error: {:?}\n", e);
        e
    })?;
    let size = with_timeout(
        TLS_TIMEOUT,
        ratls_server.read(remote_information.as_bytes_mut()),
    )
    .await
    .map_err(|e| {
        log::error!("exchange_msk: ratls_server.read timeout error: {:?}\n", e);
        e
    })?
    .map_err(|e| {
        log::error!("exchange_msk: ratls_server.read error: {:?}\n", e);
        e
    })?;
    if size < size_of::<ExchangeInformation>() {
        #[cfg(feature = "vmcall-raw")]
        log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk(): Incorrect ExchangeInformation size. Size - Expected: {} Actual: {}\n", size_of::<ExchangeInformation>(), size);
        return Err(MigrationResult::NetworkError);
    }
    shutdown_transport(ratls_server.transport_mut(), info, data).await?;
    Ok(())
}

#[cfg(feature = "spdm_attestation")]
async fn migration_src_exchange_msk(
    transport: TransportType,
    info: &MigrationInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<()> {
    const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    let mut spdm_requester = spdm::spdm_requester(transport).map_err(|_e| {
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
    Ok(())
}

#[cfg(feature = "spdm_attestation")]
async fn migration_dst_exchange_msk(
    transport: TransportType,
    info: &MigrationInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<()> {
    const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    let mut spdm_responder = spdm::spdm_responder(transport).map_err(|_e| {
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
    Ok(())
}

#[cfg(feature = "main")]
pub async fn exchange_msk(info: &MigrationInformation, data: &mut Vec<u8>) -> Result<()> {
    let mut transport = setup_transport(info, data).await?;

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
        let mut exchange_information =
            exchange_info(&info.mig_info, info.is_src()).map_err(|e| {
                log::error!(migration_request_id = info.mig_info.mig_request_id; "exchange_msk: exchange_info error: {:?}\n", e);
                e
            })?;

        // Establish TLS layer connection and negotiate the MSK
        if info.is_src() {
            migration_src_exchange_msk(
                transport,
                info,
                data,
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
                data,
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
        exchange_information.key.clear();
        remote_information.key.clear();
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
            log::error!(migration_request_id = mig_info.mig_request_id; "write_msk: tdcall_servtd_wr failed with error: {:?} for mig_info.binding_handle = {}, idx = {}, value = {}\n", e, mig_info.binding_handle, idx, msk.fields[idx]);
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
}
