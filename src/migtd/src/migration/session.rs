// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::collections::BTreeSet;
#[cfg(feature = "vmcall-interrupt")]
use core::sync::atomic::Ordering;
use core::{future::poll_fn, mem::size_of, task::Poll};
#[cfg(feature = "vmcall-interrupt")]
use event::VMCALL_SERVICE_FLAG;
use lazy_static::lazy_static;
use scroll::Pread;
use spin::Mutex;
use td_payload::mm::shared::SharedMemory;
use td_shim_interface::td_uefi_pi::{
    hob::{self as hob_lib, align_to_next_hob_offset},
    pi::hob::{GuidExtension, Header, HOB_TYPE_END_OF_HOB_LIST, HOB_TYPE_GUID_EXTENSION},
};
use tdx_tdcall::{
    td_call,
    tdx::{self, tdcall_servtd_wr},
    TdcallArgs,
};
use zerocopy::AsBytes;

type Result<T> = core::result::Result<T, MigrationResult>;

use super::{data::*, *};
use crate::ratls;

const TDCALL_STATUS_SUCCESS: u64 = 0;
const TDCS_FIELD_MIG_DEC_KEY: u64 = 0x9810_0003_0000_0010;
const TDCS_FIELD_MIG_ENC_KEY: u64 = 0x9810_0003_0000_0018;
const TDCS_FIELD_MIG_VERSION: u64 = 0x9810_0001_0000_0020;
// TDX Module global-scope metadata field
const GSM_FIELD_MIN_EXPORT_VERSION: u64 = 0x2000000100000001;
const GSM_FIELD_MAX_EXPORT_VERSION: u64 = 0x2000000100000002;
const GSM_FIELD_MIN_IMPORT_VERSION: u64 = 0x2000000100000003;
const GSM_FIELD_MAX_IMPORT_VERSION: u64 = 0x2000000100000004;

lazy_static! {
    pub static ref REQUESTS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
}

pub struct MigrationInformation {
    pub mig_info: MigtdMigrationInformation,
    pub mig_socket_info: MigtdStreamSocketInfo,
    pub mig_policy: Option<MigtdMigpolicy>,
}

impl MigrationInformation {
    pub fn is_src(&self) -> bool {
        self.mig_info.migration_source == 1
    }
}

struct ExchangeInformation {
    min_ver: u16,
    max_ver: u16,
    key: MigrationSessionKey,
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

#[cfg(feature = "main")]
pub async fn exchange_msk(info: &MigrationInformation) -> Result<()> {
    use crate::driver::ticks::with_timeout;
    use core::time::Duration;

    const TLS_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds

    let transport;
    #[cfg(feature = "virtio-serial")]
    {
        use virtio_serial::VirtioSerialPort;
        const VIRTIO_SERIAL_PORT_ID: u32 = 1;

        let port = VirtioSerialPort::new(VIRTIO_SERIAL_PORT_ID);
        port.open()?;
        transport = port;
    };

    #[cfg(not(feature = "virtio-serial"))]
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

    let mut remote_information = ExchangeInformation::default();
    let mut exchange_information = exchange_info(&info)?;

    // Establish TLS layer connection and negotiate the MSK
    if info.is_src() {
        // TLS client
        let mut ratls_client =
            ratls::client(transport).map_err(|_| MigrationResult::SecureSessionError)?;

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
        #[cfg(not(feature = "virtio-serial"))]
        ratls_client.transport_mut().shutdown().await?;
    } else {
        // TLS server
        let mut ratls_server =
            ratls::server(transport).map_err(|_| MigrationResult::SecureSessionError)?;

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
        #[cfg(not(feature = "virtio-serial"))]
        ratls_server.transport_mut().shutdown().await?;
    }

    let mig_ver = cal_mig_version(info.is_src(), &exchange_information, &remote_information)?;
    set_mig_version(info, mig_ver)?;
    write_msk(&info.mig_info, &remote_information.key)?;

    log::info!("Set MSK and report status\n");
    exchange_information.key.clear();
    remote_information.key.clear();

    Ok(())
}

fn exchange_info(info: &MigrationInformation) -> Result<ExchangeInformation> {
    let mut exchange_info = ExchangeInformation::default();
    read_msk(&info.mig_info, &mut exchange_info.key)?;

    let (field_min, field_max) = if info.is_src() {
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

fn write_msk(mig_info: &MigtdMigrationInformation, msk: &MigrationSessionKey) -> Result<()> {
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

fn read_mig_info(hob: &[u8]) -> Option<MigrationInformation> {
    let mut offset = 0;
    let mut mig_info_hob = None;
    let mut mig_socket_hob = None;
    let mut policy_info_hob = None;

    while let Some(hob) = get_next_hob(hob, &mut offset) {
        let header: Header = hob.pread(0).ok()?;

        match header.r#type {
            HOB_TYPE_GUID_EXTENSION => {
                let guid_hob_header: GuidExtension = hob.pread(0).ok()?;
                let guid_hob = hob.get(..guid_hob_header.header.length as usize)?;
                match &guid_hob_header.name {
                    name if name == MIGRATION_INFORMATION_HOB_GUID.as_bytes() => {
                        if mig_info_hob.is_some() {
                            // Duplicate Migration Information HOB
                            return None;
                        }
                        mig_info_hob = Some(guid_hob);
                    }
                    name if name == STREAM_SOCKET_INFO_HOB_GUID.as_bytes() => {
                        if mig_socket_hob.is_some() {
                            // Duplicate Stream Socket Information HOB
                            return None;
                        }
                        mig_socket_hob = Some(guid_hob);
                    }
                    name if name == MIGPOLICY_HOB_GUID.as_bytes() => {
                        if policy_info_hob.is_some() {
                            // Duplicate Migration Policy HOB
                            return None;
                        }
                        policy_info_hob = Some(guid_hob);
                    }
                    _ => {
                        // Unexpected GUIDed HOB
                        return None;
                    }
                }
            }
            HOB_TYPE_END_OF_HOB_LIST => break,
            _ => {
                // Unexpected HOB type
                return None;
            }
        }
    }

    create_migration_information(mig_info_hob, mig_socket_hob, policy_info_hob)
}

fn get_next_hob<'a>(hob: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    if *offset >= hob.len() {
        return None;
    }
    let hob_slice = &hob[*offset..];
    *offset = align_to_next_hob_offset(
        hob.len(),
        *offset,
        hob_slice.pread::<Header>(0).ok()?.length,
    )?;
    Some(hob_slice)
}

fn create_migration_information(
    mig_info_hob: Option<&[u8]>,
    mig_socket_hob: Option<&[u8]>,
    policy_info_hob: Option<&[u8]>,
) -> Option<MigrationInformation> {
    let mig_info = hob_lib::get_guid_data(mig_info_hob?)?
        .pread::<MigtdMigrationInformation>(0)
        .ok()?;

    let mig_socket_info = hob_lib::get_guid_data(mig_socket_hob?)?
        .pread::<MigtdStreamSocketInfo>(0)
        .ok()?;

    let mig_policy = policy_info_hob.and_then(|hob| {
        let policy_raw = hob_lib::get_guid_data(hob)?;
        let policy_header = policy_raw.pread::<MigtdMigpolicyInfo>(0).ok()?;
        let offset = size_of::<MigtdMigpolicyInfo>();
        let policy_data = policy_raw
            .get(offset..offset + policy_header.mig_policy_size as usize)?
            .to_vec();
        Some(MigtdMigpolicy {
            header: policy_header,
            mig_policy: policy_data,
        })
    });

    Some(MigrationInformation {
        mig_info,
        mig_socket_info,
        mig_policy,
    })
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

fn cal_mig_version(
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

fn set_mig_version(info: &MigrationInformation, mig_ver: u16) -> Result<()> {
    tdcall_servtd_wr(
        info.mig_info.binding_handle,
        TDCS_FIELD_MIG_VERSION,
        mig_ver as u64,
        &info.mig_info.target_td_uuid,
    )?;
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::migration::{session::cal_mig_version, MigrationResult};
    use scroll::Pwrite;
    use td_shim_interface::td_uefi_pi::pi::hob::{
        GuidExtension, Header, HOB_TYPE_END_OF_HOB_LIST, HOB_TYPE_GUID_EXTENSION,
        HOB_TYPE_RESOURCE_DESCRIPTOR,
    };

    use super::*;

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

    #[test]
    fn test_read_mig_info_valid_hobs() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 1024];
        let mut offset = 0;

        // Add Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add Stream Socket Information HOB
        create_socket_info_hob(&mut hob_data, &mut offset);
        // Add Migration Policy HOB
        create_policy_info_hob(&mut hob_data, &mut offset);
        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Call the function
        let result = read_mig_info(&hob_data);

        // Assert the result is valid
        assert!(result.is_some());
        let mig_info = result.unwrap();
        assert!(mig_info.mig_policy.is_some());
    }

    #[test]
    fn test_read_mig_info_duplicate_mig_info_hob() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 1024];
        let mut offset = 0;

        // Add Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add another Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add Stream Socket Information HOB
        create_socket_info_hob(&mut hob_data, &mut offset);
        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Call the function
        let result = read_mig_info(&hob_data);

        // Assert the result is None due to duplicate HOB
        assert!(result.is_none());
    }

    #[test]
    fn test_read_mig_info_duplicate_socket_info_hob() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 1024];
        let mut offset = 0;

        // Add Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add Stream Socket Information HOB
        create_socket_info_hob(&mut hob_data, &mut offset);
        // Add another Stream Socket Information HOB
        create_socket_info_hob(&mut hob_data, &mut offset);
        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Call the function
        let result = read_mig_info(&hob_data);

        // Assert the result is None due to duplicate HOB
        assert!(result.is_none());
    }

    #[test]
    fn test_read_mig_info_duplicate_policy_info_hob() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 1024];
        let mut offset = 0;

        // Add Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add Stream Socket Information HOB
        create_socket_info_hob(&mut hob_data, &mut offset);
        // Add Policy Information HOB
        create_policy_info_hob(&mut hob_data, &mut offset);
        // Add another Policy Information HOB
        create_policy_info_hob(&mut hob_data, &mut offset);
        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Call the function
        let result = read_mig_info(&hob_data);

        // Assert the result is None due to duplicate HOB
        assert!(result.is_none());
    }

    #[test]
    fn test_read_mig_info_missing_mig_info_hob() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 1024];
        let mut offset = 0;

        // Add Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add Policy Information HOB
        create_policy_info_hob(&mut hob_data, &mut offset);
        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Call the function
        let result = read_mig_info(&hob_data);

        // Assert the result is None due to missing migration information HOB
        assert!(result.is_none());
    }

    #[test]
    fn test_read_mig_info_missing_socket_info_hob() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 1024];
        let mut offset = 0;

        // Add Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add Policy Information HOB
        create_policy_info_hob(&mut hob_data, &mut offset);
        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Call the function
        let result = read_mig_info(&hob_data);

        assert!(result.is_none());
    }

    #[test]
    fn test_read_mig_info_missing_policy_info_hob() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 1024];
        let mut offset = 0;

        // Add Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add Stream Socket Information HOB
        create_socket_info_hob(&mut hob_data, &mut offset);
        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Call the function
        let mig_info = read_mig_info(&hob_data).unwrap();

        // Assert the result is None because policy information HOB does not exist
        assert!(mig_info.mig_policy.is_none());
    }

    #[test]
    fn test_read_mig_info_unexpected_hob_type() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 1024];
        let mut offset = 0;

        // Add an unexpected HOB type
        let unexpected_hob = Header {
            r#type: HOB_TYPE_RESOURCE_DESCRIPTOR,
            length: 64,
            reserved: 0,
        };
        hob_data.pwrite(unexpected_hob, offset).unwrap();
        offset += unexpected_hob.length as usize;

        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Call the function
        let result = read_mig_info(&hob_data);

        // Assert the result is None due to unexpected HOB type
        assert!(result.is_none());
    }

    #[test]
    fn test_read_unknown_guided_hob() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 1024];
        let mut offset = 0;

        // Add Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add Stream Socket Information HOB
        create_socket_info_hob(&mut hob_data, &mut offset);
        // Add a unknown GUIDed HOB
        create_unknown_guided_hob(&mut hob_data, &mut offset);
        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Call the function
        let result = read_mig_info(&hob_data);

        // Assert the result is None due to unknown GUIDed HOB
        assert!(result.is_none());
    }

    #[test]
    fn test_read_mig_info_invalid_hob_length() {
        // Create mock HOB data
        let mut hob_data = vec![0u8; 256];
        let mut offset = 0;

        // Add Migration Information HOB
        create_mig_info_hob(&mut hob_data, &mut offset);
        // Add Stream Socket Information HOB
        create_socket_info_hob(&mut hob_data, &mut offset);
        // Add End of HOB List
        create_end_of_hob_list(&mut hob_data, &mut offset);

        // Modify the length of the Migration Information HOB
        hob_data[2..4].copy_from_slice(&1024u16.to_le_bytes());

        // Call the function
        let result = read_mig_info(&hob_data);

        // Assert the result is None due to invalid HOB length
        assert!(result.is_none());
    }

    fn create_unknown_guided_hob(hob: &mut [u8], offset: &mut usize) {
        let guid = [0x10u8; 16];
        let guided_hob = create_guid_hob(&guid, 64);
        hob.pwrite(guided_hob, *offset).unwrap();
        *offset += size_of::<GuidExtension>() + 64;
    }

    fn create_mig_info_hob(hob: &mut [u8], offset: &mut usize) {
        let mig_info_hob_guid = MIGRATION_INFORMATION_HOB_GUID.as_bytes();
        let mig_info_hob =
            create_guid_hob(mig_info_hob_guid, size_of::<MigtdMigrationInformation>());
        let mig_info = MigtdMigrationInformation {
            mig_request_id: 0,
            migration_source: 1,
            _pad: [0, 0, 0, 0, 0, 0, 0],
            target_td_uuid: [0, 0, 0, 0],
            binding_handle: 0,
            mig_policy_id: 0,
            communication_id: 0,
        };
        hob.pwrite(mig_info_hob, *offset).unwrap();
        *offset += size_of::<GuidExtension>();
        hob.pwrite(mig_info, *offset).unwrap();
        *offset += size_of::<MigtdMigrationInformation>();
    }

    fn create_socket_info_hob(hob: &mut [u8], offset: &mut usize) {
        let stream_socket_hob_guid = STREAM_SOCKET_INFO_HOB_GUID.as_bytes();
        let stream_socket_hob =
            create_guid_hob(stream_socket_hob_guid, size_of::<MigtdStreamSocketInfo>());
        let stream_socket_info = MigtdStreamSocketInfo {
            communication_id: 0,
            mig_td_cid: 0,
            mig_channel_port: 0,
            quote_service_port: 0,
        };
        hob.pwrite(stream_socket_hob, *offset).unwrap();
        *offset += size_of::<GuidExtension>();
        hob.pwrite(stream_socket_info, *offset).unwrap();
        *offset += size_of::<MigtdStreamSocketInfo>();
    }

    fn create_policy_info_hob(hob: &mut [u8], offset: &mut usize) {
        let mig_policy_hob_guid = MIGPOLICY_HOB_GUID.as_bytes();
        let mig_policy_hob =
            create_guid_hob(mig_policy_hob_guid, size_of::<MigtdMigpolicyInfo>() + 64);
        hob.pwrite(mig_policy_hob, *offset).unwrap();
        *offset += size_of::<GuidExtension>();
        let mig_policy_info = MigtdMigpolicyInfo {
            mig_policy_id: 0,
            mig_policy_size: 64,
        };
        hob.pwrite(mig_policy_info, *offset).unwrap();
        *offset += size_of::<MigtdMigpolicyInfo>() + 64;
    }

    fn create_end_of_hob_list(hob: &mut [u8], offset: &mut usize) {
        let end_hob = Header {
            r#type: HOB_TYPE_END_OF_HOB_LIST,
            length: 24,
            reserved: 0,
        };
        hob.pwrite(end_hob, *offset).unwrap();
        *offset += size_of::<Header>();
    }

    fn create_guid_hob(guid: &[u8], length: usize) -> GuidExtension {
        GuidExtension {
            header: Header {
                r#type: HOB_TYPE_GUID_EXTENSION,
                length: (length + size_of::<GuidExtension>()) as u16,
                reserved: 0,
            },
            name: {
                let mut name = [0u8; 16];
                name.copy_from_slice(guid);
                name
            },
        }
    }
}
