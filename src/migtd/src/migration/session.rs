// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "async")]
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::mem::size_of;
#[cfg(feature = "async")]
use core::time::Duration;
#[cfg(feature = "async")]
use lazy_static::lazy_static;
use scroll::Pread;
#[cfg(feature = "async")]
use spin::Mutex;
use td_payload::mm::dma::DmaMemory;
use td_uefi_pi::hob as hob_lib;
use tdx_tdcall::tdx;
use zerocopy::AsBytes;

type Result<T> = core::result::Result<T, MigrationResult>;

use super::{data::*, *};
#[cfg(feature = "async")]
use crate::driver::ticks::with_timeout;
use crate::ratls;

const TDCS_FIELD_MIG_DEC_KEY: u64 = 0x9810_0003_0000_0010;
const TDCS_FIELD_MIG_ENC_KEY: u64 = 0x9810_0003_0000_0018;
const MSK_SIZE: usize = 32;
#[cfg(feature = "async")]
const TLS_TIMEOUT: Duration = Duration::from_secs(10); // 10 seconds

#[cfg(feature = "async")]
lazy_static! {
    pub static ref REQUESTS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
}

pub struct MigrationInformation {
    pub mig_info: MigtdMigrationInformation,
    pub mig_socket_info: MigtdStreamSocketInfo,
    pub mig_policy: Option<MigtdMigpolicy>,
}

struct VmcallService {
    command: DmaMemory,
    response: DmaMemory,
    private: Vec<u8>,
}

impl<'a> VmcallService {
    fn new() -> Result<Self> {
        // Allocate one shared page for each command and response buffer
        let command = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
        let response = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
        Ok(Self {
            command,
            response,
            private: Vec::new(),
        })
    }

    fn call(&mut self) -> Result<()> {
        #[cfg(feature = "vmcall-interrupt")]
        {
            tdx::tdvmcall_service(
                self.command.as_bytes(),
                self.response.as_mut_bytes(),
                event::VMCALL_SERVICE_VECTOR as u64,
                0,
            )?;
            #[cfg(not(feature = "async"))]
            event::wait_for_event(&event::VMCALL_SERVICE_FLAG);
        }
        #[cfg(not(feature = "vmcall-interrupt"))]
        tdx::tdvmcall_service(self.command.as_bytes(), self.response.as_mut_bytes(), 0, 0)?;

        Ok(())
    }

    fn create_vsc(&'a mut self, guid: Guid) -> Result<VmcallServiceCommand<'a>> {
        VmcallServiceCommand::new(self.command.as_mut_bytes(), guid)
            .ok_or(MigrationResult::InvalidParameter)
    }

    fn create_vsr(&'a mut self, guid: Guid) -> Result<()> {
        VmcallServiceResponse::new(self.response.as_mut_bytes(), guid)
            .ok_or(MigrationResult::InvalidParameter)
            .map(|_| ())
    }

    fn parse_vsr(&'a mut self) -> Result<VmcallServiceResponse<'a>> {
        self.private = copy_from_shared_memory(self.response.as_bytes());
        VmcallServiceResponse::try_read(self.private.as_slice())
            .ok_or(MigrationResult::InvalidParameter)
    }
}

pub fn query() -> Result<()> {
    let mut vmcall_service = VmcallService::new()?;

    // Set Migration query command buffer
    let mut command = vmcall_service.create_vsc(VMCALL_SERVICE_COMMON_GUID)?;
    let query = ServiceMigWaitForReqCommand {
        version: 0,
        command: QUERY_COMMAND,
        reserved: [0; 2],
    };
    command.write(query.as_bytes())?;
    command.write(VMCALL_SERVICE_MIGTD_GUID.as_bytes())?;

    // Set query response buffer
    vmcall_service.create_vsr(VMCALL_SERVICE_COMMON_GUID)?;

    // Execute the tdvmcall
    vmcall_service.call()?;

    // Parse the response data
    let response = vmcall_service.parse_vsr()?;

    // Check the GUID of the service reponse
    if response.read_guid() != VMCALL_SERVICE_COMMON_GUID.as_bytes() {
        return Err(MigrationResult::InvalidParameter);
    }

    // Check the validity query response
    let query = response
        .read_data::<ServiceQueryResponse>(0)
        .ok_or(MigrationResult::InvalidParameter)?;
    if query.command != QUERY_COMMAND || &query.guid != VMCALL_SERVICE_MIGTD_GUID.as_bytes() {
        return Err(MigrationResult::InvalidParameter);
    }
    if query.status != 0 {
        return Err(MigrationResult::Unsupported);
    }

    Ok(())
}

fn wait_for_request(vmcall_service: &mut VmcallService) -> Result<ServiceMigWaitForReqResponse> {
    // Set Migration wait for request command buffer
    let mut command = vmcall_service.create_vsc(VMCALL_SERVICE_MIGTD_GUID)?;
    let wfr = ServiceMigWaitForReqCommand {
        version: 0,
        command: MIG_COMMAND_WAIT,
        reserved: [0; 2],
    };
    command.write(wfr.as_bytes())?;

    // Set migtd response buffer
    vmcall_service.create_vsr(VMCALL_SERVICE_MIGTD_GUID)?;

    // Execute the tdvmcall
    vmcall_service.call()?;

    // Parse the response data
    let response = vmcall_service.parse_vsr()?;
    // Check the GUID of the service reponse
    if response.read_guid() != VMCALL_SERVICE_MIGTD_GUID.as_bytes() {
        return Err(MigrationResult::InvalidParameter);
    }

    // Check the validity of migtd response
    let wfr = response
        .read_data::<ServiceMigWaitForReqResponse>(0)
        .ok_or(MigrationResult::InvalidParameter)?;
    if wfr.command != MIG_COMMAND_WAIT {
        return Err(MigrationResult::InvalidParameter);
    }

    Ok(wfr)
}

pub fn wait_for_request_block() -> Result<MigrationInformation> {
    let mut vmcall_service = VmcallService::new()?;

    loop {
        // Check the validity of migtd response
        let wfr = wait_for_request(&mut vmcall_service)?;
        if wfr.operation == 1 {
            let mig_info = read_mig_info(
                &vmcall_service.private[24 + size_of::<ServiceMigWaitForReqResponse>()..],
            )
            .ok_or(MigrationResult::InvalidParameter)?;

            return Ok(mig_info);
        } else if wfr.operation != 0 {
            return Err(MigrationResult::InvalidParameter);
        }
    }
}

#[cfg(feature = "async")]
pub fn wait_for_request_nonblock() -> Result<Option<MigrationInformation>> {
    let mut vmcall_service = VmcallService::new()?;

    let wfr = wait_for_request(&mut vmcall_service)?;
    if wfr.operation == 1 {
        let info = read_mig_info(
            &vmcall_service.private[24 + size_of::<ServiceMigWaitForReqResponse>()..],
        )
        .ok_or(MigrationResult::InvalidParameter)?;

        let request_id = info.mig_info.mig_request_id;
        if REQUESTS.lock().contains(&request_id) {
            Ok(None)
        } else {
            REQUESTS.lock().insert(request_id);
            Ok(Some(info))
        }
    } else if wfr.operation == 0 {
        Ok(None)
    } else {
        Err(MigrationResult::InvalidParameter)
    }
}

pub fn shutdown() -> Result<()> {
    let mut vmcall_service = VmcallService::new()?;

    // Set migtd shutdown command
    let mut command = vmcall_service.create_vsc(VMCALL_SERVICE_MIGTD_GUID)?;
    let sd = ServiceMigWaitForReqShutdown {
        version: 0,
        command: MIG_COMMAND_SHUT_DOWN,
        reserved: [0; 2],
    };
    command.write(sd.as_bytes())?;

    // Execute the tdvmcall
    vmcall_service.call()
}

pub fn report_status(request: &MigrationInformation, status: u8) -> Result<()> {
    let mut vmcall_service = VmcallService::new()?;

    // Set migtd resport status command
    let mut command = vmcall_service.create_vsc(VMCALL_SERVICE_MIGTD_GUID)?;
    let rs = ServiceMigReportStatusCommand {
        version: 0,
        command: MIG_COMMAND_REPORT_STATUS,
        operation: 1,
        status,
        mig_request_id: request.mig_info.mig_request_id,
    };
    command.write(rs.as_bytes())?;

    // Set migtd response buffer
    vmcall_service.create_vsr(VMCALL_SERVICE_MIGTD_GUID)?;

    // Execute the tdvmcall
    vmcall_service.call()?;

    // Parse the response data
    let response = vmcall_service.parse_vsr()?;
    if response.read_guid() != VMCALL_SERVICE_MIGTD_GUID.as_bytes() {
        return Err(MigrationResult::InvalidParameter);
    }

    // Check the validity of migtd response
    let query = response
        .read_data::<ServiceMigReportStatusResponse>(0)
        .ok_or(MigrationResult::InvalidParameter)?;
    // Ensure the response matches the command
    if query.command != MIG_COMMAND_REPORT_STATUS {
        return Err(MigrationResult::InvalidParameter);
    }

    Ok(())
}

pub fn trans_msk(info: &MigrationInformation) -> Result<()> {
    let mut msk = MigrationSessionKey::new();
    let mut msk_peer = MigrationSessionKey::new();

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
        // Establish the vsock connection with host
        let mut vsock = VsockStream::new(true)?;
        vsock.connect(&VsockAddr::new(
            info.mig_socket_info.mig_td_cid as u32,
            info.mig_socket_info.mig_channel_port,
        ))?;

        transport = vsock;
    };

    read_msk(&info.mig_info, &mut msk)?;
    // Establish TLS layer connection and negotiate the MSK
    if info.mig_info.migration_source == 1 {
        // TLS client
        let mut ratls_client =
            ratls::client(transport).map_err(|_| MigrationResult::SecureSessionError)?;

        // MigTD-S send Migration Session Forward key to peer
        ratls_client.write(msk.as_bytes())?;
        let size = ratls_client.read(msk_peer.as_bytes_mut())?;
        if size < MSK_SIZE {
            return Err(MigrationResult::NetworkError);
        }
    } else {
        // TLS server
        let mut ratls_server =
            ratls::server(transport).map_err(|_| MigrationResult::SecureSessionError)?;

        ratls_server.write(msk.as_bytes())?;
        let size = ratls_server.read(msk_peer.as_bytes_mut())?;
        if size < MSK_SIZE {
            return Err(MigrationResult::NetworkError);
        }
    }

    log::info!("Set MSK and report status\n");
    write_msk(&info.mig_info, &msk_peer)?;
    msk.clear();
    msk_peer.clear();

    Ok(())
}

#[cfg(feature = "async")]
pub async fn trans_msk_async(info: &MigrationInformation) -> Result<()> {
    let mut msk = MigrationSessionKey::new();
    let mut msk_peer = MigrationSessionKey::new();

    let transport;
    // #[cfg(feature = "virtio-serial")]
    // {
    //     use virtio_serial::VirtioSerialPort;
    //     const VIRTIO_SERIAL_PORT_ID: u32 = 1;

    //     let port = VirtioSerialPort::new(VIRTIO_SERIAL_PORT_ID);
    //     port.open()?;
    //     transport = port;
    // };

    #[cfg(not(feature = "virtio-serial"))]
    {
        use vsock::{stream::VsockStream, VsockAddr};
        // Establish the vsock connection with host
        let mut vsock = VsockStream::new(false)?;
        vsock
            .async_connect(&VsockAddr::new(
                info.mig_socket_info.mig_td_cid as u32,
                info.mig_socket_info.mig_channel_port,
            ))
            .await?;

        transport = vsock;
    };

    read_msk(&info.mig_info, &mut msk)?;
    // Establish TLS layer connection and negotiate the MSK
    if info.mig_info.migration_source == 1 {
        // TLS client
        let mut ratls_client =
            ratls::async_client(transport).map_err(|_| MigrationResult::SecureSessionError)?;

        // MigTD-S send Migration Session Forward key to peer
        with_timeout(TLS_TIMEOUT, ratls_client.start()).await??;
        with_timeout(TLS_TIMEOUT, ratls_client.write(msk.as_bytes())).await??;
        let size = with_timeout(TLS_TIMEOUT, ratls_client.read(msk_peer.as_bytes_mut())).await??;
        if size < MSK_SIZE {
            return Err(MigrationResult::NetworkError);
        }
    } else {
        // TLS server
        let mut ratls_server =
            ratls::async_server(transport).map_err(|_| MigrationResult::SecureSessionError)?;

        with_timeout(TLS_TIMEOUT, ratls_server.start()).await??;
        with_timeout(TLS_TIMEOUT, ratls_server.write(msk.as_bytes())).await??;
        let size = with_timeout(TLS_TIMEOUT, ratls_server.read(msk_peer.as_bytes_mut())).await??;
        if size < MSK_SIZE {
            return Err(MigrationResult::NetworkError);
        }
    }

    log::info!("Set MSK and report status\n");
    write_msk(&info.mig_info, &msk_peer)?;
    msk.clear();
    msk_peer.clear();

    Ok(())
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

fn write_msk(mig_info: &MigtdMigrationInformation, msk_peer: &MigrationSessionKey) -> Result<()> {
    for idx in 0..msk_peer.fields.len() {
        tdx::tdcall_servtd_wr(
            mig_info.binding_handle,
            TDCS_FIELD_MIG_DEC_KEY + idx as u64,
            msk_peer.fields[idx],
            &mig_info.target_td_uuid,
        )
        .map_err(|_| MigrationResult::TdxModuleError)?;
    }

    Ok(())
}

fn read_mig_info(hob: &[u8]) -> Option<MigrationInformation> {
    let mig_info_hob =
        hob_lib::get_next_extension_guid_hob(hob, MIGRATION_INFORMATION_HOB_GUID.as_bytes())?;

    let mig_info = hob_lib::get_guid_data(mig_info_hob)?
        .pread::<MigtdMigrationInformation>(0)
        .ok()?;

    let mig_socket_hob =
        hob_lib::get_next_extension_guid_hob(hob, STREAM_SOCKET_INFO_HOB_GUID.as_bytes())?;

    let mig_socket_info = hob_lib::get_guid_data(mig_socket_hob)?
        .pread::<MigtdStreamSocketInfo>(0)
        .ok()?;

    // Migration Information is optional here
    let mut mig_policy = None;
    if let Some(policy_info_hob) =
        hob_lib::get_next_extension_guid_hob(hob, MIGPOLICY_HOB_GUID.as_bytes())
    {
        if let Some(policy_raw) = hob_lib::get_guid_data(policy_info_hob) {
            let policy_header = policy_raw.pread::<MigtdMigpolicyInfo>(0).ok()?;
            let mut policy_data: Vec<u8> = Vec::new();
            let offset = size_of::<MigtdMigpolicyInfo>();
            policy_data.extend_from_slice(
                &policy_raw[offset..offset + policy_header.mig_policy_size as usize],
            );
            mig_policy = Some(MigtdMigpolicy {
                header: policy_header,
                mig_policy: policy_data,
            });
        }
    }

    let mig_info = MigrationInformation {
        mig_info,
        mig_socket_info,
        mig_policy,
    };

    Some(mig_info)
}

fn copy_from_shared_memory(shared: &[u8]) -> Vec<u8> {
    let mut private = Vec::new();
    private.extend_from_slice(shared);
    private
}
