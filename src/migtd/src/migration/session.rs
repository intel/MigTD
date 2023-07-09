// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use core::mem::size_of;
use scroll::Pread;
use td_payload::mm::dma::DmaMemory;
use td_uefi_pi::hob as hob_lib;
use tdx_tdcall::tdx;
use zerocopy::AsBytes;

type Result<T> = core::result::Result<T, MigrationResult>;

use super::{data::*, *};
use crate::ratls;

const TDCS_FIELD_MIG_DEC_KEY: u64 = 0x9810_0003_0000_0010;
const TDCS_FIELD_MIG_ENC_KEY: u64 = 0x9810_0003_0000_0018;
const MSK_SIZE: usize = 32;

pub struct MigrationInformation {
    pub mig_info: MigtdMigrationInformation,
    pub mig_socket_info: MigtdStreamSocketInfo,
    pub mig_policy: Option<MigtdMigpolicy>,
}

#[derive(Debug, Clone, Copy)]
struct RequestInformation {
    request_id: u64,
    operation: u8,
}

enum MigrationState {
    WaitForRequest,
    Operate(MigrationOperation),
    Complete(RequestInformation),
}

enum MigrationOperation {
    Migrate(MigrationInformation),
}

pub struct MigrationSession {
    state: MigrationState,
}

impl MigrationSession {
    pub fn new() -> Self {
        MigrationSession {
            state: MigrationState::WaitForRequest,
        }
    }

    pub fn query() -> Result<()> {
        // Allocate one shared page for command and response buffer
        let mut cmd_mem = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
        let mut rsp_mem = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

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

        let private_mem = Self::copy_from_shared_memory(rsp_mem.as_bytes());

        // Parse the response data
        // Check the GUID of the reponse
        let rsp = VmcallServiceResponse::try_read(private_mem.as_bytes())
            .ok_or(MigrationResult::InvalidParameter)?;
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

    pub fn wait_for_request(&mut self) -> Result<()> {
        match self.state {
            MigrationState::WaitForRequest => {
                // Allocate shared page for command and response buffer
                let mut cmd_mem = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
                let mut rsp_mem = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

                // Set Migration wait for request command buffer
                let mut cmd =
                    VmcallServiceCommand::new(cmd_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
                        .ok_or(MigrationResult::InvalidParameter)?;
                let wfr = ServiceMigWaitForReqCommand {
                    version: 0,
                    command: MIG_COMMAND_WAIT,
                    reserved: [0; 2],
                };
                cmd.write(wfr.as_bytes())?;
                let _ =
                    VmcallServiceResponse::new(rsp_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
                        .ok_or(MigrationResult::InvalidParameter)?;

                loop {
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

                    let private_mem = Self::copy_from_shared_memory(rsp_mem.as_bytes());

                    // Parse out the response data
                    let rsp = VmcallServiceResponse::try_read(private_mem.as_bytes())
                        .ok_or(MigrationResult::InvalidParameter)?;
                    // Check the GUID of the reponse
                    if rsp.read_guid() != VMCALL_SERVICE_MIGTD_GUID.as_bytes() {
                        return Err(MigrationResult::InvalidParameter);
                    }
                    let wfr = rsp
                        .read_data::<ServiceMigWaitForReqResponse>(0)
                        .ok_or(MigrationResult::InvalidParameter)?;
                    if wfr.command != MIG_COMMAND_WAIT {
                        return Err(MigrationResult::InvalidParameter);
                    }
                    if wfr.operation == 1 {
                        let mig_info = Self::read_mig_info(
                            &private_mem[24 + size_of::<ServiceMigWaitForReqResponse>()..],
                        )
                        .ok_or(MigrationResult::InvalidParameter)?;
                        self.state = MigrationState::Operate(MigrationOperation::Migrate(mig_info));

                        return Ok(());
                    } else if wfr.operation != 0 {
                        break;
                    }
                }
                Err(MigrationResult::InvalidParameter)
            }
            _ => Err(MigrationResult::InvalidParameter),
        }
    }

    pub fn info(&self) -> Option<&MigrationInformation> {
        match &self.state {
            MigrationState::Operate(operation) => match operation {
                MigrationOperation::Migrate(info) => Some(info),
            },
            _ => None,
        }
    }

    pub fn op(&mut self) -> Result<()> {
        match &self.state {
            MigrationState::Operate(operation) => match operation {
                MigrationOperation::Migrate(info) => {
                    let state = Self::migrate(info);
                    self.state = MigrationState::Complete(RequestInformation {
                        request_id: info.mig_info.mig_request_id,
                        operation: 1,
                    });

                    state
                }
            },
            _ => Err(MigrationResult::InvalidParameter),
        }
    }

    pub fn shutdown() -> Result<()> {
        // Allocate shared page for command and response buffer
        let mut cmd_mem = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
        let mut rsp_mem = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

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

    pub fn report_status(&self, status: u8) -> Result<()> {
        let request = match &self.state {
            MigrationState::Complete(request) => *request,
            _ => return Err(MigrationResult::InvalidParameter),
        };

        // Allocate shared page for command and response buffer
        let mut cmd_mem = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
        let mut rsp_mem = DmaMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

        // Set Command
        let mut cmd = VmcallServiceCommand::new(cmd_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
            .ok_or(MigrationResult::InvalidParameter)?;

        let rs = ServiceMigReportStatusCommand {
            version: 0,
            command: MIG_COMMAND_REPORT_STATUS,
            operation: request.operation,
            status,
            mig_request_id: request.request_id,
        };

        cmd.write(rs.as_bytes())?;

        let _ = VmcallServiceResponse::new(rsp_mem.as_mut_bytes(), VMCALL_SERVICE_MIGTD_GUID)
            .ok_or(MigrationResult::InvalidParameter)?;

        tdx::tdvmcall_service(cmd_mem.as_bytes(), rsp_mem.as_mut_bytes(), 0, 0)?;

        let private_mem = Self::copy_from_shared_memory(rsp_mem.as_bytes());

        // Parse the response data
        // Check the GUID of the reponse
        let rsp = VmcallServiceResponse::try_read(private_mem.as_bytes())
            .ok_or(MigrationResult::InvalidParameter)?;
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

    fn migrate(info: &MigrationInformation) -> Result<()> {
        let mut msk = MigrationSessionKey::new();
        let mut msk_peer = MigrationSessionKey::new();

        for idx in 0..msk.fields.len() {
            let ret = tdx::tdcall_servtd_rd(
                info.mig_info.binding_handle,
                TDCS_FIELD_MIG_ENC_KEY + idx as u64,
                &info.mig_info.target_td_uuid,
            )?;
            msk.fields[idx] = ret.content;
        }

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
            let mut vsock = VsockStream::new()?;
            vsock.connect(&VsockAddr::new(
                info.mig_socket_info.mig_td_cid as u32,
                info.mig_socket_info.mig_channel_port,
            ))?;

            transport = vsock;
        };

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

        for idx in 0..msk.fields.len() {
            tdx::tdcall_servtd_wr(
                info.mig_info.binding_handle,
                TDCS_FIELD_MIG_DEC_KEY + idx as u64,
                msk_peer.fields[idx],
                &info.mig_info.target_td_uuid,
            )
            .map_err(|_| MigrationResult::TdxModuleError)?;
        }
        log::info!("Set MSK and report status\n");
        msk.clear();
        msk_peer.clear();

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
}
