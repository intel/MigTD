// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use core::mem::size_of;
use scroll::Pread;
use td_payload::mm::shared::SharedMemory;
use td_shim_interface::td_uefi_pi::hob as hob_lib;
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

#[derive(Debug, Clone, Copy)]
struct RequestInformation {
    request_id: u64,
    operation: u8,
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

impl Default for MigrationSession {
    fn default() -> Self {
        Self::new()
    }
}

impl MigrationSession {
    pub fn new() -> Self {
        MigrationSession {
            state: MigrationState::WaitForRequest,
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
        let rsp = VmcallServiceResponse::try_read(private_mem)
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
                let mut cmd_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
                let mut rsp_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

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

                    let private_mem = rsp_mem
                        .copy_to_private_shadow()
                        .ok_or(MigrationResult::OutOfResource)?;

                    // Parse out the response data
                    let rsp = VmcallServiceResponse::try_read(private_mem)
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

    #[cfg(feature = "main")]
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

    pub fn report_status(&self, status: u8) -> Result<()> {
        let request = match &self.state {
            MigrationState::Complete(request) => *request,
            _ => return Err(MigrationResult::InvalidParameter),
        };

        // Allocate shared page for command and response buffer
        let mut cmd_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;
        let mut rsp_mem = SharedMemory::new(1).ok_or(MigrationResult::OutOfResource)?;

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

        let private_mem = rsp_mem
            .copy_to_private_shadow()
            .ok_or(MigrationResult::OutOfResource)?;

        // Parse the response data
        // Check the GUID of the reponse
        let rsp = VmcallServiceResponse::try_read(private_mem)
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

    #[cfg(feature = "main")]
    fn migrate(info: &MigrationInformation) -> Result<()> {
        let mut msk = MigrationSessionKey::new();

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

        let mut remote_information = ExchangeInformation::default();
        let mut exchange_information = ExchangeInformation {
            key: msk,
            ..Default::default()
        };

        // Establish TLS layer connection and negotiate the MSK
        if info.is_src() {
            let min_export_version = tdcall_sys_rd(GSM_FIELD_MIN_EXPORT_VERSION)?.1;
            let max_export_version = tdcall_sys_rd(GSM_FIELD_MAX_EXPORT_VERSION)?.1;
            if min_export_version > u16::MAX as u64 || max_export_version > u16::MAX as u64 {
                return Err(MigrationResult::InvalidParameter);
            }
            exchange_information.min_ver = min_export_version as u16;
            exchange_information.max_ver = max_export_version as u16;

            // TLS client
            let mut ratls_client =
                ratls::client(transport).map_err(|_| MigrationResult::SecureSessionError)?;

            // MigTD-S send Migration Session Forward key to peer
            ratls_client.write(exchange_information.as_bytes())?;
            let size = ratls_client.read(remote_information.as_bytes_mut())?;
            if size < size_of::<ExchangeInformation>() {
                return Err(MigrationResult::NetworkError);
            }
        } else {
            let min_import_version = tdcall_sys_rd(GSM_FIELD_MIN_IMPORT_VERSION)?.1;
            let max_import_version = tdcall_sys_rd(GSM_FIELD_MAX_IMPORT_VERSION)?.1;
            if min_import_version > u16::MAX as u64 || max_import_version > u16::MAX as u64 {
                return Err(MigrationResult::InvalidParameter);
            }
            exchange_information.min_ver = min_import_version as u16;
            exchange_information.max_ver = max_import_version as u16;

            // TLS server
            let mut ratls_server =
                ratls::server(transport).map_err(|_| MigrationResult::SecureSessionError)?;

            ratls_server.write(exchange_information.as_bytes())?;
            let size = ratls_server.read(remote_information.as_bytes_mut())?;
            if size < size_of::<ExchangeInformation>() {
                return Err(MigrationResult::NetworkError);
            }
        }

        let mig_ver = cal_mig_version(info.is_src(), &exchange_information, &remote_information)?;
        set_mig_version(info, mig_ver)?;

        for idx in 0..remote_information.key.fields.len() {
            tdx::tdcall_servtd_wr(
                info.mig_info.binding_handle,
                TDCS_FIELD_MIG_DEC_KEY + idx as u64,
                remote_information.key.fields[idx],
                &info.mig_info.target_td_uuid,
            )
            .map_err(|_| MigrationResult::TdxModuleError)?;
        }
        log::info!("Set MSK and report status\n");
        exchange_information.key.clear();
        remote_information.key.clear();

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
