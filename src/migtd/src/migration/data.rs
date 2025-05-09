// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;
use core::{mem::size_of, slice::from_raw_parts, slice::from_raw_parts_mut};
use r_efi::efi::Guid;
#[cfg(not(feature = "vmcall-raw"))]
use td_shim_interface::td_uefi_pi::{
    hob::{self as hob_lib, align_to_next_hob_offset},
    pi::hob::{GuidExtension, Header, HOB_TYPE_END_OF_HOB_LIST, HOB_TYPE_GUID_EXTENSION},
};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use super::*;

pub const QUERY_COMMAND: u8 = 0;
pub const MIG_COMMAND_SHUT_DOWN: u8 = 0;
pub const MIG_COMMAND_WAIT: u8 = 1;
pub const MIG_COMMAND_REPORT_STATUS: u8 = 2;

pub struct VmcallServiceCommand<'a> {
    data: &'a mut [u8],
    offset: usize,
}

// According to GHCI v1.5 table 3-40, the command buffer
// layout is:
// GUID -- 16bytes
// Length -- 4bytes
// Reserved -- 4bytes
// Data -- N
const COMMAND_HEADER_LENGTH: usize = 24;

impl<'a> VmcallServiceCommand<'a> {
    pub fn new(data: &'a mut [u8], guid: Guid) -> Option<Self> {
        if data.len() < COMMAND_HEADER_LENGTH {
            return None;
        }
        data.fill(0);
        // GUID field
        data[0..16].copy_from_slice(guid.as_bytes());
        // Length field
        data[16..20].copy_from_slice(&u32::to_le_bytes(24));
        // Reserved field
        data[20..24].copy_from_slice(&u32::to_le_bytes(0));
        Some(Self { data, offset: 24 })
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<(), MigrationResult> {
        if bytes.len() > self.data.len() - self.offset {
            return Err(MigrationResult::InvalidParameter);
        }

        self.data[self.offset..self.offset + bytes.len()].copy_from_slice(bytes);
        self.offset += bytes.len();

        // Update the length field
        self.data[16..20].copy_from_slice(&u32::to_le_bytes(self.offset as u32));

        Ok(())
    }
}

#[repr(packed)]
pub struct ServiceMigWaitForReqCommand {
    pub version: u8,
    pub command: u8,
    pub reserved: [u8; 2],
}

impl ServiceMigWaitForReqCommand {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

#[repr(packed)]
pub struct ServiceMigReportStatusCommand {
    pub version: u8,
    pub command: u8,
    pub operation: u8,
    pub status: u8,
    pub mig_request_id: u64,
}

impl ServiceMigReportStatusCommand {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

pub struct VmcallServiceResponse<'a> {
    data: &'a [u8],
}

// According to GHCI v1.5 table 3-41, the response buffer
// layout is:
// GUID -- 16bytes
// Length -- 4bytes
// Status -- 4bytes
// Data -- N
const RESPONSE_HEADER_LENGTH: usize = 24;

impl<'a> VmcallServiceResponse<'a> {
    pub fn try_read(data: &'a [u8]) -> Option<Self> {
        if data.len() < RESPONSE_HEADER_LENGTH {
            return None;
        }
        // Safty:
        // length of slice response has been checked
        let length = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;

        // Validate the content read from VMM input data
        if length < RESPONSE_HEADER_LENGTH || length > data.len() {
            return None;
        }
        Some(Self { data })
    }

    pub fn new(response: &'a mut [u8], guid: Guid) -> Option<Self> {
        if response.len() < RESPONSE_HEADER_LENGTH {
            return None;
        }
        let len = response.len();
        response.fill(0);
        // GUID field
        response[0..16].copy_from_slice(guid.as_bytes());
        // Length field
        response[16..20].copy_from_slice(&u32::to_le_bytes(len as u32));
        // Reserved field
        response[20..24].copy_from_slice(&u32::to_le_bytes(0));
        Some(Self { data: response })
    }

    pub fn read_guid(&self) -> &[u8] {
        &self.data[..16]
    }

    #[allow(unused)]
    pub fn read_status(&self) -> u32 {
        // Safe since length has been checked when create the instance
        u32::from_le_bytes(self.data[20..24].try_into().unwrap())
    }

    pub fn read_data<T: FromBytes>(&self, offset: usize) -> Option<T> {
        if self.data.len() < (24 + offset + size_of::<T>()) {
            return None;
        }

        T::read_from(&self.data[24 + offset..24 + offset + size_of::<T>()])
    }
}

#[repr(packed)]
#[derive(Debug, FromZeroes, FromBytes, AsBytes)]
pub struct ServiceQueryResponse {
    pub version: u8,
    pub command: u8,
    pub status: u8,
    pub reserved: u8,
    pub guid: [u8; 16],
}

#[repr(packed)]
#[derive(FromZeroes, FromBytes, AsBytes)]
#[cfg(not(feature = "vmcall-raw"))]
pub struct ServiceMigWaitForReqResponse {
    pub version: u8,
    pub command: u8,
    pub operation: u8,
    pub reserved: u8,
}

#[repr(C)]
#[derive(FromZeroes, FromBytes, AsBytes)]
#[cfg(feature = "vmcall-raw")]
pub struct ServiceMigWaitForReqResponse {
    pub data_status: u32,
    pub request_type: u32,
    pub mig_request_id: u64,
    pub migration_source: u8,
    pub reserved: [u8; 7],
    pub target_td_uuid: [u64; 4],
    pub binding_handle: u64,
}

#[repr(packed)]
#[derive(FromZeroes, FromBytes, AsBytes)]
pub struct ServiceMigWaitForReqShutdown {
    pub version: u8,
    pub command: u8,
    pub reserved: [u8; 2],
}

#[repr(packed)]
#[derive(FromZeroes, FromBytes, AsBytes)]
pub struct ServiceMigReportStatusResponse {
    pub version: u8,
    pub command: u8,
    pub reserved: [u8; 2],
}

pub struct MigrationSessionKey {
    pub fields: [u64; 4],
}

impl MigrationSessionKey {
    pub fn new() -> Self {
        Self { fields: [0u64; 4] }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(self as *mut Self as *mut u8, size_of::<Self>()) }
    }

    pub fn clear(&mut self) {
        self.fields.fill(0);
    }
}

impl Default for MigrationSessionKey {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MigrationInformation {
    pub mig_info: MigtdMigrationInformation,
    #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))]
    pub mig_socket_info: MigtdStreamSocketInfo,
    #[cfg(not(feature = "vmcall-raw"))]
    pub mig_policy: Option<MigtdMigpolicy>,
}

impl MigrationInformation {
    pub fn is_src(&self) -> bool {
        self.mig_info.migration_source == 1
    }
}

#[cfg(not(feature = "vmcall-raw"))]
pub fn read_mig_info(hob: &[u8]) -> Option<MigrationInformation> {
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

#[cfg(not(feature = "vmcall-raw"))]
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

#[allow(unused)]
#[cfg(not(feature = "vmcall-raw"))]
fn create_migration_information(
    mig_info_hob: Option<&[u8]>,
    mig_socket_hob: Option<&[u8]>,
    policy_info_hob: Option<&[u8]>,
) -> Option<MigrationInformation> {
    let mig_info = hob_lib::get_guid_data(mig_info_hob?)?
        .pread::<MigtdMigrationInformation>(0)
        .ok()?;

    #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))]
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
        #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))]
        mig_socket_info,
        mig_policy,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::migration::VMCALL_SERVICE_COMMON_GUID;

    use scroll::Pwrite;
    use td_shim_interface::td_uefi_pi::pi::hob::{
        GuidExtension, Header, HOB_TYPE_END_OF_HOB_LIST, HOB_TYPE_GUID_EXTENSION,
        HOB_TYPE_RESOURCE_DESCRIPTOR,
    };

    #[test]
    fn test_vmcallservicecommand_001() {
        let mut data = [0u8; COMMAND_HEADER_LENGTH];
        let ret = VmcallServiceCommand::new(data.as_bytes_mut(), VMCALL_SERVICE_COMMON_GUID);
        assert!(ret.is_some());

        let mut cmd = ret.unwrap();
        let query = [0u8; 1];
        cmd.write(query.as_bytes());
    }

    #[test]
    fn test_vmcallservicecommand_002() {
        let mut data = [0u8; COMMAND_HEADER_LENGTH - 1];
        let ret = VmcallServiceCommand::new(data.as_bytes_mut(), VMCALL_SERVICE_COMMON_GUID);
        assert!(ret.is_none());
    }

    #[test]
    fn test_vmcallservicecommand_003() {
        let mut data = [0u8; COMMAND_HEADER_LENGTH + 1];
        let ret = VmcallServiceCommand::new(data.as_bytes_mut(), VMCALL_SERVICE_COMMON_GUID);
        assert!(ret.is_some());

        let mut cmd = ret.unwrap();
        let query = [0u8; 1];
        cmd.write(query.as_bytes());
        let length = u32::from_le_bytes(cmd.data[16..20].try_into().unwrap()) as usize;
        assert_eq!(length, COMMAND_HEADER_LENGTH + 1);
    }

    #[test]
    fn test_vmcallserviceresponse_001() {
        let mut rsp_mem = [0u8; RESPONSE_HEADER_LENGTH];
        let _ = VmcallServiceResponse::new(rsp_mem.as_bytes_mut(), VMCALL_SERVICE_COMMON_GUID);

        let ret = VmcallServiceResponse::try_read(rsp_mem.as_bytes());
        assert!(ret.is_some());

        let rsp = ret.unwrap();
        assert_eq!(rsp.read_guid(), VMCALL_SERVICE_COMMON_GUID.as_bytes());
    }

    #[test]
    fn test_vmcallserviceresponse_002() {
        let mut rsp_mem = [0u8; RESPONSE_HEADER_LENGTH + 1];
        let _ = VmcallServiceResponse::new(rsp_mem.as_bytes_mut(), VMCALL_SERVICE_COMMON_GUID);

        let ret = VmcallServiceResponse::try_read(rsp_mem.as_bytes());
        assert!(ret.is_some());

        let rsp = ret.unwrap();
        assert_eq!(rsp.read_guid(), VMCALL_SERVICE_COMMON_GUID.as_bytes());

        let status = rsp.read_status();
        assert_eq!(status, 0);

        let ret1 = rsp.read_data::<u8>(0);
        assert!(ret1.is_some());

        let ret1 = rsp.read_data::<u16>(0);
        assert!(ret1.is_none());
    }

    #[test]
    fn test_vmcallserviceresponse_003() {
        let mut rsp_mem = [0u8; RESPONSE_HEADER_LENGTH - 1];
        let ret = VmcallServiceResponse::new(rsp_mem.as_bytes_mut(), VMCALL_SERVICE_COMMON_GUID);
        assert!(ret.is_none());
    }

    #[test]
    fn test_vmcallserviceresponse_004() {
        let mut data = [0u8; RESPONSE_HEADER_LENGTH - 1];
        let ret = VmcallServiceResponse::try_read(data.as_bytes_mut());
        assert!(ret.is_none());
    }

    #[test]
    fn test_vmcallserviceresponse_005() {
        let mut data = [0u8; RESPONSE_HEADER_LENGTH];
        data[16..20].copy_from_slice(&u32::to_le_bytes(RESPONSE_HEADER_LENGTH as u32 - 1));
        let ret = VmcallServiceResponse::try_read(data.as_bytes_mut());
        assert!(ret.is_none());
    }

    #[test]
    fn test_vmcallserviceresponse_006() {
        let mut data = [0u8; RESPONSE_HEADER_LENGTH];
        data[16..20].copy_from_slice(&u32::to_le_bytes(RESPONSE_HEADER_LENGTH as u32 + 1));
        let ret = VmcallServiceResponse::try_read(data.as_bytes_mut());
        assert!(ret.is_none());
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

        #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))]
        assert!(result.is_none());
        #[cfg(feature = "virtio-serial")]
        assert!(result.is_some());
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
