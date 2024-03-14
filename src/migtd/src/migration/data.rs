// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;
use core::{mem::size_of, slice::from_raw_parts, slice::from_raw_parts_mut};
use r_efi::efi::Guid;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use super::MigrationResult;

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

    pub fn data(&self) -> &[u8] {
        &self.data[24..]
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
pub struct ServiceMigWaitForReqResponse {
    pub version: u8,
    pub command: u8,
    pub operation: u8,
    pub reserved: u8,
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::migration::VMCALL_SERVICE_COMMON_GUID;

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
}
