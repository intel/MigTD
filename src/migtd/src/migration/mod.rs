// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod data;
pub mod event;
#[cfg(feature = "main")]
pub mod session;

use crate::driver::ticks::TimeoutError;
use crate::ratls::RatlsError;
use crate::ratls::{
    INVALID_MIG_POLICY_ERROR, MIG_POLICY_UNSATISFIED_ERROR, MUTUAL_ATTESTATION_ERROR,
};
use alloc::string::ToString;
use alloc::vec::Vec;
use crypto::Error as CryptoError;
use r_efi::efi::Guid;
use rust_std_stub::io;
use scroll::{Pread, Pwrite};
use tdx_tdcall::TdCallError;
use tdx_tdcall::TdVmcallError;
#[cfg(feature = "virtio-serial")]
use virtio_serial::VirtioSerialError;
#[cfg(any(feature = "virtio-vsock", feature = "vmcall-vsock"))]
use vsock::VsockError;

pub const VMCALL_SERVICE_COMMON_GUID: Guid = Guid::from_fields(
    0xfb6fc5e1,
    0x3378,
    0x4acb,
    0x89,
    0x64,
    &[0xfa, 0x5e, 0xe4, 0x3b, 0x9c, 0x8a],
);

pub const VMCALL_SERVICE_MIGTD_GUID: Guid = Guid::from_fields(
    0xe60e6330,
    0x1e09,
    0x4387,
    0xa4,
    0x44,
    &[0x8f, 0x32, 0xb8, 0xd6, 0x11, 0xe5],
);

pub const MIGRATION_INFORMATION_HOB_GUID: Guid = Guid::from_fields(
    0x42b5e398,
    0xa199,
    0x4d30,
    0xbe,
    0xfc,
    &[0xc7, 0x5a, 0xc3, 0xda, 0x5d, 0x7c],
);

pub const MIGPOLICY_HOB_GUID: Guid = Guid::from_fields(
    0xd64f771a,
    0xf0c9,
    0x4d33,
    0x99,
    0x8b,
    &[0xe, 0x3d, 0x8b, 0x94, 0xa, 0x61],
);

pub const STREAM_SOCKET_INFO_HOB_GUID: Guid = Guid::from_fields(
    0x7a103b9d,
    0x552b,
    0x485f,
    0xbb,
    0x4c,
    &[0x2f, 0x3d, 0x2e, 0x8b, 0x1e, 0xe],
);

#[repr(C)]
#[derive(Debug, Pread, Pwrite, Clone, Default)]
pub struct MigtdMigrationInformation {
    // ID for the migration request, which can be used in TDG.VP.VMCALL
    // <Service.MigTD.ReportStatus>
    pub mig_request_id: u64,

    // If set, current MigTD is MigTD-s else current MigTD is MigTD-d
    pub migration_source: u8,
    _pad: [u8; 7],

    // UUID of target TD
    pub target_td_uuid: [u64; 4],

    // Binding handle for the MigTD and the target TD
    pub binding_handle: u64,

    #[cfg(not(feature = "vmcall-raw"))]
    // ID for the migration policy
    pub mig_policy_id: u64,

    #[cfg(not(feature = "vmcall-raw"))]
    // Unique identifier for the communication between MigTD and VMM
    // It can be retrieved from MIGTD_STREAM_SOCKET_INFO HOB
    pub communication_id: u64,
}

#[repr(C)]
#[derive(Debug, Pread, Pwrite)]
#[cfg(feature = "vmcall-raw")]
pub struct ReportInfo {
    // ID for the migration request, which can be used in TDG.VP.VMCALL
    // <Service.MigTD.ReportStatus>
    pub mig_request_id: u64,
    pub reportdata: [u8; 64],
}

#[repr(C)]
#[derive(Debug, Pread, Pwrite)]
#[cfg(feature = "vmcall-raw")]
pub struct EnableLogAreaInfo {
    // ID for the migration request, which can be used in TDG.VP.VMCALL
    // <Service.MigTD.ReportStatus>
    pub mig_request_id: u64,
    pub log_max_level: u8,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(Debug, Pread, Pwrite)]
pub struct MigtdStreamSocketInfo {
    // Unique identifier for the communication between MigTD and VMM
    // It can be used in MigtdMigrationInformation Hob
    pub communication_id: u64,

    // The context ID (CID) of MigTD
    pub mig_td_cid: u64,

    // The listening port of the socket server (MigTD or VMM) for the
    // migration secure communication channel.
    pub mig_channel_port: u32,

    // The listening port of the socket server (VMM) for the quote
    // service channel.
    pub quote_service_port: u32,
}

#[repr(C)]
#[derive(Pread, Pwrite)]
pub struct MigtdMigpolicyInfo {
    // Unique identifier of the policy, it can be used by MigtdMigrationInformation
    pub mig_policy_id: u64,

    // The size in bytes of migration policy
    pub mig_policy_size: u32,
}

pub struct MigtdMigpolicy {
    pub header: MigtdMigpolicyInfo,

    // Migration policy data
    pub mig_policy: Vec<u8>,
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq)]
pub enum MigrationResult {
    Success = 0,
    InvalidParameter = 1,
    Unsupported = 2,
    OutOfResource = 3,
    TdxModuleError = 4,
    NetworkError = 5,
    SecureSessionError = 6,
    MutualAttestationError = 7,
    PolicyUnsatisfiedError = 8,
    InvalidPolicyError = 9,
    VmmCanceled = 10,
    VmmInternalError = 11,
    UnsupportedOperationError = 12,
}

#[cfg(any(feature = "virtio-vsock", feature = "vmcall-vsock"))]
impl From<VsockError> for MigrationResult {
    fn from(_: VsockError) -> Self {
        MigrationResult::NetworkError
    }
}

#[cfg(feature = "virtio-serial")]
impl From<VirtioSerialError> for MigrationResult {
    fn from(_: VirtioSerialError) -> Self {
        MigrationResult::NetworkError
    }
}

impl From<RatlsError> for MigrationResult {
    fn from(e: RatlsError) -> Self {
        match e {
            RatlsError::Crypto(_)
            | RatlsError::X509(_)
            | RatlsError::InvalidEventlog
            | RatlsError::InvalidPolicy => MigrationResult::SecureSessionError,
            RatlsError::TdxModule(_) => MigrationResult::TdxModuleError,
            RatlsError::GetQuote | RatlsError::VerifyQuote => {
                MigrationResult::MutualAttestationError
            }
        }
    }
}

impl From<CryptoError> for MigrationResult {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::TlsVerifyPeerCert(desc) => {
                if desc.as_str() == MIG_POLICY_UNSATISFIED_ERROR {
                    MigrationResult::PolicyUnsatisfiedError
                } else if desc.as_str() == INVALID_MIG_POLICY_ERROR {
                    MigrationResult::InvalidPolicyError
                } else if desc.as_str() == MUTUAL_ATTESTATION_ERROR {
                    MigrationResult::MutualAttestationError
                } else {
                    MigrationResult::SecureSessionError
                }
            }
            _ => MigrationResult::SecureSessionError,
        }
    }
}

impl From<io::Error> for MigrationResult {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::InvalidData => {
                let desc = e.to_string();

                if desc.contains(MIG_POLICY_UNSATISFIED_ERROR) {
                    MigrationResult::PolicyUnsatisfiedError
                } else if desc.contains(INVALID_MIG_POLICY_ERROR) {
                    MigrationResult::InvalidPolicyError
                } else if desc.contains(MUTUAL_ATTESTATION_ERROR) {
                    MigrationResult::MutualAttestationError
                } else {
                    MigrationResult::SecureSessionError
                }
            }
            _ => MigrationResult::NetworkError,
        }
    }
}

impl From<TdVmcallError> for MigrationResult {
    fn from(_: TdVmcallError) -> Self {
        MigrationResult::InvalidParameter
    }
}

impl From<TdCallError> for MigrationResult {
    fn from(_: TdCallError) -> Self {
        MigrationResult::TdxModuleError
    }
}

impl From<TimeoutError> for MigrationResult {
    fn from(_: TimeoutError) -> Self {
        MigrationResult::NetworkError
    }
}
