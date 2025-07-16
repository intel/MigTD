// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod data;
pub mod event;
#[cfg(feature = "main")]
pub mod session;

use crate::config::get_policy;
use crate::driver::ticks::TimeoutError;
use crate::event_log::get_event_log;
use crate::ratls::{
    RatlsError, EXTNID_MIGTD_EVENTLOG_INIT, EXTNID_MIGTD_POLICY_INIT, EXTNID_MIGTD_TDREPORT_INIT,
};
use crate::ratls::{
    INVALID_MIG_POLICY_ERROR, MIG_POLICY_UNSATISFIED_ERROR, MUTUAL_ATTESTATION_ERROR,
};
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use crypto::x509::{Certificate, Decode};
use crypto::Error as CryptoError;
use r_efi::efi::Guid;
use rust_std_stub::io;
use scroll::{Pread, Pwrite};
use spin::Mutex;
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
#[derive(Debug, Pread, Pwrite)]
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

    // ID for the migration policy
    pub mig_policy_id: u64,

    // Unique identifier for the communication between MigTD and VMM
    // It can be retrieved from MIGTD_STREAM_SOCKET_INFO HOB
    pub communication_id: u64,
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
            | RatlsError::Config => MigrationResult::SecureSessionError,
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

/// Struct to store the initial migtd configurations for a migrated target TD
#[derive(Debug, Clone)]
pub struct InitMigtdConfig {
    pub td_report: Vec<u8>,
    pub event_log: Vec<u8>,
    pub mig_policy: Vec<u8>,
}

/// Key for identifying a target TD (UUID + binding handle)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InitConfigKey {
    pub target_td_uuid: [u64; 4],
    pub binding_handle: u64,
}

/// Map to store all migrated target TDs' init info
pub type InitMigtdConfigMap = BTreeMap<InitConfigKey, InitMigtdConfig>;

/// Global storage for migrated target TD initial configurations
static INIT_MIGTD_CONFIG_MAP: Mutex<InitMigtdConfigMap> = Mutex::new(BTreeMap::new());

/// Insert or update the initial configuration for a target TD
pub fn put_init_migtd_config(mig_info: &MigtdMigrationInformation, config: InitMigtdConfig) {
    let key = InitConfigKey {
        target_td_uuid: mig_info.target_td_uuid,
        binding_handle: mig_info.binding_handle,
    };
    let mut map = INIT_MIGTD_CONFIG_MAP.lock();
    map.insert(key, config);
}

pub fn contains_init_migtd_config(mig_info: &MigtdMigrationInformation) -> bool {
    let key = InitConfigKey {
        target_td_uuid: mig_info.target_td_uuid,
        binding_handle: mig_info.binding_handle,
    };
    let map = INIT_MIGTD_CONFIG_MAP.lock();
    map.contains_key(&key)
}

/// Remove the initial configuration for a target TD
pub fn remove_init_migtd_config(mig_info: &MigtdMigrationInformation) -> Option<InitMigtdConfig> {
    let key = InitConfigKey {
        target_td_uuid: mig_info.target_td_uuid,
        binding_handle: mig_info.binding_handle,
    };
    let mut map = INIT_MIGTD_CONFIG_MAP.lock();
    map.remove(&key)
}

/// Access the initial migtd configuration for a target TD with a closure
/// This avoids cloning large data by providing temporary access via a closure
pub fn with_init_migtd_config<T, F>(mig_info: &MigtdMigrationInformation, f: F) -> Option<T>
where
    F: FnOnce(&InitMigtdConfig) -> Option<T>,
{
    let key = InitConfigKey {
        target_td_uuid: mig_info.target_td_uuid,
        binding_handle: mig_info.binding_handle,
    };
    let map = INIT_MIGTD_CONFIG_MAP.lock();
    map.get(&key).and_then(f)
}

pub fn parse_and_store_init_migtd_config(
    mig_info: &MigtdMigrationInformation,
    src_cert: &[&[u8]],
) -> Result<(), MigrationResult> {
    let cert = src_cert.get(0).ok_or(MigrationResult::SecureSessionError)?;
    let config = parse_migtd_cert(cert).ok_or(MigrationResult::MutualAttestationError)?;
    put_init_migtd_config(mig_info, config);
    Ok(())
}

#[allow(unused)]
fn parse_migtd_cert(cert: &[u8]) -> Option<InitMigtdConfig> {
    let cert = Certificate::from_der(cert).ok()?;
    let extensions = cert.tbs_certificate().extensions.as_ref()?;

    let mut td_report = None;
    let mut event_log = None;
    let mut mig_policy = None;

    for extn in extensions.get() {
        if extn.extn_id == EXTNID_MIGTD_TDREPORT_INIT {
            td_report = extn.extn_value.map(|v| v.as_bytes().to_vec());
        } else if extn.extn_id == EXTNID_MIGTD_EVENTLOG_INIT {
            event_log = extn.extn_value.map(|v| v.as_bytes().to_vec());
        } else if extn.extn_id == EXTNID_MIGTD_POLICY_INIT {
            mig_policy = extn.extn_value.map(|v| v.as_bytes().to_vec());
        }
    }

    Some(InitMigtdConfig {
        td_report: td_report?,
        event_log: event_log?,
        mig_policy: mig_policy?,
    })
}

/// Store the current MigTD's own configuration in the map
pub fn put_current_migtd_config(
    mig_info: &MigtdMigrationInformation,
) -> Result<(), MigrationResult> {
    // Get the current MigTD's TD report
    let td_report = tdx_tdcall::tdreport::tdcall_report(&[0u8; 64])
        .map_err(|_| MigrationResult::TdxModuleError)?
        .as_bytes()
        .to_vec();

    let event_log = get_event_log()
        .ok_or(MigrationResult::InvalidParameter)?
        .to_vec();
    let mig_policy = get_policy()
        .ok_or(MigrationResult::InvalidParameter)?
        .to_vec();

    let config = InitMigtdConfig {
        td_report,
        event_log,
        mig_policy,
    };

    put_init_migtd_config(mig_info, config);
    Ok(())
}
