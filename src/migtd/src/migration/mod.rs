// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod data;
pub mod event;
pub mod logging;
#[cfg(feature = "policy_v2")]
pub mod pre_session_data;
#[cfg(all(feature = "main", feature = "policy_v2", feature = "vmcall-raw"))]
pub mod rebinding;
pub mod servtd_ext;
#[cfg(feature = "main")]
pub mod session;
#[cfg(feature = "main")]
pub mod transport;

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

/// Implement `read_from_bytes(data_length, payload)` for a struct whose layout
/// starts with `mig_request_id: u64` followed by optional data bytes.
/// Accepts either the full struct or just the `mig_request_id` (with the
/// optional field set to its default).
///
/// Usage: `impl_read_from_bytes_with_optional!(Type, field_name, default_value)`
///
/// Example:
///   `impl_read_from_bytes_with_optional!(ReportInfo, reportdata, [0u8; 64])`
#[cfg(feature = "vmcall-raw")]
macro_rules! impl_read_from_bytes_with_optional {
    ($t:ty, $field:ident, $default:expr) => {
        #[cfg(feature = "vmcall-raw")]
        impl $t {
            pub fn read_from_bytes(
                data_length: u32,
                payload: &[u8],
            ) -> core::result::Result<Self, MigrationResult> {
                let request_id_only = core::mem::size_of::<u64>() as u32;
                let full_size = core::mem::size_of::<Self>() as u32;
                if data_length != request_id_only && data_length != full_size {
                    return Err(MigrationResult::InvalidParameter);
                }
                if data_length == full_size {
                    payload
                        .pread(0)
                        .map_err(|_| MigrationResult::InvalidParameter)
                } else {
                    let mig_request_id: u64 = payload
                        .pread(0)
                        .map_err(|_| MigrationResult::InvalidParameter)?;
                    Ok(Self {
                        mig_request_id,
                        $field: $default,
                    })
                }
            }
        }
    };
}

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

/// Size in bytes of the TDX-module `TdInfo` struct (TDINFO_STRUCT per the
/// TDX module ABI and GHCI 1.5 MIGTD_DATA `initMigtdData`).
pub const TD_INFO_SIZE: usize = core::mem::size_of::<tdx_tdcall::tdreport::TdInfo>();

/// Offset of the `mrowner` field inside a TDINFO_STRUCT.
/// Layout: attributes(8) + xfam(8) + mrtd(48) + mrconfig_id(48).
pub const TD_INFO_MROWNER_OFFSET: usize = 8 + 8 + 48 + 48;
/// Offset of the `mrownerconfig` field inside a TDINFO_STRUCT.
pub const TD_INFO_MROWNERCONFIG_OFFSET: usize = TD_INFO_MROWNER_OFFSET + 48;
/// Size of `mrowner` / `mrownerconfig` (SHA-384 digest size).
pub const TD_INFO_OWNER_FIELD_SIZE: usize = 48;

// Compile-time guard: catch any drift in the upstream TdInfo layout.
const _: () = {
    assert!(TD_INFO_SIZE == 512);
    assert!(TD_INFO_MROWNER_OFFSET == 112);
    assert!(TD_INFO_MROWNERCONFIG_OFFSET == 160);
};

/// Read `mrowner` from a raw TDINFO_STRUCT byte buffer.
pub fn td_info_mrowner(td_info: &[u8; TD_INFO_SIZE]) -> &[u8; TD_INFO_OWNER_FIELD_SIZE] {
    // Slice into a fixed-size array reference; bounds are guaranteed by the
    // compile-time assertions above.
    (&td_info[TD_INFO_MROWNER_OFFSET..TD_INFO_MROWNER_OFFSET + TD_INFO_OWNER_FIELD_SIZE])
        .try_into()
        .expect("static slice bounds")
}

/// Read `mrownerconfig` from a raw TDINFO_STRUCT byte buffer.
pub fn td_info_mrownerconfig(td_info: &[u8; TD_INFO_SIZE]) -> &[u8; TD_INFO_OWNER_FIELD_SIZE] {
    (&td_info
        [TD_INFO_MROWNERCONFIG_OFFSET..TD_INFO_MROWNERCONFIG_OFFSET + TD_INFO_OWNER_FIELD_SIZE])
        .try_into()
        .expect("static slice bounds")
}

/// Fetch the local MigTD's TDINFO_STRUCT bytes via `tdcall_report`.
/// Used as a fallback when no VMM-provided `init_td_info` is available.
#[cfg(all(feature = "main", feature = "policy_v2"))]
pub fn local_init_td_info() -> Result<[u8; TD_INFO_SIZE], MigrationResult> {
    let report = tdx_tdcall::tdreport::tdcall_report(&[0u8; 64])
        .map_err(|_| MigrationResult::TdxModuleError)?;
    let mut buf = [0u8; TD_INFO_SIZE];
    buf.copy_from_slice(report.td_info.as_bytes());
    Ok(buf)
}

/// Size of the fixed `MigtdMigrationInformation` header preceding the
/// optional `init_td_info` tail (per GHCI 1.5 StartMigration layout).
#[cfg(feature = "policy_v2")]
pub(crate) const MIGTD_MIGRATION_INFO_HEADER_SIZE: usize =
    core::mem::size_of::<MigtdMigrationInformation>() - TD_INFO_SIZE;

#[repr(C)]
#[derive(Debug, Pread, Pwrite, Clone)]
#[cfg_attr(not(feature = "policy_v2"), derive(Default))]
pub struct MigtdMigrationInformation {
    // ID for the migration request, which can be used in TDG.VP.VMCALL
    // <Service.MigTD.ReportStatus>
    pub mig_request_id: u64,

    // If set, current MigTD is MigTD-s else current MigTD is MigTD-d
    pub migration_source: u8,

    // Per GHCI 1.5: hasInitMigtdData — true if initMigtdData follows at offset 56
    pub has_init_data: u8,

    _reserved: [u8; 6],

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

    // Per GHCI 1.5: optional 512-byte TDINFO_STRUCT of the initial MigTD.
    // Present when `has_init_data == 1`. Use `init_td_info_if_present()` for
    // safe access. Sent by the VMM as the raw `TdInfo` bytes (no envelope).
    //
    // NOTE: literal `512` (== TD_INFO_SIZE) is required here because
    // scroll-derive 0.10.5 only accepts integer literals as array length.
    // A const-time assertion above guards against drift.
    #[cfg(feature = "policy_v2")]
    pub init_td_info: [u8; 512],
}

#[cfg(feature = "policy_v2")]
impl Default for MigtdMigrationInformation {
    fn default() -> Self {
        Self {
            mig_request_id: 0,
            migration_source: 0,
            has_init_data: 0,
            _reserved: [0; 6],
            target_td_uuid: [0; 4],
            binding_handle: 0,
            #[cfg(not(feature = "vmcall-raw"))]
            mig_policy_id: 0,
            #[cfg(not(feature = "vmcall-raw"))]
            communication_id: 0,
            init_td_info: [0u8; TD_INFO_SIZE],
        }
    }
}

#[cfg(feature = "policy_v2")]
impl MigtdMigrationInformation {
    /// Safe accessor for the optional initial TDINFO_STRUCT. Returns `Some`
    /// only when the VMM signaled `has_init_data == 1`.
    pub fn init_td_info_if_present(&self) -> Option<&[u8; TD_INFO_SIZE]> {
        if self.has_init_data == 1 {
            Some(&self.init_td_info)
        } else {
            None
        }
    }
}

#[cfg(feature = "policy_v2")]
impl MigtdMigrationInformation {
    /// Parse a policy_v2 wire payload of either:
    /// - header-only (short form, `has_init_data == 0`), or
    /// - header + 512-byte TDINFO_STRUCT (full form, `has_init_data == 1`).
    /// Header size is transport-dependent (56 for vmcall-raw, 72 otherwise).
    pub fn read_from_bytes(
        data_length: u32,
        payload: &[u8],
    ) -> core::result::Result<Self, MigrationResult> {
        let short_size = MIGTD_MIGRATION_INFO_HEADER_SIZE as u32;
        let full_size = core::mem::size_of::<Self>() as u32;
        if data_length != short_size && data_length != full_size {
            return Err(MigrationResult::InvalidParameter);
        }
        if (payload.len() as u32) < data_length {
            return Err(MigrationResult::InvalidParameter);
        }
        let parsed: Self = if data_length == full_size {
            payload
                .pread(0)
                .map_err(|_| MigrationResult::InvalidParameter)?
        } else {
            // Short form: zero-pad to full_size and pread; tail field's default
            // is `[0u8; TD_INFO_SIZE]` so zero-fill is correct.
            let mut padded = alloc::vec![0u8; full_size as usize];
            padded[..short_size as usize].copy_from_slice(&payload[..short_size as usize]);
            padded
                .as_slice()
                .pread(0)
                .map_err(|_| MigrationResult::InvalidParameter)?
        };

        if parsed._reserved != [0; 6] {
            return Err(MigrationResult::InvalidParameter);
        }
        if parsed.has_init_data > 1 {
            return Err(MigrationResult::InvalidParameter);
        }
        // has_init_data and data_length must be consistent: the full-size
        // payload is required iff has_init_data == 1.
        if (parsed.has_init_data == 1) != (data_length == full_size) {
            return Err(MigrationResult::InvalidParameter);
        }
        Ok(parsed)
    }
}

#[cfg(not(feature = "policy_v2"))]
impl MigtdMigrationInformation {
    pub fn read_from_bytes(
        data_length: u32,
        payload: &[u8],
    ) -> core::result::Result<Self, MigrationResult> {
        let full_size = core::mem::size_of::<Self>() as u32;
        if data_length != full_size {
            return Err(MigrationResult::InvalidParameter);
        }
        let parsed: Self = payload
            .pread(0)
            .map_err(|_| MigrationResult::InvalidParameter)?;
        if parsed._reserved != [0; 6] {
            return Err(MigrationResult::InvalidParameter);
        }
        if parsed.has_init_data != 0 {
            return Err(MigrationResult::InvalidParameter);
        }
        Ok(parsed)
    }
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

#[cfg(feature = "vmcall-raw")]
impl_read_from_bytes_with_optional!(ReportInfo, reportdata, [0u8; 64]);

#[repr(C)]
#[derive(Debug, Pread, Pwrite)]
#[cfg(all(feature = "vmcall-raw", feature = "policy_v2"))]
pub struct MigtdDataInfo {
    // ID for the migration request, which can be used in TDG.VP.VMCALL
    // <Service.MigTD.ReportStatus>
    pub mig_request_id: u64,
    pub reportdata: [u8; 64],
}

#[cfg(all(feature = "vmcall-raw", feature = "policy_v2"))]
impl_read_from_bytes_with_optional!(MigtdDataInfo, reportdata, [0u8; 64]);

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

#[cfg(feature = "vmcall-raw")]
impl EnableLogAreaInfo {
    pub fn read_from_bytes(
        data_length: u32,
        payload: &[u8],
    ) -> core::result::Result<Self, MigrationResult> {
        if data_length != core::mem::size_of::<Self>() as u32 {
            return Err(MigrationResult::InvalidParameter);
        }
        let info: Self = payload
            .pread(0)
            .map_err(|_| MigrationResult::InvalidParameter)?;
        // GHCI 1.5 v6 Table 3-50: reserved bytes MUST be zero.
        if info.reserved.iter().any(|&b| b != 0) {
            return Err(MigrationResult::InvalidParameter);
        }
        Ok(info)
    }
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
#[derive(Copy, Clone, Debug, PartialEq)]
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
    InitializationError = 0xFF,
}

impl TryFrom<u8> for MigrationResult {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MigrationResult::Success),
            1 => Ok(MigrationResult::InvalidParameter),
            2 => Ok(MigrationResult::Unsupported),
            3 => Ok(MigrationResult::OutOfResource),
            4 => Ok(MigrationResult::TdxModuleError),
            5 => Ok(MigrationResult::NetworkError),
            6 => Ok(MigrationResult::SecureSessionError),
            7 => Ok(MigrationResult::MutualAttestationError),
            8 => Ok(MigrationResult::PolicyUnsatisfiedError),
            9 => Ok(MigrationResult::InvalidPolicyError),
            10 => Ok(MigrationResult::VmmCanceled),
            11 => Ok(MigrationResult::VmmInternalError),
            12 => Ok(MigrationResult::UnsupportedOperationError),
            0xFF => Ok(MigrationResult::InitializationError),
            _ => Err(()),
        }
    }
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
            | RatlsError::GenerateCertificate => MigrationResult::SecureSessionError,
            RatlsError::InvalidPolicy => MigrationResult::InvalidPolicyError,
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
            io::ErrorKind::ConnectionAborted => MigrationResult::VmmCanceled,
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

#[cfg(test)]
#[cfg(feature = "policy_v2")]
mod test {
    use super::*;
    use alloc::vec;

    /// Create a 512-byte TDINFO_STRUCT with known mrowner and mrownerconfig.
    fn make_tdinfo(mrowner: &[u8; 48], mrownerconfig: &[u8; 48]) -> [u8; TD_INFO_SIZE] {
        let mut tdinfo = [0u8; TD_INFO_SIZE];
        // mrowner at offset 112..160
        tdinfo[112..160].copy_from_slice(mrowner);
        // mrownerconfig at offset 160..208
        tdinfo[160..208].copy_from_slice(mrownerconfig);
        tdinfo
    }

    /// Build a MigtdMigrationInformation byte buffer matching the active
    /// feature layout. Under non-vmcall-raw, `mig_policy_id` and
    /// `communication_id` (zero-initialized) are inserted after
    /// `binding_handle`. When `init_tdinfo` is `Some`, the raw TDINFO bytes
    /// are appended directly (no envelope, per the unified wire contract).
    fn build_mig_info(
        mig_request_id: u64,
        migration_source: u8,
        has_init_data: u8,
        uuid: [u64; 4],
        binding_handle: u64,
        init_tdinfo: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&mig_request_id.to_le_bytes()); // 0..8
        buf.push(migration_source); // 8
        buf.push(has_init_data); // 9
        buf.extend_from_slice(&[0u8; 6]); // 10..16 reserved
        for u in &uuid {
            buf.extend_from_slice(&u.to_le_bytes()); // 16..48
        }
        buf.extend_from_slice(&binding_handle.to_le_bytes()); // 48..56
        #[cfg(not(feature = "vmcall-raw"))]
        {
            buf.extend_from_slice(&0u64.to_le_bytes()); // mig_policy_id 56..64
            buf.extend_from_slice(&0u64.to_le_bytes()); // communication_id 64..72
        }
        if let Some(data) = init_tdinfo {
            buf.extend_from_slice(data);
        }
        buf
    }

    #[test]
    fn test_mig_info_no_init_data() {
        let buf = build_mig_info(42, 1, 0, [1, 2, 3, 4], 99, None);
        let info = MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf)
            .expect("should parse");
        assert_eq!(info.mig_request_id, 42);
        assert_eq!(info.migration_source, 1);
        assert_eq!(info.has_init_data, 0);
        assert_eq!(info.target_td_uuid, [1, 2, 3, 4]);
        assert_eq!(info.binding_handle, 99);
        assert!(info.init_td_info_if_present().is_none());
        // Padded tail is zero.
        assert_eq!(info.init_td_info, [0u8; TD_INFO_SIZE]);
    }

    #[test]
    fn test_mig_info_with_init_data() {
        let tdinfo = make_tdinfo(&[0xCAu8; 48], &[0xFEu8; 48]);
        let buf = build_mig_info(7, 0, 1, [10, 20, 30, 40], 55, Some(&tdinfo));
        let info = MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf)
            .expect("should parse with init data");
        assert_eq!(info.mig_request_id, 7);
        assert_eq!(info.has_init_data, 1);
        let init = info.init_td_info_if_present().expect("should be present");
        assert_eq!(init, &tdinfo);
        assert_eq!(td_info_mrowner(init), &[0xCAu8; 48]);
        assert_eq!(td_info_mrownerconfig(init), &[0xFEu8; 48]);
    }

    #[test]
    fn test_mig_info_rejects_short_buffer() {
        // Anything shorter than the layout's short-form header must be rejected.
        let too_short = MIGTD_MIGRATION_INFO_HEADER_SIZE - 1;
        assert!(MigtdMigrationInformation::read_from_bytes(10, &[0u8; 10]).is_err());
        assert!(MigtdMigrationInformation::read_from_bytes(
            too_short as u32,
            &vec![0u8; too_short]
        )
        .is_err());
    }

    #[test]
    fn test_mig_info_rejects_nonzero_reserved() {
        let mut buf = build_mig_info(1, 0, 0, [0; 4], 0, None);
        buf[10] = 0xFF; // reserved byte not zero
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
    }

    #[test]
    fn test_mig_info_rejects_has_init_data_without_tail() {
        // has_init_data=1 but no tail bytes following → flag/length mismatch
        let buf = build_mig_info(1, 0, 1, [0; 4], 0, None);
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
    }

    #[test]
    fn test_mig_info_rejects_full_form_without_flag() {
        // has_init_data=0 but full-size buffer (with init_td_info tail) → flag/length mismatch
        let tdinfo = [0u8; TD_INFO_SIZE];
        let buf = build_mig_info(1, 0, 0, [0; 4], 0, Some(&tdinfo));
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
    }

    #[test]
    fn test_mig_info_rejects_invalid_has_init_data() {
        // has_init_data must be 0 or 1
        let mut buf = build_mig_info(1, 0, 0, [0; 4], 0, None);
        buf[9] = 2;
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
        buf[9] = 0xFF;
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
    }

    #[test]
    fn test_mig_info_rejects_unexpected_length() {
        // Only short or full lengths are accepted; mid-sized buffers are rejected.
        let mid = MIGTD_MIGRATION_INFO_HEADER_SIZE + 1;
        let mid_buf = vec![0u8; mid];
        assert!(
            MigtdMigrationInformation::read_from_bytes(mid_buf.len() as u32, &mid_buf).is_err()
        );
    }
}
