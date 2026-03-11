// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg(feature = "spdm_attestation")]

#[cfg(all(feature = "main", feature = "policy_v2", feature = "vmcall-raw"))]
mod spdm_rebind;
mod spdm_req;
mod spdm_rsp;
mod spdm_vdm;
mod vmcall_msg;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use async_trait::async_trait;
use codec::Codec;
use codec::Reader;
use codec::Writer;
use log::error;
use spdmlib::common::SpdmDeviceIo;
use spdmlib::error::*;
use spdmlib::protocol::{SpdmDigestStruct, SPDM_MAX_HASH_SIZE};
use spin::Mutex;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use async_io::AsyncRead;
use async_io::AsyncWrite;
use crypto::hash::digest_sha384;
#[cfg(all(feature = "main", feature = "policy_v2", feature = "vmcall-raw"))]
pub use spdm_rebind::spdm_requester_rebind_old;
#[cfg(all(feature = "main", feature = "policy_v2", feature = "vmcall-raw"))]
pub use spdm_rebind::spdm_responder_rebind_new;
pub use spdm_req::spdm_requester;
pub use spdm_req::spdm_requester_transfer_msk;
pub use spdm_rsp::spdm_responder;
pub use spdm_rsp::spdm_responder_transfer_msk;

pub use spdm_vdm::*;

use crate::migration::MigrationResult;
use crate::migration::MigtdMigrationInformation;
use crate::spdm::vmcall_msg::VMCALL_SPDM_MESSAGE_HEADER_SIZE;

pub(crate) type SpdmDeviceIoArc<T> = Arc<Mutex<MigtdTransport<T>>>;
pub struct MigtdTransport<T: AsyncRead + AsyncWrite + Unpin + Send> {
    pub transport: T,
}

#[async_trait]
impl<T: AsyncRead + AsyncWrite + Unpin + Send> SpdmDeviceIo for MigtdTransport<T> {
    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        let mut sent = 0;
        while sent < buffer.len() {
            match self.transport.write(&buffer[sent..]).await {
                Ok(len) => sent += len,
                Err(_) => return Err(SPDM_STATUS_SEND_FAIL),
            }
        }
        Ok(())
    }

    async fn receive(
        &mut self,
        buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let mut buffer = buffer.lock();
        if buffer.len() < VMCALL_SPDM_MESSAGE_HEADER_SIZE {
            return Err(0_usize);
        }

        let mut recvd = 0;
        while recvd < VMCALL_SPDM_MESSAGE_HEADER_SIZE {
            let n = self
                .transport
                .read(&mut buffer[recvd..])
                .await
                .map_err(|_| 0_usize)?;
            recvd += n;
        }

        let mut reader = Reader::init(&buffer);
        let vmcall_msg_header =
            vmcall_msg::VmCallMessageHeader::read(&mut reader).ok_or(0_usize)?;
        let payload_size = vmcall_msg_header.length as usize;

        if payload_size > buffer.len().saturating_sub(VMCALL_SPDM_MESSAGE_HEADER_SIZE) {
            return Err(0_usize);
        }

        while recvd < payload_size + VMCALL_SPDM_MESSAGE_HEADER_SIZE {
            let n = self
                .transport
                .read(&mut buffer[recvd..])
                .await
                .map_err(|_| 0_usize)?;
            recvd += n;
        }

        Ok(recvd)
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub fn gen_quote_spdm(report_data: &[u8]) -> Result<Vec<u8>, MigrationResult> {
    let hash = digest_sha384(report_data)?;

    // Generate the TD Report that contains the public key hash as nonce
    let mut additional_data = [0u8; 64];
    additional_data[..hash.len()].copy_from_slice(hash.as_ref());
    let td_report = tdx_tdcall::tdreport::tdcall_report(&additional_data)?;

    let res =
        attestation::get_quote(td_report.as_bytes()).map_err(|_| MigrationResult::Unsupported)?;
    Ok(res)
}

/// Verify that the peer's quote contains the expected REPORTDATA.
///
/// The REPORTDATA in the verified report should equal SHA384(expected_report_data),
/// mirroring the binding created by gen_quote_spdm().
///
/// `supplemental_data` is the output of verify_quote() (774 bytes),
/// which contains the REPORTDATA at offset 520..568 (48 bytes).
pub fn verify_peer_report_data(
    supplemental_data: &[u8],
    expected_report_data: &[u8],
) -> Result<(), MigrationResult> {
    const REPORT_DATA_OFFSET: usize = 520;
    const REPORT_DATA_SIZE: usize = 48;

    if supplemental_data.len() < REPORT_DATA_OFFSET + REPORT_DATA_SIZE {
        return Err(MigrationResult::InvalidParameter);
    }

    let hash = digest_sha384(expected_report_data)?;
    let actual = &supplemental_data[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_SIZE];

    if actual != hash.as_slice() {
        return Err(MigrationResult::InvalidParameter);
    }

    Ok(())
}

/// Build report data by concatenating a prefix and the TH1 digest.
///
/// Returns a `Vec<u8>` containing `prefix || th1.data[..th1.data_size]`.
pub fn build_report_data(prefix: &[u8], th1: &SpdmDigestStruct) -> SpdmResult<Vec<u8>> {
    let th1_len = th1.data_size as usize;
    if th1_len > SPDM_MAX_HASH_SIZE {
        error!("th1 length is too large: {}\n", th1_len);
        return Err(SPDM_STATUS_BUFFER_FULL);
    }
    let mut report_data = vec![0u8; prefix.len() + th1_len];
    report_data[..prefix.len()].copy_from_slice(prefix);
    report_data[prefix.len()..].copy_from_slice(&th1.data[..th1_len]);
    Ok(report_data)
}

/// Verify a quote, returning the supplemental data on success.
///
/// When the `test_disable_ra_and_accept_all` feature is enabled, verification
/// is bypassed and an empty `Vec` is returned.
pub fn spdm_verify_quote(#[allow(unused_variables)] quote: &[u8]) -> SpdmResult<Vec<u8>> {
    #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
    let res = attestation::verify_quote(quote);
    #[cfg(feature = "test_disable_ra_and_accept_all")]
    let res: Result<Vec<u8>, ()> = Ok(vec![]);

    res.map_err(|_| {
        error!("Quote verification failed!\n");
        SPDM_STATUS_INVALID_MSG_FIELD
    })
}

/// Verify that the peer's REPORTDATA is bound to the expected prefix and TH1.
pub fn verify_report_data_binding(
    supplemental_data: &[u8],
    peer_prefix: &[u8],
    th1: &SpdmDigestStruct,
) -> Result<(), MigrationResult> {
    let report_data =
        build_report_data(peer_prefix, th1).map_err(|_| MigrationResult::InvalidParameter)?;
    verify_peer_report_data(supplemental_data, &report_data)
}

const ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH: usize = 0xb9;

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq)]
pub struct PrivateKeyDer {
    pub data_size: u16,
    pub data: Box<[u8; ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH]>,
}

impl Default for PrivateKeyDer {
    fn default() -> Self {
        Self {
            data_size: 0,
            data: Box::new([0u8; ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH]),
        }
    }
}
impl From<&[u8]> for PrivateKeyDer {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() <= ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH);
        let data_size = value.len() as u16;
        let mut data = Box::new([0u8; ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH]);
        data[0..value.len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

impl Codec for PrivateKeyDer {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0usize;
        size += self.data_size.encode(bytes)?;
        for d in self.data.iter().take(self.data_size as usize) {
            size += d.encode(bytes)?;
        }
        Ok(size)
    }

    fn read(r: &mut Reader) -> Option<PrivateKeyDer> {
        let data_size = u16::read(r)?;
        if data_size > ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH as u16 {
            return None;
        }
        let mut data = Box::new([0u8; ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH]);
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(PrivateKeyDer { data_size, data })
    }
}

#[derive(Debug)]
struct SpdmAppContextData {
    pub migration_info: MigtdMigrationInformation,
    pub private_key: PrivateKeyDer,
}

impl Codec for SpdmAppContextData {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        size += self.migration_info.mig_request_id.encode(bytes)?;
        size += self.migration_info.migration_source.encode(bytes)?;
        size += self.migration_info.target_td_uuid.encode(bytes)?;
        size += self.migration_info.binding_handle.encode(bytes)?;

        #[cfg(not(feature = "vmcall-raw"))]
        {
            size += self.migration_info.mig_policy_id.encode(bytes)?;
            size += self.migration_info.communication_id.encode(bytes)?
        }

        size += self.private_key.encode(bytes)?;

        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let mut migration_info = MigtdMigrationInformation::default();
        migration_info.mig_request_id = u64::read(reader)?;
        migration_info.migration_source = u8::read(reader)?;
        migration_info.target_td_uuid = <[u64; 4]>::read(reader)?;
        migration_info.binding_handle = u64::read(reader)?;

        #[cfg(not(feature = "vmcall-raw"))]
        {
            migration_info.mig_policy_id = u64::read(reader)?;
            migration_info.communication_id = u64::read(reader)?;
        }

        let private_key = PrivateKeyDer::read(reader)?;

        Some(Self {
            migration_info,
            private_key,
        })
    }
}

impl From<SpdmStatus> for MigrationResult {
    fn from(spdm_status: SpdmStatus) -> Self {
        if spdm_status.severity == StatusSeverity::SUCCESS {
            MigrationResult::Success
        } else if let StatusCode::VDM(vdm_error) = &spdm_status.status_code {
            MigrationResult::try_from(vdm_error.vdm_error_code as u8)
                .unwrap_or(MigrationResult::SecureSessionError)
        } else {
            MigrationResult::SecureSessionError
        }
    }
}

impl From<MigrationResult> for SpdmStatus {
    fn from(mig_result: MigrationResult) -> Self {
        if mig_result == MigrationResult::Success {
            SpdmStatus {
                severity: StatusSeverity::SUCCESS,
                status_code: StatusCode::SUCCESS,
                error_data: None,
            }
        } else {
            SpdmStatus {
                severity: StatusSeverity::ERROR,
                status_code: StatusCode::VDM(StatusCodeVdmError {
                    vdm_error_code: mig_result as u16,
                }),
                error_data: None,
            }
        }
    }
}
