// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg(feature = "spdm_attestation")]

mod spdm_mig;
#[cfg(feature = "policy_v2")]
mod spdm_rebind;
mod spdm_req;
mod spdm_rsp;
mod spdm_vdm;
mod vmcall_msg;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use codec::Codec;
use codec::Reader;
use codec::Writer;
use spdmlib::common::SpdmDeviceIo;
use spdmlib::error::*;
use spin::Mutex;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use async_io::AsyncRead;
use async_io::AsyncWrite;
use crypto::hash::digest_sha384;
pub use spdm_mig::spdm_requester_transfer_msk;
pub use spdm_mig::spdm_responder_transfer_msk;
#[cfg(feature = "policy_v2")]
pub use spdm_rebind::spdm_requester_rebind_old;
#[cfg(feature = "policy_v2")]
pub use spdm_rebind::spdm_responder_rebind_new;
pub use spdm_req::spdm_requester;
pub use spdm_rsp::spdm_responder;

pub use spdm_vdm::*;

use crate::migration::MigrationResult;
use crate::spdm::vmcall_msg::VMCALL_SPDM_MESSAGE_HEADER_SIZE;

pub struct MigtdTransport<T: AsyncRead + AsyncWrite + Unpin> {
    pub transport: T,
}
unsafe impl<T: AsyncRead + AsyncWrite + Unpin> Send for MigtdTransport<T> {}

#[async_trait]
impl<T: AsyncRead + AsyncWrite + Unpin> SpdmDeviceIo for MigtdTransport<T> {
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
    pub private_key: PrivateKeyDer,
}

impl Codec for SpdmAppContextData {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;

        size += self.private_key.encode(bytes)?;

        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let private_key = PrivateKeyDer::read(reader)?;

        Some(Self { private_key })
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
