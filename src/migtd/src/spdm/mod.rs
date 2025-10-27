// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg(feature = "spdm_attestation")]

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
use core::time::Duration;
use spdmlib::common::SpdmDeviceIo;
use spdmlib::error::SpdmResult;
use spdmlib::error::SPDM_STATUS_SEND_FAIL;
use spin::Mutex;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use async_io::AsyncRead;
use async_io::AsyncWrite;
use crypto::hash::digest_sha384;
pub use spdm_req::spdm_requester;
pub use spdm_req::spdm_requester_transfer_msk;
pub use spdm_rsp::spdm_responder;
pub use spdm_rsp::spdm_responder_transfer_msk;

pub use spdm_vdm::*;

use crate::migration::MigrationResult;
use crate::migration::MigtdMigrationInformation;

const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds

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
        let mut received = 0;
        while received == 0 {
            match self.transport.read(&mut buffer).await {
                Ok(len) => received += len,
                Err(_) => return Err(0),
            }
        }
        Ok(received)
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

    let res = attestation::get_quote(td_report.as_bytes()).unwrap();
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
    pub migration_info: MigtdMigrationInformation,
    pub private_key: PrivateKeyDer,
    #[cfg(feature = "policy_v2")]
    pub remote_policy_ptr: u64,
    #[cfg(feature = "policy_v2")]
    pub remote_policy_len: u32,
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

        #[cfg(feature = "policy_v2")]
        {
            size += self.remote_policy_ptr.encode(bytes)?;
            size += self.remote_policy_len.encode(bytes)?;
        }

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

        #[cfg(feature = "policy_v2")]
        let remote_policy_ptr = u64::read(reader)?;
        #[cfg(feature = "policy_v2")]
        let remote_policy_len = u32::read(reader)?;

        Some(Self {
            migration_info,
            private_key,
            #[cfg(feature = "policy_v2")]
            remote_policy_ptr,
            #[cfg(feature = "policy_v2")]
            remote_policy_len,
        })
    }
}
