// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::boxed::Box;
use alloc::sync::Arc;
use codec::{Codec, EncodeErr, Reader, Writer};
use core::ops::DerefMut;
use spdmlib::{
    common::SpdmTransportEncap,
    error::SpdmResult,
    error::{SPDM_STATUS_DECAP_FAIL, SPDM_STATUS_ENCAP_FAIL},
};
use spin::Mutex;

pub const VMCALL_SPDM_SIGNATURE: u32 = 0x4D445053; // 'SPDM'
pub const VMCALL_SPDM_VERSION: u16 = 0x0100; // Version 1.0
pub const VMCALL_SPDM_MESSAGE_TYPE_SPDM_MESSAGE: u8 = 0x1; // 1 – DSP0274 SPDM message
pub const VMCALL_SPDM_MESSAGE_TYPE_SECURED_SPDM_MESSAGE: u8 = 0x2; // 2 – DSP0277 Secured SPDM message

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmCallMessageType {
    SpdmMessage,
    SecuredSpdmMessage,
}

impl Default for VmCallMessageType {
    fn default() -> Self {
        Self::SpdmMessage
    }
}

impl From<&VmCallMessageType> for u8 {
    fn from(value: &VmCallMessageType) -> Self {
        match value {
            VmCallMessageType::SpdmMessage => VMCALL_SPDM_MESSAGE_TYPE_SPDM_MESSAGE,
            VmCallMessageType::SecuredSpdmMessage => VMCALL_SPDM_MESSAGE_TYPE_SECURED_SPDM_MESSAGE,
        }
    }
}

impl TryFrom<u8> for VmCallMessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            VMCALL_SPDM_MESSAGE_TYPE_SPDM_MESSAGE => Ok(VmCallMessageType::SpdmMessage),
            VMCALL_SPDM_MESSAGE_TYPE_SECURED_SPDM_MESSAGE => {
                Ok(VmCallMessageType::SecuredSpdmMessage)
            }
            _ => Err(()),
        }
    }
}

impl Codec for VmCallMessageType {
    fn encode(&self, bytes: &mut codec::Writer<'_>) -> Result<usize, EncodeErr> {
        u8::from(self).encode(bytes)
    }

    fn read(r: &mut codec::Reader<'_>) -> Option<Self> {
        let spdm_version = u8::read(r)?;
        Self::try_from(spdm_version).ok()
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct VmCallMessageHeader {
    pub version: u16,
    pub msg_type: VmCallMessageType,
    pub length: u32,
}

impl Codec for VmCallMessageHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        let signature = VMCALL_SPDM_SIGNATURE; // 'SPDM' as uint32 (little-endian)
        cnt += signature.encode(bytes)?;
        cnt += self.version.encode(bytes)?;
        cnt += self.msg_type.encode(bytes)?;
        cnt += 0u8.encode(bytes)?; // reserved byte
        cnt += self.length.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let signature = u32::read(r)?;
        if signature != VMCALL_SPDM_SIGNATURE {
            // Verify 'SPDM' signature
            return None;
        }
        let version = u16::read(r)?;
        if version != VMCALL_SPDM_VERSION {
            return None;
        }
        let msg_type = VmCallMessageType::read(r)?;
        let _ = u8::read(r)?; // reserved byte
        let length = u32::read(r)?;

        Some(Self {
            version,
            msg_type,
            length,
        })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct VmCallTransportEncap {}

#[maybe_async::maybe_async]
impl SpdmTransportEncap for VmCallTransportEncap {
    async fn encap(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        transport_buffer: Arc<Mutex<&mut [u8]>>,
        secured_message: bool,
    ) -> SpdmResult<usize> {
        let mut transport_buffer = transport_buffer.lock();
        let transport_buffer: &mut &'life2 mut [u8] = transport_buffer.deref_mut();
        let mut writer = Writer::init(transport_buffer);
        let msg_type = if secured_message {
            VmCallMessageType::SecuredSpdmMessage
        } else {
            VmCallMessageType::SpdmMessage
        };

        let vmcall_msg_header = VmCallMessageHeader {
            version: VMCALL_SPDM_VERSION,
            msg_type,
            length: spdm_buffer.len() as u32,
        };
        vmcall_msg_header
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_ENCAP_FAIL)?;
        let header_size = writer.used();

        // Prevent integer overflow and check destination fits
        let payload_len = spdm_buffer.len();
        if let Some(total) = header_size.checked_add(payload_len) {
            if transport_buffer.len() < total {
                return Err(SPDM_STATUS_ENCAP_FAIL);
            }
            transport_buffer[header_size..total].copy_from_slice(&spdm_buffer);
            Ok(total)
        } else {
            return Err(SPDM_STATUS_ENCAP_FAIL);
        }
    }

    async fn decap(
        &mut self,
        transport_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(&transport_buffer);
        let vmcall_msg_header =
            VmCallMessageHeader::read(&mut reader).ok_or(SPDM_STATUS_DECAP_FAIL)?;
        let header_size = reader.used();
        let payload_size = vmcall_msg_header.length as usize;
        // Check for overflow when adding header and payload sizes
        let total = match header_size.checked_add(payload_size) {
            Some(t) => t,
            None => return Err(SPDM_STATUS_DECAP_FAIL),
        };
        if transport_buffer.len() < total {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        let mut spdm_buffer = spdm_buffer.lock();
        let spdm_buffer = spdm_buffer.deref_mut();
        if spdm_buffer.len() < payload_size {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        let payload = &transport_buffer[header_size..total];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        let secured_message = vmcall_msg_header.msg_type == VmCallMessageType::SecuredSpdmMessage;

        Ok((payload_size, secured_message))
    }

    async fn encap_app(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        app_buffer: Arc<Mutex<&mut [u8]>>,
        _is_app_message: bool,
    ) -> SpdmResult<usize> {
        let mut app_buffer = app_buffer.lock();
        app_buffer[0..spdm_buffer.len()].copy_from_slice(&spdm_buffer);
        Ok(spdm_buffer.len())
    }

    async fn decap_app(
        &mut self,
        app_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let mut spdm_buffer = spdm_buffer.lock();
        spdm_buffer[0..app_buffer.len()].copy_from_slice(&app_buffer);
        Ok((app_buffer.len(), false))
    }

    // Sequence Number Length: 8 Bytes
    fn get_sequence_number_count(&mut self) -> u8 {
        8
    }
    fn get_max_random_count(&mut self) -> u16 {
        0
    }
}
