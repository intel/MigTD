// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use codec::{enum_builder, Codec, Reader, Writer};
use crypto::hash::digest_sha384;
use spdmlib::common;
use spdmlib::{
    common::{ManagedVdmBuffer, SpdmCodec},
    error::*,
    message::*,
    protocol::{SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmVersion},
    responder::ResponderContext,
};

use crate::spdm::spdm_rsp::*;

// Intel(343)
pub const VDM_MESSAGE_VENDOR_ID: [u8; 4] = [0x57, 0x1, 0x0, 0x0];
pub const VDM_MESSAGE_VENDOR_ID_LEN: usize = 4;

pub const VDM_MESSAGE_MAJOR_VERSION: u8 = 0;
pub const VDM_MESSAGE_MINOR_VERSION: u8 = 0;

pub const VDM_MESSAGE_EXCHANGE_PUB_KEY_REQ_ELEMENT_COUNT: u8 = 1;
pub const VDM_MESSAGE_EXCHANGE_PUB_KEY_RSP_ELEMENT_COUNT: u8 = 1;
pub const VDM_MESSAGE_EXCHANGE_MIGRATION_ATTEST_INFO_REQ_ELEMENT_COUNT: u8 = 3;
//pub const VDM_MESSAGE_EXCHANGE_MIGRATION_ATTEST_INFO_REQ_WITH_HISTORY_INFO_ELEMENT_COUNT: u8 = 7; Migration with History Info is not supported yet.
pub const VDM_MESSAGE_EXCHANGE_MIGRATION_ATTEST_INFO_RSP_ELEMENT_COUNT: u8 = 3;
pub const VDM_MESSAGE_EXCHANGE_MIGRATION_INFO_REQ_ELEMENT_COUNT: u8 = 2;
pub const VDM_MESSAGE_EXCHANGE_MIGRATION_INFO_RSP_ELEMENT_COUNT: u8 = 2;
pub const VDM_MESSAGE_EXCHANGE_REBIND_ATTEST_INFO_REQ_WITH_HISTORY_INFO_ELEMENT_COUNT: u8 = 7;
pub const VDM_MESSAGE_EXCHANGE_REBIND_ATTEST_INFO_RSP_ELEMENT_COUNT: u8 = 3;
pub const VDM_MESSAGE_EXCHANGE_REBIND_INFO_ELEMENT_REQ_COUNT: u8 = 1;
pub const VDM_MESSAGE_EXCHANGE_REBIND_INFO_ELEMENT_RSP_COUNT: u8 = 0;

pub const VDM_MESSAGE_MIGRATION_EXPORT_VERSION_SIZE: u32 = 4;
pub const VDM_MESSAGE_FORWARD_MIGRATION_SESSION_KEY_SIZE: u32 = 32;
pub const VDM_MESSAGE_MIGRATION_IMPORT_VERSION_SIZE: u32 = 4;
pub const VDM_MESSAGE_BACKWARD_MIGRATION_SESSION_KEY_SIZE: u32 = 32;
pub const VDM_MESSAGE_REBIND_SESSION_TOKEN_SIZE: u32 = 32;

enum_builder! {
    @U8
    EnumName: VdmMessageOpCode;
    EnumVal{
        OpCodeUnknown => 0x00,
        ExchangePubKeyReq => 0x01,
        ExchangePubKeyRsp => 0x02,
        ExchangeMigrationAttestInfoReq => 0x03,
        ExchangeMigrationAttestInfoRsp => 0x04,
        ExchangeMigrationInfoReq => 0x05,
        ExchangeMigrationInfoRsp => 0x06,
        ExchangeRebindAttestInfoReq => 0x07,
        ExchangeRebindAttestInfoRsp => 0x08,
        ExchangeRebindInfoReq => 0x09,
        ExchangeRebindInfoRsp => 0x0A
    }
}

#[allow(clippy::derivable_impls)]
impl Default for VdmMessageOpCode {
    fn default() -> VdmMessageOpCode {
        VdmMessageOpCode::OpCodeUnknown
    }
}

#[derive(Debug)]
pub struct VdmMessage {
    pub major_version: u8,
    pub minor_version: u8,
    pub op_code: VdmMessageOpCode,
    pub element_count: u8,
}

impl Codec for VdmMessage {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.major_version.encode(bytes)?;
        cnt += self.minor_version.encode(bytes)?;
        cnt += self.op_code.encode(bytes)?;
        cnt += self.element_count.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader<'_>) -> Option<Self> {
        let major_version = u8::read(r)?;
        let minor_version = u8::read(r)?;
        let op_code = VdmMessageOpCode::read(r)?;
        let element_count = u8::read(r)?;
        Some(VdmMessage {
            major_version,
            minor_version,
            op_code,
            element_count,
        })
    }
}

enum_builder! {
    @U16
    EnumName: VdmMessageElementType;
    EnumVal{
        ElementUnknown => 0x00,
        PubKeyMy => 0x01,
        TdReportMy => 0x02,
        QuoteMy => 0x03,
        EventLogMy => 0x04,
        MigPolicyMy => 0x05,
        SerVtdExt => 0x10,
        TdReportInit => 0x12,
        EventLogInit => 0x14,
        MigPolicyInit => 0x15,
        MigrationExportVersion => 0x81,
        MigrationImportVersion => 0x82,
        ForwardMigrationSessionKey => 0x83,
        BackwardMigrationSessionKey => 0x84,
        RebindSessionToken => 0x85
    }
}

#[allow(clippy::derivable_impls)]
impl Default for VdmMessageElementType {
    fn default() -> VdmMessageElementType {
        VdmMessageElementType::ElementUnknown
    }
}

#[derive(Debug)]
pub struct VdmMessageElement {
    pub element_type: VdmMessageElementType,
    pub length: u32,
}

impl Codec for VdmMessageElement {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.element_type.encode(bytes)?;
        cnt += self.length.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader<'_>) -> Option<Self> {
        let element_type = VdmMessageElementType::read(r)?;
        let length = u32::read(r)?;
        Some(VdmMessageElement {
            element_type,
            length,
        })
    }
}

// Define the VDM request and response payloads rather than reuse Spdm lib structures to avoid using large slices in stack.
#[derive(Debug, Clone)]
pub struct SpdmVdmRequestPayload {
    pub standard_id: RegistryOrStandardsBodyID,
    pub vendor_id: VendorIDStruct,
    pub req_length: u32,
    pub req_payload: Vec<u8>,
}

impl SpdmCodec for SpdmVdmRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let large_payload = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
            && context
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP);
        let mut cnt = 0usize;
        let param1 = if large_payload {
            SpdmVdmFlags::USE_LARGE_PAYLOAD
        } else {
            SpdmVdmFlags::default()
        };
        cnt += param1.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .standard_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; //Standard ID
        cnt += self
            .vendor_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        if large_payload {
            if self.req_length as usize > self.req_payload.len() {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // req_length
            cnt += self
                .req_length
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            for d in self.req_payload.iter().take(self.req_length as usize) {
                cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            }
        } else {
            if self.req_length > u16::MAX as u32
                || self.req_payload.len() < self.req_length as usize
            {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
            cnt += (self.req_length as u16)
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            for d in self.req_payload.iter().take(self.req_length as usize) {
                cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            }
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmVdmRequestPayload> {
        let param1 = SpdmVdmFlags::read(r)?; // param1
        u8::read(r)?; // param2
        let large_payload = param1.contains(SpdmVdmFlags::USE_LARGE_PAYLOAD);
        if large_payload
            && !(context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
                && context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
                && context
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP))
        {
            return None;
        }
        let standard_id = RegistryOrStandardsBodyID::read(r)?; // Standard ID
        let vendor_id = VendorIDStruct::read(r)?;
        let req_length = if large_payload {
            let _ = u16::read(r)?; // rsp_length (reserved)
            u32::read(r)?
        } else {
            let len = u16::read(r)?; // rsp_length
            len as u32
        };
        let mut req_payload = Vec::with_capacity(req_length as usize);
        for _ in 0..req_length {
            let d = u8::read(r)?;
            req_payload.push(d);
        }

        Some(SpdmVdmRequestPayload {
            standard_id,
            vendor_id,
            req_length,
            req_payload,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SpdmVdmResponsePayload {
    pub standard_id: RegistryOrStandardsBodyID,
    pub vendor_id: VendorIDStruct,
    pub rsp_length: u32,
    pub rsp_payload: Vec<u8>,
}

impl SpdmCodec for SpdmVdmResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let large_payload = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
            && context
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP);
        let mut cnt = 0usize;
        let param1 = if large_payload {
            SpdmVdmFlags::USE_LARGE_PAYLOAD
        } else {
            SpdmVdmFlags::default()
        };
        cnt += param1.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .standard_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; //Standard ID
        cnt += self
            .vendor_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        if large_payload {
            if self.rsp_length as usize > self.rsp_payload.len() {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // rsp_length
            cnt += self
                .rsp_length
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            for d in self.rsp_payload.iter().take(self.rsp_length as usize) {
                cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            }
        } else {
            if self.rsp_length > u16::MAX as u32
                || self.rsp_payload.len() < self.rsp_length as usize
            {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
            cnt += (self.rsp_length as u16)
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            for d in self.rsp_payload.iter().take(self.rsp_length as usize) {
                cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            }
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmVdmResponsePayload> {
        let param1 = SpdmVdmFlags::read(r)?; // param1
        u8::read(r)?; // param2
        let large_payload = param1.contains(SpdmVdmFlags::USE_LARGE_PAYLOAD);
        if large_payload
            && !(context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
                && context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
                && context
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP))
        {
            return None;
        }
        let standard_id = RegistryOrStandardsBodyID::read(r)?; // Standard ID
        let vendor_id = VendorIDStruct::read(r)?;
        let rsp_length = if large_payload {
            let _ = u16::read(r)?; // rsp_length (reserved)
            u32::read(r)?
        } else {
            let len = u16::read(r)?; // rsp_length
            len as u32
        };
        let mut rsp_payload = Vec::with_capacity(rsp_length as usize);
        for _ in 0..rsp_length {
            let d = u8::read(r)?;
            rsp_payload.push(d);
        }

        Some(SpdmVdmResponsePayload {
            standard_id,
            vendor_id,
            rsp_length,
            rsp_payload,
        })
    }
}

pub fn migtd_vdm_msg_rsp_dispatcher_ex<'a>(
    responder_context: &mut ResponderContext,
    session_id: Option<u32>,
    req_bytes: &[u8],
    rsp_bytes: &'a mut [u8],
) -> (SpdmResult, Option<&'a [u8]>) {
    let mut writer = Writer::init(rsp_bytes);

    let mut reader = Reader::init(req_bytes);
    let message_header = SpdmMessageHeader::read(&mut reader);
    if let Some(message_header) = message_header {
        if message_header.version != responder_context.common.negotiate_info.spdm_version_sel {
            responder_context.write_spdm_error(
                SpdmErrorCode::SpdmErrorVersionMismatch,
                0,
                &mut writer,
            );
            let used = writer.used();
            return (Err(SPDM_STATUS_INVALID_MSG_FIELD), Some(&rsp_bytes[..used]));
        }
    } else {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, &mut writer);
        let used = writer.used();
        return (Err(SPDM_STATUS_INVALID_MSG_FIELD), Some(&rsp_bytes[..used]));
    }

    let req_payload = SpdmVdmRequestPayload::spdm_read(&mut responder_context.common, &mut reader);
    if req_payload.is_none() {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, &mut writer);
        let used = writer.used();
        return (Err(SPDM_STATUS_INVALID_MSG_FIELD), Some(&rsp_bytes[..used]));
    }

    let req_payload = req_payload.unwrap();
    let standard_id = req_payload.standard_id;
    let vendor_id = req_payload.vendor_id;

    if standard_id != RegistryOrStandardsBodyID::IANA
        || vendor_id.len != VDM_MESSAGE_VENDOR_ID_LEN as u8
        || vendor_id.vendor_id[..VDM_MESSAGE_VENDOR_ID_LEN] != VDM_MESSAGE_VENDOR_ID
    {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, &mut writer);
        let used = writer.used();
        return (Err(SPDM_STATUS_INVALID_MSG_FIELD), Some(&rsp_bytes[..used]));
    }

    let mut reader = Reader::init(&req_payload.req_payload[0..req_payload.req_length as usize]);
    let vdm_request = if let Some(vdm_request) = VdmMessage::read(&mut reader) {
        vdm_request
    } else {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, &mut writer);
        let used = writer.used();
        return (Err(SPDM_STATUS_INVALID_MSG_SIZE), Some(&rsp_bytes[..used]));
    };

    let response_header = SpdmMessageHeader {
        version: responder_context.common.negotiate_info.spdm_version_sel,
        request_response_code: SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse,
    };

    let mut vdm_rsp_payload = SpdmVdmResponsePayload {
        standard_id: RegistryOrStandardsBodyID::IANA,
        vendor_id: VendorIDStruct {
            len: VDM_MESSAGE_VENDOR_ID_LEN as u8,
            vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
        },
        rsp_length: 0,
        rsp_payload: vec![0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    // Patch the vendor id field
    vdm_rsp_payload.vendor_id.vendor_id[..VDM_MESSAGE_VENDOR_ID_LEN]
        .copy_from_slice(&VDM_MESSAGE_VENDOR_ID);

    //Patch the response payload
    let vdm_payload_size = match vdm_request.op_code {
        VdmMessageOpCode::ExchangePubKeyReq => handle_exchange_pub_key_req(
            responder_context,
            &vdm_request,
            &mut reader,
            &mut vdm_rsp_payload.rsp_payload,
        ),
        VdmMessageOpCode::ExchangeMigrationAttestInfoReq => handle_exchange_mig_attest_info_req(
            responder_context,
            session_id,
            &vdm_request,
            &mut reader,
            &mut vdm_rsp_payload.rsp_payload,
        ),
        VdmMessageOpCode::ExchangeMigrationInfoReq => handle_exchange_mig_info_req(
            responder_context,
            session_id,
            &vdm_request,
            &mut reader,
            &mut vdm_rsp_payload.rsp_payload,
        ),
        #[cfg(all(feature = "main", feature = "policy_v2", feature = "vmcall-raw"))]
        VdmMessageOpCode::ExchangeRebindAttestInfoReq => handle_exchange_rebind_attest_info_req(
            responder_context,
            session_id,
            &vdm_request,
            &mut reader,
            &mut vdm_rsp_payload.rsp_payload,
        ),
        #[cfg(all(feature = "main", feature = "policy_v2", feature = "vmcall-raw"))]
        VdmMessageOpCode::ExchangeRebindInfoReq => handle_exchange_rebind_info_req(
            responder_context,
            session_id,
            &vdm_request,
            &mut reader,
            &mut vdm_rsp_payload.rsp_payload,
        ),
        _ => Err(SPDM_STATUS_INVALID_MSG_FIELD),
    };
    if let Ok(vdm_payload_size) = vdm_payload_size {
        vdm_rsp_payload.rsp_length = vdm_payload_size as u32;
    } else {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, &mut writer);
        let used = writer.used();
        return (
            Err(vdm_payload_size.err().unwrap()),
            Some(&rsp_bytes[..used]),
        );
    };

    let res = response_header.encode(&mut writer);
    if res.is_err() {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, &mut writer);
        let used = writer.used();
        return (
            Err(SPDM_STATUS_INVALID_STATE_LOCAL),
            Some(&rsp_bytes[..used]),
        );
    }

    let res = vdm_rsp_payload.spdm_encode(&mut responder_context.common, &mut writer);
    if res.is_err() {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, &mut writer);
        let used = writer.used();
        return (
            Err(SPDM_STATUS_INVALID_STATE_LOCAL),
            Some(&rsp_bytes[..used]),
        );
    }

    let len = writer.used();

    match vdm_request.op_code {
        VdmMessageOpCode::ExchangePubKeyReq => {
            let vdm_pub_key_src_hash = match digest_sha384(req_bytes) {
                Ok(hash) => hash,
                Err(_) => {
                    responder_context.write_spdm_error(
                        SpdmErrorCode::SpdmErrorUnspecified,
                        0,
                        &mut writer,
                    );
                    return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(&rsp_bytes[..len]));
                }
            };
            let vdm_pub_key_dst_hash = match digest_sha384(writer.used_slice()) {
                Ok(hash) => hash,
                Err(_) => {
                    responder_context.write_spdm_error(
                        SpdmErrorCode::SpdmErrorUnspecified,
                        0,
                        &mut writer,
                    );
                    return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(&rsp_bytes[..len]));
                }
            };
            let mut transcript_before_key_exchange = ManagedVdmBuffer::default();
            let res =
                transcript_before_key_exchange.append_message(vdm_pub_key_src_hash.as_slice());
            if res.is_none() {
                responder_context.write_spdm_error(
                    SpdmErrorCode::SpdmErrorUnspecified,
                    0,
                    &mut writer,
                );
                return (Err(SPDM_STATUS_BUFFER_FULL), Some(&rsp_bytes[..len]));
            }
            let res =
                transcript_before_key_exchange.append_message(vdm_pub_key_dst_hash.as_slice());
            if res.is_none() {
                responder_context.write_spdm_error(
                    SpdmErrorCode::SpdmErrorUnspecified,
                    0,
                    &mut writer,
                );
                return (Err(SPDM_STATUS_BUFFER_FULL), Some(&rsp_bytes[..len]));
            }
            responder_context
                .common
                .runtime_info
                .vdm_message_transcript_before_key_exchange = Some(transcript_before_key_exchange);
        }
        VdmMessageOpCode::ExchangeMigrationAttestInfoReq
        | VdmMessageOpCode::ExchangeRebindAttestInfoReq => {
            let vdm_attest_info_src_hash = match digest_sha384(req_bytes) {
                Ok(hash) => hash,
                Err(_) => {
                    responder_context.write_spdm_error(
                        SpdmErrorCode::SpdmErrorUnspecified,
                        0,
                        &mut writer,
                    );
                    return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(&rsp_bytes[..len]));
                }
            };
            let vdm_attest_info_dst_hash = match digest_sha384(writer.used_slice()) {
                Ok(hash) => hash,
                Err(_) => {
                    responder_context.write_spdm_error(
                        SpdmErrorCode::SpdmErrorUnspecified,
                        0,
                        &mut writer,
                    );
                    return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(&rsp_bytes[..len]));
                }
            };
            let mut transcript_before_finish = ManagedVdmBuffer::default();
            let res = transcript_before_finish.append_message(vdm_attest_info_src_hash.as_slice());
            if res.is_none() {
                responder_context.write_spdm_error(
                    SpdmErrorCode::SpdmErrorUnspecified,
                    0,
                    &mut writer,
                );
                return (Err(SPDM_STATUS_BUFFER_FULL), Some(&rsp_bytes[..len]));
            }
            let res = transcript_before_finish.append_message(vdm_attest_info_dst_hash.as_slice());
            if res.is_none() {
                responder_context.write_spdm_error(
                    SpdmErrorCode::SpdmErrorUnspecified,
                    0,
                    &mut writer,
                );
                return (Err(SPDM_STATUS_BUFFER_FULL), Some(&rsp_bytes[..len]));
            }
            let session_id = responder_context.common.runtime_info.get_last_session_id();
            if let Some(sid) = session_id {
                if let Some(s) = responder_context.common.get_session_via_id(sid) {
                    s.runtime_info.vdm_message_transcript_before_finish =
                        Some(transcript_before_finish);
                }
            }
        }
        VdmMessageOpCode::ExchangeMigrationInfoReq | VdmMessageOpCode::ExchangeRebindInfoReq => {}
        _ => {}
    };

    (Ok(()), Some(&rsp_bytes[..len]))
}
