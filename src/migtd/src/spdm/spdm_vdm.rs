// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use codec::{enum_builder, Codec, Reader, Writer};
use crypto::hash::digest_sha384;
use spdmlib::{
    common::{ManagedVdmBuffer, SpdmCodec},
    error::*,
    message::*,
    responder::ResponderContext,
};

use crate::spdm::spdm_rsp::*;

// Intel(343)
pub const VDM_MESSAGE_VENDOR_ID: [u8; 4] = [0x57, 0x1, 0x0, 0x0];
pub const VDM_MESSAGE_VENDOR_ID_LEN: usize = 4;

pub const VDM_MESSAGE_MAJOR_VERSION: u8 = 0;
pub const VDM_MESSAGE_MINOR_VERSION: u8 = 0;

pub const VDM_MESSAGE_EXCHANGE_PUB_KEY_ELEMENT_COUNT: u8 = 1;
pub const VDM_MESSAGE_EXCHANGE_MIG_ATTEST_INFO_ELEMENT_COUNT: u8 = 3;
pub const VDM_MESSAGE_EXCHANGE_MIG_INFO_ELEMENT_COUNT: u8 = 2;

pub const VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_VERSION_SIZE: u16 = 4;
pub const VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_SESSION_KEY_SIZE: u16 = 32;

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
        ExchangeMigrationInfoRsp => 0x06
//        ExchangeRebindAttestInfoReq => 0x07,
//        ExchangeRebindAttestInfoRsp => 0x08,
//        ExchangeRebindInfoReq => 0x09,
//        ExchangeRebindInfoRsp => 0x0A
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
//        SerVtdExt => 0x10,
//        TdReportInit => 0x12,
//        EventLogInit => 0x14,
//        MigPolicyInit => 0x15,
        MigrationExportVersion => 0x81,
        MigrationImportVersion => 0x82,
        ForwardMigrationSessionKey => 0x83,
        BackwardMigrationSessionKey => 0x84
//        RebindSessionToken => 0x85,
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
    pub length: u16,
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
        let length = u16::read(r)?;
        Some(VdmMessageElement {
            element_type,
            length,
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

    let vendor_defined_request_payload =
        SpdmVendorDefinedRequestPayload::spdm_read(&mut responder_context.common, &mut reader);
    if vendor_defined_request_payload.is_none() {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, &mut writer);
        let used = writer.used();
        return (Err(SPDM_STATUS_INVALID_MSG_FIELD), Some(&rsp_bytes[..used]));
    }

    let vendor_defined_request_payload = vendor_defined_request_payload.unwrap();
    let standard_id = vendor_defined_request_payload.standard_id;
    let vendor_id = vendor_defined_request_payload.vendor_id;
    let req_payload = vendor_defined_request_payload.req_payload;

    if standard_id != RegistryOrStandardsBodyID::IANA
        || vendor_id.len != VDM_MESSAGE_VENDOR_ID_LEN as u8
        || vendor_id.vendor_id[..VDM_MESSAGE_VENDOR_ID_LEN] != VDM_MESSAGE_VENDOR_ID
    {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, &mut writer);
        let used = writer.used();
        return (Err(SPDM_STATUS_INVALID_MSG_FIELD), Some(&rsp_bytes[..used]));
    }

    let mut reader =
        Reader::init(&req_payload.vendor_defined_req_payload[0..req_payload.req_length as usize]);
    let vdm_request = if let Some(vdm_request) = VdmMessage::read(&mut reader) {
        vdm_request
    } else {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, &mut writer);
        let used = writer.used();
        return (Err(SPDM_STATUS_INVALID_MSG_SIZE), Some(&rsp_bytes[..used]));
    };

    let mut response = SpdmMessage {
        header: SpdmMessageHeader {
            version: responder_context.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse,
        },
        payload: SpdmMessagePayload::SpdmVendorDefinedResponse(SpdmVendorDefinedResponsePayload {
            standard_id: RegistryOrStandardsBodyID::IANA,
            vendor_id: VendorIDStruct {
                len: VDM_MESSAGE_VENDOR_ID_LEN as u8,
                vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
            },
            rsp_payload: VendorDefinedRspPayloadStruct {
                rsp_length: 0,
                vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
            },
        }),
    };

    let vdm_payload = match &mut response.payload {
        SpdmMessagePayload::SpdmVendorDefinedResponse(vdm_payload) => vdm_payload,
        _ => {
            responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, &mut writer);
            let used = writer.used();
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(&rsp_bytes[..used]),
            );
        }
    };

    // Patch the vendor id field
    vdm_payload.vendor_id.vendor_id[..VDM_MESSAGE_VENDOR_ID_LEN]
        .copy_from_slice(&VDM_MESSAGE_VENDOR_ID);

    //Patch the response payload
    let rsp_payload = &mut vdm_payload.rsp_payload;
    let vdm_payload_size = match vdm_request.op_code {
        VdmMessageOpCode::ExchangePubKeyReq => handle_exchange_pub_key_req(
            responder_context,
            &vdm_request,
            &mut reader,
            &mut rsp_payload.vendor_defined_rsp_payload,
        ),
        VdmMessageOpCode::ExchangeMigrationAttestInfoReq => handle_exchange_mig_attest_info_req(
            responder_context,
            session_id,
            &vdm_request,
            &mut reader,
            &mut rsp_payload.vendor_defined_rsp_payload,
        ),
        VdmMessageOpCode::ExchangeMigrationInfoReq => handle_exchange_mig_info_req(
            responder_context,
            session_id,
            &vdm_request,
            &mut reader,
            &mut rsp_payload.vendor_defined_rsp_payload,
        ),
        _ => Err(SPDM_STATUS_INVALID_MSG_FIELD),
    };
    if let Ok(vdm_payload_size) = vdm_payload_size {
        rsp_payload.rsp_length = vdm_payload_size as u32;
    } else {
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, &mut writer);
        let used = writer.used();
        return (
            Err(SPDM_STATUS_INVALID_STATE_LOCAL),
            Some(&rsp_bytes[..used]),
        );
    };

    let res = response.spdm_encode(&mut responder_context.common, &mut writer);
    if res.is_err() {
        writer.clear();
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
                    writer.clear();
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
                    writer.clear();
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
                writer.clear();
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
                writer.clear();
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
        VdmMessageOpCode::ExchangeMigrationAttestInfoReq => {
            let vdm_attest_info_src_hash = match digest_sha384(req_bytes) {
                Ok(hash) => hash,
                Err(_) => {
                    writer.clear();
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
                    writer.clear();
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
                writer.clear();
                responder_context.write_spdm_error(
                    SpdmErrorCode::SpdmErrorUnspecified,
                    0,
                    &mut writer,
                );
                return (Err(SPDM_STATUS_BUFFER_FULL), Some(&rsp_bytes[..len]));
            }
            let res = transcript_before_finish.append_message(vdm_attest_info_dst_hash.as_slice());
            if res.is_none() {
                writer.clear();
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
        VdmMessageOpCode::ExchangeMigrationInfoReq => {}
        _ => {}
    };

    (Ok(()), Some(&rsp_bytes[..len]))
}
