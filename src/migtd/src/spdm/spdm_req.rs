// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use crate::mig_policy;
use crate::{
    migration::{
        data::MigrationSessionKey,
        session::{cal_mig_version, exchange_info, set_mig_version, write_msk},
        MigtdMigrationInformation,
    },
    spdm::{spdm_rsp::SECRET_ASYM_IMPL_INSTANCE, vmcall_msg::VmCallTransportEncap, *},
};
use async_io::{AsyncRead, AsyncWrite};
use codec::{Codec, Reader, Writer};
use crypto::{ecdsa::EcdsaPk, hash::digest_sha384};
use spdmlib::{
    common::{self, *},
    config,
    error::*,
    message::*,
    protocol::*,
    requester::RequesterContext,
};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use log::error;

use crate::{
    config::get_policy, driver::ticks::with_timeout, event_log::get_event_log,
    migration::session::ExchangeInformation,
};

pub fn spdm_requester<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
    stream: T,
) -> Result<RequesterContext, SpdmStatus> {
    let transport = MigtdTransport { transport: stream };
    let device_io = Arc::new(Mutex::new(transport));

    let req_capabilities = SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP
        | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        | SpdmRequestCapabilityFlags::CHUNK_CAP;

    let config_info = common::SpdmConfigInfo {
        spdm_version: [None, None, Some(SpdmVersion::SpdmVersion12), None, None],
        req_capabilities,
        req_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::default(),
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        other_params_support: SpdmAlgoOtherParams::OPAQUE_DATA_FMT1,
        data_transfer_size: config::SPDM_DATA_TRANSFER_SIZE as u32,
        max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
        secure_spdm_version: [
            None,
            None,
            Some(SecuredMessageVersion::try_from(0x12u8).unwrap()),
        ],
        ..Default::default()
    };

    let provision_info = SpdmProvisionInfo {
        ..Default::default()
    };

    // Create a transport layer
    let transport_encap = Arc::new(Mutex::new(VmCallTransportEncap {}));

    // Initialize the RequesterContext
    let requester_context =
        RequesterContext::new(device_io, transport_encap, config_info, provision_info);

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    Ok(requester_context)
}

pub async fn spdm_requester_transfer_msk(
    spdm_requester: &mut RequesterContext,
    mig_info: &MigtdMigrationInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<(), SpdmStatus> {
    let res = with_timeout(SPDM_TIMEOUT, spdm_requester.send_receive_spdm_version()).await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            return Err(SPDM_STATUS_RECEIVE_FAIL);
        }
    };

    let res = with_timeout(SPDM_TIMEOUT, spdm_requester.send_receive_spdm_capability()).await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            return Err(SPDM_STATUS_RECEIVE_FAIL);
        }
    };

    let res = with_timeout(SPDM_TIMEOUT, spdm_requester.send_receive_spdm_algorithm()).await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            return Err(SPDM_STATUS_RECEIVE_FAIL);
        }
    };

    let res = with_timeout(SPDM_TIMEOUT, send_and_receive_pub_key(spdm_requester)).await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            return Err(SPDM_STATUS_RECEIVE_FAIL);
        }
    };

    let res = with_timeout(
        SPDM_TIMEOUT,
        spdm_requester.send_receive_spdm_key_exchange(
            0xff,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        ),
    )
    .await;
    let session_id = match res {
        Ok(Ok(sid)) => sid,
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            return Err(SPDM_STATUS_RECEIVE_FAIL);
        }
    };

    let res: Result<Result<(), SpdmStatus>, crate::driver::ticks::TimeoutError> = with_timeout(
        SPDM_TIMEOUT,
        send_and_receive_sdm_migration_attest_info(
            spdm_requester,
            session_id,
            #[cfg(feature = "policy_v2")]
            remote_policy,
        ),
    )
    .await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            return Err(SPDM_STATUS_RECEIVE_FAIL);
        }
    };
    let res = with_timeout(
        SPDM_TIMEOUT,
        spdm_requester.send_receive_spdm_finish(Some(0xff), session_id),
    )
    .await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            return Err(SPDM_STATUS_RECEIVE_FAIL);
        }
    };

    let res = with_timeout(
        SPDM_TIMEOUT,
        send_and_receive_sdm_exchange_migration_info(spdm_requester, mig_info, Some(session_id)),
    )
    .await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            return Err(SPDM_STATUS_RECEIVE_FAIL);
        }
    };

    let res = with_timeout(
        SPDM_TIMEOUT,
        spdm_requester.send_receive_spdm_end_session(session_id),
    )
    .await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            return Err(SPDM_STATUS_RECEIVE_FAIL);
        }
    };
    Ok(())
}

async fn send_and_receive_pub_key(spdm_requester: &mut RequesterContext) -> SpdmResult {
    let signing_key = EcdsaPk::new().map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    let my_pub_key = signing_key.public_key_spki();

    //Save private to spdm context for signing
    let private_key = signing_key.private_key();
    let requester_app_context = SpdmAppContextData {
        migration_info: MigtdMigrationInformation::default(),
        private_key: PrivateKeyDer::from(private_key),
    };
    let writer = &mut Writer::init(&mut spdm_requester.common.app_context_data_buffer);
    requester_app_context
        .encode(writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    let mut vendor_id = [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN];
    vendor_id[..VDM_MESSAGE_VENDOR_ID_LEN].copy_from_slice(&VDM_MESSAGE_VENDOR_ID);
    let vendor_id = VendorIDStruct { len: 4, vendor_id };

    let mut payload = [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
    let mut writer = Writer::init(&mut payload);
    let mut cnt = 0;

    let vdm_exchange_pub_key = VdmMessage {
        major_version: VDM_MESSAGE_MAJOR_VERSION,
        minor_version: VDM_MESSAGE_MINOR_VERSION,
        op_code: VdmMessageOpCode::ExchangePubKeyReq,
        element_count: VDM_MESSAGE_EXCHANGE_PUB_KEY_ELEMENT_COUNT,
    };
    cnt += vdm_exchange_pub_key
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    let pub_key_element = VdmMessageElement {
        element_type: VdmMessageElementType::PubKeyMy,
        length: my_pub_key.len() as u16,
    };
    cnt += pub_key_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += writer
        .extend_from_slice(my_pub_key.as_slice())
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;

    let vdm_payload = VendorDefinedReqPayloadStruct {
        req_length: cnt as u32,
        vendor_defined_req_payload: payload,
    };

    spdm_requester.common.reset_buffer_via_request_code(
        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
        None,
    );

    let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(&mut send_buffer);
    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: spdm_requester.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
        },
        payload: SpdmMessagePayload::SpdmVendorDefinedRequest(SpdmVendorDefinedRequestPayload {
            standard_id: RegistryOrStandardsBodyID::IANA,
            vendor_id,
            req_payload: vdm_payload,
        }),
    };
    let used = request.spdm_encode(&mut spdm_requester.common, &mut writer)?;

    spdm_requester
        .send_message(None, &send_buffer[..used], false)
        .await?;

    let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
    let receive_used = spdm_requester
        .receive_message(None, &mut receive_buffer, false)
        .await?;

    let vdm_payload =
        spdm_requester.handle_spdm_vendor_defined_respond(None, &receive_buffer[..receive_used])?;

    // Format checks and save the received public key
    let mut reader =
        Reader::init(&vdm_payload.vendor_defined_rsp_payload[..vdm_payload.rsp_length as usize]);
    let vdm_message = VdmMessage::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_message.major_version != VDM_MESSAGE_MAJOR_VERSION {
        error!(
            "Invalid VDM message major_version: {:x?}\n",
            vdm_message.major_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_message.minor_version != VDM_MESSAGE_MINOR_VERSION {
        error!(
            "Invalid VDM message minor_version: {:x?}\n",
            vdm_message.minor_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_message.op_code != VdmMessageOpCode::ExchangePubKeyRsp {
        error!("Invalid VDM message op_code: {:x?}\n", vdm_message.op_code);
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_message.element_count != VDM_MESSAGE_EXCHANGE_PUB_KEY_ELEMENT_COUNT {
        error!(
            "Invalid VDM message element_count: {:x?}\n",
            vdm_message.element_count
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let vdm_element = VdmMessageElement::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_element.element_type != VdmMessageElementType::PubKeyMy {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            vdm_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_element.length as usize != reader.left() {
        error!(
            "Invalid VDM message element length: {:x?}, left: {:x?}\n",
            vdm_element.length,
            reader.left()
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let peer_pub_key = reader
        .take(vdm_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

    if my_pub_key.len() > config::MAX_SPDM_CERT_CHAIN_DATA_SIZE
        || peer_pub_key.len() > config::MAX_SPDM_CERT_CHAIN_DATA_SIZE
    {
        error!("Public key size is too large.\n");
        return Err(SPDM_STATUS_BUFFER_FULL);
    }

    // Provision the public keys to spdm context
    let mut my_pub_key_prov = SpdmCertChainData {
        data_size: my_pub_key.len() as u32,
        data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
    };
    my_pub_key_prov.data[..my_pub_key.len()].copy_from_slice(&my_pub_key);
    spdm_requester.common.provision_info.my_pub_key = Some(my_pub_key_prov);

    let mut peer_pub_key_prov = SpdmCertChainData {
        data_size: peer_pub_key.len() as u32,
        data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
    };
    peer_pub_key_prov.data[..peer_pub_key.len()].copy_from_slice(peer_pub_key);
    spdm_requester.common.provision_info.peer_pub_key = Some(peer_pub_key_prov);

    let vdm_pub_key_src_hash =
        digest_sha384(&send_buffer[..used]).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    let vdm_pub_key_dst_hash =
        digest_sha384(&receive_buffer[..receive_used]).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    let mut transcript_before_key_exchange = ManagedVdmBuffer::default();
    transcript_before_key_exchange
        .append_message(vdm_pub_key_src_hash.as_slice())
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;
    transcript_before_key_exchange
        .append_message(vdm_pub_key_dst_hash.as_slice())
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;

    spdm_requester
        .common
        .runtime_info
        .vdm_message_transcript_before_key_exchange = Some(transcript_before_key_exchange);

    Ok(())
}

pub async fn send_and_receive_sdm_migration_attest_info(
    spdm_requester: &mut RequesterContext,
    session_id: u32,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> SpdmResult {
    if spdm_requester.common.provision_info.my_pub_key.is_none()
        || spdm_requester.common.provision_info.peer_pub_key.is_none()
    {
        error!("Cannot transfer attestation info without provisioning my_pub_key.\n");
        return Err(SPDM_STATUS_UNSUPPORTED_CAP);
    }

    let mut vendor_id = [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN];
    vendor_id[..VDM_MESSAGE_VENDOR_ID_LEN].copy_from_slice(&VDM_MESSAGE_VENDOR_ID);
    let vendor_id = VendorIDStruct { len: 4, vendor_id };

    let mut payload = [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
    let mut writer = Writer::init(&mut payload);
    let mut cnt = 0;

    let vdm_exchange_attest_info = VdmMessage {
        major_version: VDM_MESSAGE_MAJOR_VERSION,
        minor_version: VDM_MESSAGE_MINOR_VERSION,
        op_code: VdmMessageOpCode::ExchangeMigrationAttestInfoReq,
        element_count: VDM_MESSAGE_EXCHANGE_MIG_ATTEST_INFO_ELEMENT_COUNT,
    };

    cnt += vdm_exchange_attest_info
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    let th1 = if let Some(s) = spdm_requester.common.get_session_via_id(session_id) {
        s.get_th1()
    } else {
        error!("Cannot get session id. Attestation failed.\n");
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    };

    let report_data_prefix = "MigTDReq".as_bytes();
    let report_data_prefix_len = report_data_prefix.len();
    // Build concatenated slice: "MigTDReq" || th1
    let th1_len = th1.data_size as usize;
    // th1 for SHA-384 should be 48 bytes; 8 (prefix) + 48 digest = 56 bytes needed.
    if th1_len > SPDM_MAX_HASH_SIZE {
        error!("th1 length is too large: {}\n", th1_len);
        return Err(SPDM_STATUS_BUFFER_FULL);
    }
    let mut report_data = [0u8; "MigTDReq".len() + SPDM_MAX_HASH_SIZE];
    // Copy prefix
    report_data[..report_data_prefix_len].copy_from_slice(report_data_prefix);
    report_data[report_data_prefix_len..report_data_prefix_len + th1_len]
        .copy_from_slice(&th1.data[..th1_len]);

    //quote src
    let quote_src = gen_quote_spdm(&report_data[..report_data_prefix_len + th1_len])
        .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?;
    let res = attestation::verify_quote(quote_src.as_slice());
    //  The session MUST be terminated immediately, if the mutual attestation failure
    if res.is_err() {
        error!("mutual attestation failed, end the session!\n");
        let session = spdm_requester
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        session.teardown();
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    #[cfg(not(feature = "policy_v2"))]
    let verified_report_local = res.unwrap();

    if quote_src.len() > u16::MAX as usize {
        error!("Quote size is too large: {}\n", quote_src.len());
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }
    let quote_element = VdmMessageElement {
        element_type: VdmMessageElementType::QuoteMy,
        length: quote_src.len() as u16,
    };
    cnt += quote_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += writer
        .extend_from_slice(quote_src.as_slice())
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;

    //event log src
    let event_log_src = get_event_log().ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    if event_log_src.len() > u16::MAX as usize {
        error!("Event log size is too large: {}\n", event_log_src.len());
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }
    let event_log_element = VdmMessageElement {
        element_type: VdmMessageElementType::EventLogMy,
        length: event_log_src.len() as u16,
    };
    cnt += event_log_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += writer
        .extend_from_slice(event_log_src)
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;

    //mig policy src
    let mig_policy_src = get_policy().ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    let mig_policy_src_hash =
        digest_sha384(mig_policy_src).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;

    let mig_policy_element = VdmMessageElement {
        element_type: VdmMessageElementType::MigPolicyMy,
        length: mig_policy_src_hash.len() as u16,
    };
    cnt += mig_policy_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += writer
        .extend_from_slice(&mig_policy_src_hash)
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;

    let vdm_payload = VendorDefinedReqPayloadStruct {
        req_length: cnt as u32,
        vendor_defined_req_payload: payload,
    };

    spdm_requester.common.reset_buffer_via_request_code(
        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
        None,
    );

    let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(&mut send_buffer);
    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: spdm_requester.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
        },
        payload: SpdmMessagePayload::SpdmVendorDefinedRequest(SpdmVendorDefinedRequestPayload {
            standard_id: RegistryOrStandardsBodyID::IANA,
            vendor_id,
            req_payload: vdm_payload,
        }),
    };
    let used = request.spdm_encode(&mut spdm_requester.common, &mut writer)?;

    spdm_requester
        .send_message(None, &send_buffer[..used], false)
        .await?;

    let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
    let receive_used = spdm_requester
        .receive_message(None, &mut receive_buffer, false)
        .await?;

    let vdm_payload =
        spdm_requester.handle_spdm_vendor_defined_respond(None, &receive_buffer[..receive_used])?;

    //Format checks
    let reader = &mut Reader::init(
        &vdm_payload.vendor_defined_rsp_payload[..vdm_payload.rsp_length as usize],
    );
    let vdm_message = VdmMessage::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_message.major_version != VDM_MESSAGE_MAJOR_VERSION {
        error!(
            "Invalid VDM message major_version: {:x?}\n",
            vdm_message.major_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_message.minor_version != VDM_MESSAGE_MINOR_VERSION {
        error!(
            "Invalid VDM message minor_version: {:x?}\n",
            vdm_message.minor_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_message.op_code != VdmMessageOpCode::ExchangeMigrationAttestInfoRsp {
        error!("Invalid VDM message op_code: {:x?}\n", vdm_message.op_code);
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_message.element_count != VDM_MESSAGE_EXCHANGE_MIG_ATTEST_INFO_ELEMENT_COUNT {
        error!(
            "Invalid VDM message element_count: {:x?}\n",
            vdm_message.element_count
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    //quote dst
    let vdm_element = VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_element.element_type != VdmMessageElementType::QuoteMy {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            vdm_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let quote_dst = reader
        .take(vdm_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    let res = attestation::verify_quote(quote_dst);
    if res.is_err() {
        error!("mutual attestation failed, end the session!\n");
        let session = spdm_requester
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        session.teardown();
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    #[cfg(not(feature = "policy_v2"))]
    let verified_report_peer = res.unwrap();
    #[cfg(feature = "policy_v2")]
    let quote_dst_vec = quote_dst.to_vec();

    //event log dst
    let vdm_element = VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_element.element_type != VdmMessageElementType::EventLogMy {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            vdm_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let event_log_dst = reader
        .take(vdm_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    #[cfg(feature = "policy_v2")]
    let event_log_dst_vec = event_log_dst.to_vec();

    #[cfg(not(feature = "policy_v2"))]
    {
        let policy_check_result = mig_policy::authenticate_policy(
            true,
            verified_report_local.as_slice(),
            verified_report_peer.as_slice(),
            event_log_dst,
        );
        if let Err(e) = &policy_check_result {
            error!("Policy check failed, below is the detail information:\n");
            error!("{:x?}\n", e);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
    }

    //mig policy dst
    let vdm_element = VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_element.element_type != VdmMessageElementType::MigPolicyMy {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            vdm_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    #[cfg(feature = "policy_v2")]
    let mig_policy_hash_dst = reader
        .take(vdm_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    #[cfg(not(feature = "policy_v2"))]
    let _mig_policy_hash_dst = reader
        .take(vdm_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

    #[cfg(feature = "policy_v2")]
    {
        let remote_policy_hash =
            digest_sha384(&remote_policy).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
        if mig_policy_hash_dst != remote_policy_hash.as_slice() {
            error!(
                "The received mig policy hash does not match the expected remote policy hash!\n"
            );
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        let policy_check_result = mig_policy::authenticate_remote(
            true,
            quote_dst_vec.as_slice(),
            &remote_policy,
            event_log_dst_vec.as_slice(),
        );
        if let Err(e) = &policy_check_result {
            error!("Policy v2 check failed, below is the detail information:\n");
            error!("{:x?}\n", e);
            let session = spdm_requester
                .common
                .get_session_via_id(session_id)
                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
            session.teardown();
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
    }

    let vdm_attest_info_src_hash =
        digest_sha384(&send_buffer[..used]).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    let vdm_attest_info_dst_hash =
        digest_sha384(&receive_buffer[..receive_used]).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    let mut transcript_before_finish = ManagedVdmBuffer::default();
    transcript_before_finish
        .append_message(vdm_attest_info_src_hash.as_slice())
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;
    transcript_before_finish
        .append_message(vdm_attest_info_dst_hash.as_slice())
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;
    if let Some(s) = spdm_requester.common.get_session_via_id(session_id) {
        s.runtime_info.vdm_message_transcript_before_finish = Some(transcript_before_finish);
    } else {
        error!("Cannot get session id. Attestation failed.\n");
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }

    Ok(())
}

async fn send_and_receive_sdm_exchange_migration_info(
    spdm_requester: &mut RequesterContext,
    mig_info: &MigtdMigrationInformation,
    session_id: Option<u32>,
) -> SpdmResult {
    let mut vendor_id = [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN];
    vendor_id[..VDM_MESSAGE_VENDOR_ID_LEN].copy_from_slice(&VDM_MESSAGE_VENDOR_ID);
    let vendor_id = VendorIDStruct { len: 4, vendor_id };

    let mut exchange_information =
        exchange_info(mig_info, false).map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?;

    let mut payload = [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
    let mut writer = Writer::init(&mut payload);
    let mut cnt = 0;

    let vdm_exchange_migration_info = VdmMessage {
        major_version: VDM_MESSAGE_MAJOR_VERSION,
        minor_version: VDM_MESSAGE_MINOR_VERSION,
        op_code: VdmMessageOpCode::ExchangeMigrationInfoReq,
        element_count: VDM_MESSAGE_EXCHANGE_MIG_INFO_ELEMENT_COUNT,
    };

    cnt += vdm_exchange_migration_info
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    //Migration Export Version
    let mig_export_version_element = VdmMessageElement {
        element_type: VdmMessageElementType::MigrationExportVersion,
        length: VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_VERSION_SIZE,
    };
    cnt += mig_export_version_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += exchange_information
        .min_ver
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += exchange_information
        .max_ver
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    //Forward Migration Session Key
    let mig_session_key_element = VdmMessageElement {
        element_type: VdmMessageElementType::ForwardMigrationSessionKey,
        length: VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_SESSION_KEY_SIZE,
    };
    cnt += mig_session_key_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += exchange_information
        .key
        .fields
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    let vdm_payload = VendorDefinedReqPayloadStruct {
        req_length: cnt as u32,
        vendor_defined_req_payload: payload,
    };

    spdm_requester.common.reset_buffer_via_request_code(
        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
        None,
    );

    let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(&mut send_buffer);
    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: spdm_requester.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
        },
        payload: SpdmMessagePayload::SpdmVendorDefinedRequest(SpdmVendorDefinedRequestPayload {
            standard_id: RegistryOrStandardsBodyID::IANA,
            vendor_id,
            req_payload: vdm_payload,
        }),
    };
    let used = request.spdm_encode(&mut spdm_requester.common, &mut writer)?;

    spdm_requester
        .send_message(session_id, &send_buffer[..used], false)
        .await?;

    let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
    let receive_used = spdm_requester
        .receive_message(session_id, &mut receive_buffer, false)
        .await?;

    let vdm_payload = spdm_requester
        .handle_spdm_vendor_defined_respond(session_id, &receive_buffer[..receive_used])?;

    let reader = &mut Reader::init(
        &vdm_payload.vendor_defined_rsp_payload[..vdm_payload.rsp_length as usize],
    );
    let vdm_message = VdmMessage::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_message.major_version != VDM_MESSAGE_MAJOR_VERSION {
        error!(
            "Invalid VDM message major_version: {:x?}\n",
            vdm_message.major_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_message.minor_version != VDM_MESSAGE_MINOR_VERSION {
        error!(
            "Invalid VDM message minor_version: {:x?}\n",
            vdm_message.minor_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_message.op_code != VdmMessageOpCode::ExchangeMigrationInfoRsp {
        error!("Invalid VDM message op_code: {:x?}\n", vdm_message.op_code);
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_message.element_count != VDM_MESSAGE_EXCHANGE_MIG_INFO_ELEMENT_COUNT {
        error!(
            "Invalid VDM message element_count: {:x?}\n",
            vdm_message.element_count
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let mig_export_version_element =
        VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if mig_export_version_element.element_type != VdmMessageElementType::MigrationImportVersion {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            mig_export_version_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if mig_export_version_element.length != VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_VERSION_SIZE {
        error!(
            "Invalid VDM message element length: {:x?}\n",
            mig_export_version_element.length
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let min_import_version = u16::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    let max_import_version = u16::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    let mig_session_key_element =
        VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if mig_session_key_element.element_type != VdmMessageElementType::BackwardMigrationSessionKey {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            mig_session_key_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if mig_session_key_element.length != VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_SESSION_KEY_SIZE {
        error!(
            "Invalid VDM message element length: {:x?}\n",
            mig_session_key_element.length
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    let mut remote_information = ExchangeInformation {
        min_ver: min_import_version,
        max_ver: max_import_version,
        key: MigrationSessionKey {
            fields: <[u64; 4]>::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?,
        },
    };

    let mig_ver = cal_mig_version(false, &exchange_information, &remote_information)
        .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?;
    set_mig_version(mig_info, mig_ver).map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?;
    write_msk(mig_info, &remote_information.key).map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?;
    log::info!("Set MSK and report status\n");
    exchange_information.key.clear();
    remote_information.key.clear();

    Ok(())
}
