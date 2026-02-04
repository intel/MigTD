// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::mig_policy;
use crate::{
    config::get_policy,
    event_log::get_event_log,
    migration::{
        data::MigrationSessionKey,
        session::{
            cal_mig_version, exchange_info, set_mig_version, write_msk, ExchangeInformation,
        },
        MigtdMigrationInformation,
    },
};
use alloc::sync::Arc;
use async_io::{AsyncRead, AsyncWrite};
use codec::{Codec, Reader, Writer};
use core::ops::DerefMut;
use crypto::{ecdsa::EcdsaPk, hash::digest_sha384};
use log::error;

use crate::spdm::{vmcall_msg::VmCallTransportEncap, *};
use spdmlib::{
    common::{self, *},
    config,
    error::*,
    message::*,
    protocol::*,
    responder::ResponderContext,
    secret::SpdmSecretAsymSign,
};
use spin::Mutex;
use zerocopy::AsBytes;
use zeroize::Zeroize;

extern crate alloc;

#[repr(C)]
pub struct ResponderContextEx {
    pub responder_context: ResponderContext,
    pub remote_policy: Vec<u8>,
}

impl ResponderContextEx {
    pub fn inner(&self) -> &ResponderContext {
        &self.responder_context
    }
    pub fn inner_mut(&mut self) -> &mut ResponderContext {
        &mut self.responder_context
    }
}

#[cfg(feature = "policy_v2")]
pub unsafe fn upcast_mut(inner: &mut ResponderContext) -> &mut ResponderContextEx {
    let ptr = inner as *mut ResponderContext as *mut u8;
    let outer_ptr = ptr.sub(0) as *mut ResponderContextEx;
    &mut *outer_ptr
}

pub fn spdm_responder<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
    stream: T,
) -> Result<(ResponderContextEx, SpdmDeviceIoArc<T>), SpdmStatus> {
    let transport = MigtdTransport { transport: stream };
    let device_io = Arc::new(Mutex::new(transport));
    let device_io_ref = device_io.clone();

    let rsp_capabilities = SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP
        | SpdmResponseCapabilityFlags::MUT_AUTH_CAP
        | SpdmResponseCapabilityFlags::KEY_EX_CAP
        | SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP
        | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        | SpdmResponseCapabilityFlags::CHUNK_CAP;

    let config_info = common::SpdmConfigInfo {
        spdm_version: [None, None, Some(SpdmVersion::SpdmVersion12), None, None],
        rsp_capabilities,
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
    let mut responder_context =
        ResponderContext::new(device_io, transport_encap, config_info, provision_info);
    responder_context.common.encap_context.mut_auth_requested =
        SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ;
    responder_context.common.encap_context.req_slot_id = SPDM_PUB_KEY_SLOT_ID_KEY_EXCHANGE_RSP;

    spdmlib::message::vendor::register_vendor_defined_struct_ex(VendorDefinedStructEx {
        vendor_defined_request_handler_ex: migtd_vdm_msg_rsp_dispatcher_ex,
        vdm_handle: 0,
    });
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let responder_context_ex = ResponderContextEx {
        responder_context,
        remote_policy: Vec::new(),
    };

    Ok((responder_context_ex, device_io_ref))
}

pub async fn spdm_responder_transfer_msk(
    spdm_responder_ex: &mut ResponderContextEx,
    mig_info: &MigtdMigrationInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<(), SpdmStatus> {
    #[cfg(not(feature = "policy_v2"))]
    let remote_policy = Vec::new();

    spdm_responder_ex.remote_policy = remote_policy;

    let spdm_responder = &mut spdm_responder_ex.responder_context;
    let mut writer = Writer::init(&mut spdm_responder.common.app_context_data_buffer);

    let responder_app_context = SpdmAppContextData {
        migration_info: mig_info.clone(),
        private_key: PrivateKeyDer::default(),
    };
    responder_app_context
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    Box::pin(rsp_handle_message(spdm_responder)).await?;
    spdm_responder.common.app_context_data_buffer.zeroize();

    Ok(())
}

pub async fn rsp_handle_message(spdm_responder: &mut ResponderContext) -> Result<(), SpdmStatus> {
    let mut sid = None;
    loop {
        let raw_packet = Arc::new(Mutex::new([0u8; config::RECEIVER_BUFFER_SIZE]));
        let mut raw_packet = raw_packet.lock();
        let raw_packet = raw_packet.deref_mut();
        raw_packet.zeroize();
        let res = Box::pin(spdm_responder.process_message(false, 0, raw_packet)).await;

        let session_id = spdm_responder.common.runtime_info.get_last_session_id();
        if session_id.is_some() {
            sid = session_id;
        }
        if sid.is_some()
            && spdm_responder
                .common
                .get_session_via_id(sid.unwrap())
                .is_none()
        {
            //Terminate the responder upon end_session received.
            break;
        }

        match res {
            Ok(spdm_result) => {
                match spdm_result {
                    Ok(_) => {}
                    Err(spdm_status) => {
                        if spdm_status.severity == StatusSeverity::ERROR
                            && matches!(spdm_status.status_code, StatusCode::VDM(_))
                        {
                            return Err(spdm_status);
                        }
                        if spdm_status == SPDM_STATUS_INVALID_STATE_LOCAL {
                            //Terminate the responder upon invalid state.
                            return Err(spdm_status);
                        }
                    }
                }
            }
            Err(_) => {
                return Err(SPDM_STATUS_RECEIVE_FAIL);
            }
        }
    }
    Ok(())
}

pub fn handle_exchange_pub_key_req(
    spdm_responder: &mut ResponderContext,
    vdm_request: &VdmMessage,
    reader: &mut Reader<'_>,
    vendor_defined_rsp_payload: &mut [u8],
) -> SpdmResult<usize> {
    if spdm_responder
        .common
        .runtime_info
        .get_connection_state()
        .get_u8()
        < SpdmConnectionState::SpdmConnectionNegotiated.get_u8()
    {
        error!("Cannot negotiate pub_key before connection established.\n");
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }

    if vdm_request.major_version != VDM_MESSAGE_MAJOR_VERSION {
        error!(
            "Invalid VDM message major_version: {:x?}\n",
            vdm_request.major_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_request.minor_version != VDM_MESSAGE_MINOR_VERSION {
        error!(
            "Invalid VDM message minor_version: {:x?}\n",
            vdm_request.minor_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_request.op_code != VdmMessageOpCode::ExchangePubKeyReq {
        error!("Invalid VDM message op_code: {:x?}\n", vdm_request.op_code);
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_request.element_count != VDM_MESSAGE_EXCHANGE_PUB_KEY_ELEMENT_COUNT {
        error!(
            "Invalid VDM message element_count: {:x?}\n",
            vdm_request.element_count
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    let peer_pub_key_element =
        VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if peer_pub_key_element.element_type != VdmMessageElementType::PubKeyMy {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            peer_pub_key_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    if peer_pub_key_element.length as usize != reader.left() {
        error!(
            "Invalid VDM message element length: {:x?}, left: {:x?}\n",
            peer_pub_key_element.length,
            reader.left()
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let peer_pub_key = reader
        .take(peer_pub_key_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

    let signing_key = EcdsaPk::new().map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    let my_pub_key = signing_key.public_key_spki();

    //Save private to spdm context for signing
    let reader = &mut Reader::init(&spdm_responder.common.app_context_data_buffer);
    let mut responder_app_context =
        SpdmAppContextData::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    responder_app_context.private_key = PrivateKeyDer::from(signing_key.private_key());
    let mut writer = Writer::init(&mut spdm_responder.common.app_context_data_buffer);
    responder_app_context
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    let mut writer = Writer::init(vendor_defined_rsp_payload);
    let mut cnt = 0;

    let vdm_exchange_pub_key = VdmMessage {
        major_version: VDM_MESSAGE_MAJOR_VERSION,
        minor_version: VDM_MESSAGE_MINOR_VERSION,
        op_code: VdmMessageOpCode::ExchangePubKeyRsp,
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
        .extend_from_slice(my_pub_key.as_bytes())
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;

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
    spdm_responder.common.provision_info.my_pub_key = Some(my_pub_key_prov);

    let mut peer_pub_key_prov = SpdmCertChainData {
        data_size: peer_pub_key_element.length as u32,
        data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
    };
    peer_pub_key_prov.data[..peer_pub_key_element.length as usize].copy_from_slice(peer_pub_key);
    spdm_responder.common.provision_info.peer_pub_key = Some(peer_pub_key_prov);

    Ok(cnt)
}

pub fn handle_exchange_mig_attest_info_req(
    responder_context: &mut ResponderContext,
    session_id: Option<u32>,
    vdm_request: &VdmMessage,
    reader: &mut Reader<'_>,
    vendor_defined_rsp_payload: &mut [u8],
) -> SpdmResult<usize> {
    let session_id = if session_id.is_some() {
        session_id
    } else {
        responder_context.common.runtime_info.get_last_session_id()
    };
    if session_id.is_none() {
        error!("Cannot transfer attestation info before key exchange.\n");
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }
    let session_id = session_id.unwrap();

    let session = responder_context
        .common
        .get_session_via_id(session_id)
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    if session
        .runtime_info
        .vdm_message_transcript_before_finish
        .is_some()
    {
        error!("Attestation info has already been exchanged.\n");
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }

    if responder_context.common.provision_info.my_pub_key.is_none()
        || responder_context
            .common
            .provision_info
            .peer_pub_key
            .is_none()
    {
        error!("Cannot transfer attestation info without provisioning pub_key.\n");
        return Err(SPDM_STATUS_UNSUPPORTED_CAP);
    }

    if vdm_request.major_version != VDM_MESSAGE_MAJOR_VERSION {
        error!(
            "Invalid VDM message major_version: {:x?}\n",
            vdm_request.major_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_request.minor_version != VDM_MESSAGE_MINOR_VERSION {
        error!(
            "Invalid VDM message minor_version: {:x?}\n",
            vdm_request.minor_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_request.op_code != VdmMessageOpCode::ExchangeMigrationAttestInfoReq {
        error!("Invalid VDM message op_code: {:x?}\n", vdm_request.op_code);
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_request.element_count != VDM_MESSAGE_EXCHANGE_MIG_ATTEST_INFO_ELEMENT_COUNT {
        error!(
            "Invalid VDM message element_count: {:x?}\n",
            vdm_request.element_count
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    let th1 = if let Some(s) = responder_context.common.get_session_via_id(session_id) {
        s.get_th1()
    } else {
        error!("Cannot get TH1 from session.\n");
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    };

    let report_data_prefix = "MigTDRsp".as_bytes();
    let report_data_prefix_len = report_data_prefix.len();
    // Build concatenated slice: "MigTDRsp" || th1
    let th1_len = th1.data_size as usize;
    // th1 for SHA-384 should be 48 bytes; 8 (prefix) + 48 digest = 56 bytes needed.
    if th1_len > SPDM_MAX_HASH_SIZE {
        error!("th1 length is too large: {}\n", th1_len);
        return Err(SPDM_STATUS_BUFFER_FULL);
    }
    let mut report_data = [0u8; "MigTDRsp".len() + SPDM_MAX_HASH_SIZE];
    // Copy prefix
    report_data[..report_data_prefix_len].copy_from_slice(report_data_prefix);
    report_data[report_data_prefix_len..report_data_prefix_len + th1_len]
        .copy_from_slice(&th1.data[..th1_len]);

    //quote dst
    let quote_dst = gen_quote_spdm(&report_data[..report_data_prefix_len + th1_len])?;

    #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
    let res = attestation::verify_quote(quote_dst.as_slice());
    //  The session MUST be terminated immediately, if the mutual attestation failure
    #[cfg(feature = "test_disable_ra_and_accept_all")]
    let res: Result<Vec<u8>, ()> = Ok(vec![]);

    if res.is_err() {
        error!("mutual attestation failed, end the session!\n");
        let session = responder_context
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        session.teardown();
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    #[cfg(not(feature = "policy_v2"))]
    let verified_report_local = res.unwrap();

    //quote src
    let vdm_element = VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_element.element_type != VdmMessageElementType::QuoteMy {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            vdm_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let quote_src = reader
        .take(vdm_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
    let res = attestation::verify_quote(quote_src);
    #[cfg(feature = "test_disable_ra_and_accept_all")]
    let res: Result<Vec<u8>, ()> = Ok(vec![]);

    //  The session MUST be terminated immediately, if the mutual attestation failure
    if res.is_err() {
        error!("mutual attestation failed, end the session!\n");
        let session = responder_context
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        session.teardown();
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    #[cfg(not(feature = "policy_v2"))]
    let verified_report_peer = res.unwrap();
    #[cfg(feature = "policy_v2")]
    let quote_src_vec = quote_src.to_vec();

    //event log src
    let vdm_element = VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_element.element_type != VdmMessageElementType::EventLogMy {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            vdm_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let event_log_src = reader
        .take(vdm_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    #[cfg(feature = "policy_v2")]
    let event_log_src_vec = event_log_src.to_vec();

    #[cfg(not(feature = "policy_v2"))]
    #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
    {
        let policy_check_result = mig_policy::authenticate_policy(
            false,
            verified_report_local.as_slice(),
            verified_report_peer.as_slice(),
            event_log_src,
        );
        if let Err(e) = &policy_check_result {
            error!("Policy check failed, below is the detail information:\n");
            error!("{:x?}\n", e);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
    }

    //mig policy src
    let vdm_element = VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if vdm_element.element_type != VdmMessageElementType::MigPolicyMy {
        error!(
            "Invalid VDM message element_type: {:x?}\n",
            vdm_element.element_type
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    #[cfg(feature = "policy_v2")]
    let mig_policy_hash_src = reader
        .take(vdm_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    #[cfg(not(feature = "policy_v2"))]
    let _mig_policy_hash_src = reader
        .take(vdm_element.length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

    #[cfg(feature = "policy_v2")]
    {
        let remote_policy = unsafe {
            let spdm_responder_ex = upcast_mut(responder_context);
            spdm_responder_ex.remote_policy.as_slice()
        };
        let remote_policy_hash =
            digest_sha384(remote_policy).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
        if mig_policy_hash_src != remote_policy_hash.as_slice() {
            error!(
                "The received mig policy hash does not match the expected remote policy hash!\n"
            );
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
        {
            let policy_check_result = mig_policy::authenticate_remote(
                false,
                quote_src_vec.as_slice(),
                remote_policy,
                event_log_src_vec.as_slice(),
            );
            if let Err(e) = &policy_check_result {
                error!("Policy v2 check failed, below is the detail information:\n");
                error!("{:x?}\n", e);
                let session = responder_context
                    .common
                    .get_session_via_id(session_id)
                    .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
                session.teardown();
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
        }
    }

    let mut writer = Writer::init(vendor_defined_rsp_payload);
    let mut cnt = 0;

    let vdm_exchange_attest_info = VdmMessage {
        major_version: VDM_MESSAGE_MAJOR_VERSION,
        minor_version: VDM_MESSAGE_MINOR_VERSION,
        op_code: VdmMessageOpCode::ExchangeMigrationAttestInfoRsp,
        element_count: VDM_MESSAGE_EXCHANGE_MIG_ATTEST_INFO_ELEMENT_COUNT,
    };

    cnt += vdm_exchange_attest_info
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    //quote dst
    if quote_dst.len() > u16::MAX as usize {
        error!("Quote size is too large: {}\n", quote_dst.len());
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }
    let quote_element = VdmMessageElement {
        element_type: VdmMessageElementType::QuoteMy,
        length: quote_dst.len() as u16,
    };
    cnt += quote_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += writer
        .extend_from_slice(quote_dst.as_slice())
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;

    //event log dst
    let event_log_dst = get_event_log().ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    if event_log_dst.len() > u16::MAX as usize {
        error!("Event log size is too large: {}\n", event_log_dst.len());
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }
    let event_log_element = VdmMessageElement {
        element_type: VdmMessageElementType::EventLogMy,
        length: event_log_dst.len() as u16,
    };
    cnt += event_log_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += writer
        .extend_from_slice(event_log_dst)
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;

    //mig policy dst
    let mig_policy_dst = get_policy().ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    let mig_policy_dst_hash =
        digest_sha384(mig_policy_dst).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    let mig_policy_element = VdmMessageElement {
        element_type: VdmMessageElementType::MigPolicyMy,
        length: mig_policy_dst_hash.len() as u16,
    };
    cnt += mig_policy_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += writer
        .extend_from_slice(&mig_policy_dst_hash)
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;

    Ok(cnt)
}

pub fn handle_exchange_mig_info_req(
    responder_context: &mut ResponderContext,
    session_id: Option<u32>,
    vdm_request: &VdmMessage,
    reader: &mut Reader<'_>,
    vendor_defined_rsp_payload: &mut [u8],
) -> SpdmResult<usize> {
    // The VDM message for secret migration info exchange MUST be sent after mutual attested session establishment.
    let session_id = if let Some(sid) = session_id {
        sid
    } else {
        return Err(SPDM_STATUS_INVALID_PARAMETER);
    };

    let session = responder_context
        .common
        .get_session_via_id(session_id)
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    if session.get_session_state()
        != spdmlib::common::session::SpdmSessionState::SpdmSessionEstablished
        || session
            .runtime_info
            .vdm_message_transcript_before_finish
            .is_none()
    {
        error!("Migration info received while session is not established!\n");
        session.teardown();
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }

    if vdm_request.major_version != VDM_MESSAGE_MAJOR_VERSION {
        error!(
            "Invalid VDM message major_version: {:x?}\n",
            vdm_request.major_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_request.minor_version != VDM_MESSAGE_MINOR_VERSION {
        error!(
            "Invalid VDM message minor_version: {:x?}\n",
            vdm_request.minor_version
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_request.op_code != VdmMessageOpCode::ExchangeMigrationInfoReq {
        error!("Invalid VDM message op_code: {:x?}\n", vdm_request.op_code);
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if vdm_request.element_count != VDM_MESSAGE_EXCHANGE_MIG_INFO_ELEMENT_COUNT {
        error!(
            "Invalid VDM message element_count: {:x?}\n",
            vdm_request.element_count
        );
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    let mig_export_version_element =
        VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if mig_export_version_element.element_type != VdmMessageElementType::MigrationExportVersion
        || mig_export_version_element.length != VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_VERSION_SIZE
    {
        error!("invalid migration info payload!\n");
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let min_export_version = u16::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    let max_export_version = u16::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

    let mig_session_key_element =
        VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if mig_session_key_element.element_type != VdmMessageElementType::ForwardMigrationSessionKey
        || mig_session_key_element.length
            != VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_SESSION_KEY_SIZE
    {
        error!("invalid forward migration session key!\n");
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    let mut remote_information = ExchangeInformation {
        min_ver: min_export_version,
        max_ver: max_export_version,
        key: MigrationSessionKey {
            fields: <[u64; 4]>::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?,
        },
    };

    let mut reader = Reader::init(responder_context.common.app_context_data_buffer.as_ref());
    let responder_app_context =
        SpdmAppContextData::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    let mut exchange_information = exchange_info(&responder_app_context.migration_info, false)?;

    let mig_ver = cal_mig_version(false, &exchange_information, &remote_information)?;
    set_mig_version(&responder_app_context.migration_info, mig_ver)?;
    write_msk(
        &responder_app_context.migration_info,
        &remote_information.key,
    )?;
    log::info!("Set MSK and report status\n");

    let min_import_version = exchange_information.min_ver;
    let max_import_version = exchange_information.max_ver;
    let mig_session_key = exchange_information.key.as_bytes().to_vec();

    let mut writer = Writer::init(vendor_defined_rsp_payload);
    let mut cnt = 0;
    let vdm_exchange_mig_info = VdmMessage {
        major_version: VDM_MESSAGE_MAJOR_VERSION,
        minor_version: VDM_MESSAGE_MINOR_VERSION,
        op_code: VdmMessageOpCode::ExchangeMigrationInfoRsp,
        element_count: VDM_MESSAGE_EXCHANGE_MIG_INFO_ELEMENT_COUNT,
    };
    cnt += vdm_exchange_mig_info
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    let mig_import_version_element = VdmMessageElement {
        element_type: VdmMessageElementType::MigrationImportVersion,
        length: VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_VERSION_SIZE,
    };
    cnt += mig_import_version_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += min_import_version
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += max_import_version
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    let mig_session_key_element = VdmMessageElement {
        element_type: VdmMessageElementType::BackwardMigrationSessionKey,
        length: VDM_MESSAGE_EXCHANGE_MIG_INFO_MIGRATION_SESSION_KEY_SIZE,
    };
    cnt += mig_session_key_element
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    cnt += writer
        .extend_from_slice(&mig_session_key)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

    Ok(cnt)
}

pub static SECRET_ASYM_IMPL_INSTANCE: SpdmSecretAsymSign =
    SpdmSecretAsymSign { sign_cb: asym_sign };

fn asym_sign(
    spdm_context: &SpdmContext,
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    match (base_hash_algo, base_asym_algo) {
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384) => {
            sign_ecdsa_asym_algo(
                spdm_context,
                &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                data,
            )
        }
        _ => None,
    }
}

fn sign_ecdsa_asym_algo(
    spdm_context: &SpdmContext,
    algorithm: &'static ring::signature::EcdsaSigningAlgorithm,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    let reader = &mut Reader::init(&spdm_context.app_context_data_buffer);
    let responder_app_context = SpdmAppContextData::read(reader)?;
    let private_key = &responder_app_context.private_key;
    let key_bytes = &private_key.data[..private_key.data_size as usize];
    let rng = ring::rand::SystemRandom::new();
    let key_pair: ring::signature::EcdsaKeyPair =
        ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, key_bytes, &rng).ok()?;
    let rng = ring::rand::SystemRandom::new();

    let signature = key_pair.sign(&rng, data).ok()?;
    let signature = signature.as_ref();

    let mut full_signature: [u8; SPDM_MAX_ASYM_SIG_SIZE] = [0u8; SPDM_MAX_ASYM_SIG_SIZE];
    if full_signature.len() < signature.len() || signature.len() > u16::MAX as usize {
        return None;
    }
    full_signature[..signature.len()].copy_from_slice(signature);

    Some(SpdmSignatureStruct {
        data_size: signature.len() as u16,
        data: full_signature,
    })
}
