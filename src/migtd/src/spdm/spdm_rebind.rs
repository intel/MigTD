// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use crate::{
    migration::{rebinding::RebindingInfo, MigtdMigrationInformation},
    spdm::{
        spdm_req::{
            send_and_receive_pub_key, send_and_receive_sdm_rebind_attest_info,
            send_and_receive_sdm_rebind_info,
        },
        spdm_rsp::{rsp_handle_message, ResponderContextEx, ResponderContextExInfo},
        PrivateKeyDer, SpdmAppContextData,
    },
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use codec::{Codec, Writer};
use spdmlib::{
    error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL},
    protocol::SpdmMeasurementSummaryHashType,
    requester::RequesterContext,
};
use zeroize::Zeroize;

pub async fn spdm_requester_rebind_old(
    spdm_requester: &mut RequesterContext,
    rebind_info: &RebindingInfo,
    remote_policy: Vec<u8>,
) -> Result<(), SpdmStatus> {
    Box::pin(spdm_requester.send_receive_spdm_version()).await?;
    Box::pin(spdm_requester.send_receive_spdm_capability()).await?;
    Box::pin(spdm_requester.send_receive_spdm_algorithm()).await?;

    Box::pin(send_and_receive_pub_key(spdm_requester)).await?;
    let session_id = Box::pin(spdm_requester.send_receive_spdm_key_exchange(
        0xff,
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
    ))
    .await?;

    Box::pin(send_and_receive_sdm_rebind_attest_info(
        spdm_requester,
        rebind_info,
        session_id,
        remote_policy,
    ))
    .await?;

    Box::pin(spdm_requester.send_receive_spdm_finish(Some(0xff), session_id)).await?;

    Box::pin(send_and_receive_sdm_rebind_info(
        spdm_requester,
        rebind_info,
        Some(session_id),
    ))
    .await?;

    Box::pin(spdm_requester.send_receive_spdm_end_session(session_id)).await?;
    Ok(())
}

pub async fn spdm_responder_rebind_new<'a>(
    spdm_responder_ex: &mut ResponderContextEx<'a>,
    rebind_info: &'a RebindingInfo,
    remote_policy: Vec<u8>,
) -> Result<(), SpdmStatus> {
    spdm_responder_ex.remote_policy = remote_policy;
    spdm_responder_ex.info = ResponderContextExInfo::RebindInformation(rebind_info);

    let spdm_responder = &mut spdm_responder_ex.responder_context;
    let mut writer = Writer::init(&mut spdm_responder.common.app_context_data_buffer);

    let responder_app_context = SpdmAppContextData {
        migration_info: MigtdMigrationInformation::default(),
        private_key: PrivateKeyDer::default(),
    };
    responder_app_context
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    Box::pin(rsp_handle_message(spdm_responder)).await?;
    spdm_responder.common.app_context_data_buffer.zeroize();

    Ok(())
}
