// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use crate::{
    migration::MigtdMigrationInformation,
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
pub async fn spdm_requester_rebind_old(
    spdm_requester: &mut RequesterContext,
    rebind_info: &MigtdMigrationInformation,
    peer_data: Vec<u8>,
) -> Result<(), SpdmStatus> {
    let guard = super::AppContextGuard {
        context: spdm_requester,
        common: |context| &mut context.common,
    };
    spdm_requester_rebind_old_inner(guard.context, rebind_info, peer_data).await
}

async fn spdm_requester_rebind_old_inner(
    spdm_requester: &mut RequesterContext,
    rebind_info: &MigtdMigrationInformation,
    peer_data: Vec<u8>,
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

    let result = async {
        Box::pin(send_and_receive_sdm_rebind_attest_info(
            spdm_requester,
            rebind_info,
            session_id,
            peer_data,
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
    .await;

    if result.is_err() {
        crate::spdm::teardown_session(&mut spdm_requester.common, session_id);
    }
    result
}

pub async fn spdm_responder_rebind_new<'a>(
    spdm_responder_ex: &mut ResponderContextEx<'a>,
    rebind_info: &'a MigtdMigrationInformation,
    peer_data: Vec<u8>,
) -> Result<(), SpdmStatus> {
    let guard = super::AppContextGuard {
        context: spdm_responder_ex,
        common: |context| &mut context.responder_context.common,
    };
    let spdm_responder_ex = &mut *guard.context;

    spdm_responder_ex.peer_data = peer_data;
    spdm_responder_ex.info = ResponderContextExInfo::RebindInformation(rebind_info);

    spdm_responder_rebind_new_inner(spdm_responder_ex).await
}

async fn spdm_responder_rebind_new_inner(
    spdm_responder_ex: &mut ResponderContextEx<'_>,
) -> Result<(), SpdmStatus> {
    let spdm_responder = &mut spdm_responder_ex.responder_context;
    let mut writer = Writer::init(&mut spdm_responder.common.app_context_data_buffer);

    let responder_app_context = SpdmAppContextData {
        migration_info: MigtdMigrationInformation::default(),
        private_key: PrivateKeyDer::default(),
    };
    responder_app_context
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    Box::pin(rsp_handle_message(spdm_responder)).await
}
