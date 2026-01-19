// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{
    migration::MigtdMigrationInformation,
    spdm::{
        spdm_req::{
            send_and_receive_pub_key, send_and_receive_sdm_exchange_migration_info,
            send_and_receive_sdm_migration_attest_info,
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

pub async fn spdm_requester_transfer_msk(
    spdm_requester: &mut RequesterContext,
    mig_info: &MigtdMigrationInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
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

    Box::pin(send_and_receive_sdm_migration_attest_info(
        spdm_requester,
        session_id,
        #[cfg(feature = "policy_v2")]
        remote_policy,
    ))
    .await?;

    Box::pin(spdm_requester.send_receive_spdm_finish(Some(0xff), session_id)).await?;
    Box::pin(send_and_receive_sdm_exchange_migration_info(
        spdm_requester,
        mig_info,
        Some(session_id),
    ))
    .await?;
    Box::pin(spdm_requester.send_receive_spdm_end_session(session_id)).await?;

    Ok(())
}

pub async fn spdm_responder_transfer_msk<'a>(
    spdm_responder_ex: &mut ResponderContextEx<'a>,
    mig_info: &'a MigtdMigrationInformation,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<(), SpdmStatus> {
    #[cfg(not(feature = "policy_v2"))]
    let remote_policy = Vec::new();

    spdm_responder_ex.remote_policy = remote_policy;
    spdm_responder_ex.info = ResponderContextExInfo::MigrationInformation(mig_info);

    let spdm_responder = &mut spdm_responder_ex.responder_context;
    let mut writer = Writer::init(&mut spdm_responder.common.app_context_data_buffer);

    let responder_app_context = SpdmAppContextData {
        private_key: PrivateKeyDer::default(),
    };
    responder_app_context
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    Box::pin(rsp_handle_message(spdm_responder)).await?;
    spdm_responder.common.app_context_data_buffer.zeroize();

    Ok(())
}
