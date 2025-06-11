// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub use policy::v2::collateral::{get_collateral_with_fmspc, Collateral};
pub use policy::PolicyError;
use policy::{v1::verify_policy, v2};

use crate::{
    config::{get_engine, get_policy},
    event_log::get_event_log,
};

pub fn authenticate_policy(
    is_src: bool,
    verified_report_local: &[u8],
    verified_report_peer: &[u8],
    event_log_peer: &[u8],
) -> Result<(), PolicyError> {
    let event_log = if let Some(event_log) = get_event_log() {
        event_log
    } else {
        return Err(PolicyError::InvalidEventLog);
    };

    let policy = if let Some(policy) = get_policy() {
        policy
    } else {
        return Err(PolicyError::InvalidParameter);
    };

    verify_policy(
        is_src,
        policy,
        verified_report_local,
        event_log,
        verified_report_peer,
        event_log_peer,
    )
}

pub fn authenticate_policy_v2(
    tcb_status: &str,
    verified_report_peer: &[u8],
    collateral: &Collateral<'_>,
) -> Result<(), PolicyError> {
    let policy = get_policy().ok_or(PolicyError::InvalidParameter)?;
    let engine_svn_map = get_engine().ok_or(PolicyError::InvalidParameter)?;

    v2::verify_policy(
        policy,
        engine_svn_map,
        verified_report_peer,
        tcb_status,
        &collateral,
    )
}
