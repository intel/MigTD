// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use policy::verify_policy;
pub use policy::PolicyError;

use crate::{config::get_policy, event_log::get_event_log};

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
