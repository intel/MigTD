// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use policy::verify_policy;
pub use policy::PolicyVerifyReulst;
use tdx_tdcall::tdreport;

use crate::{config::get_policy, event_log::get_event_log};

pub fn authenticate_policy(
    is_src: bool,
    td_report_peer: &[u8],
    event_log_peer: &[u8],
) -> PolicyVerifyReulst {
    let td_report = if let Ok(td_report) = tdreport::tdcall_report(&[0u8; 64]) {
        td_report
    } else {
        return PolicyVerifyReulst::FailGetReport;
    };

    let event_log = if let Some(event_log) = get_event_log() {
        event_log
    } else {
        return PolicyVerifyReulst::UnqulifiedEventLog;
    };

    let policy = if let Some(policy) = get_policy() {
        policy
    } else {
        return PolicyVerifyReulst::InvalidParameter;
    };

    verify_policy(
        is_src,
        policy,
        td_report.as_bytes(),
        event_log,
        td_report_peer,
        event_log_peer,
    )
}
