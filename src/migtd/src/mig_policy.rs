// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(not(feature = "policy_v2"))]
pub use v1::*;

#[cfg(not(feature = "policy_v2"))]
mod v1 {
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
}

#[cfg(feature = "policy_v2")]
pub use v2::*;

#[cfg(feature = "policy_v2")]
mod v2 {
    use lazy_static::lazy_static;
    use policy::*;
    use spin::Once;

    lazy_static! {
        pub static ref VERIFIED_POLICY: Once<VerifiedPolicy<'static>> = Once::new();
    }

    /// Initialize the global verified policy once
    pub fn init_policy(policy_json: &'static [u8], cert_chain: &[u8]) -> Result<(), PolicyError> {
        VERIFIED_POLICY
            .try_call_once(|| {
                let raw = RawPolicyData::deserialize_from_json(policy_json)?;
                raw.verify(cert_chain, None, None)
            })
            .map(|_| ())
    }

    /// Get reference to the global verified policy
    /// Returns None if the policy hasn't been initialized yet
    pub fn get_verified_policy() -> Option<&'static VerifiedPolicy<'static>> {
        VERIFIED_POLICY.get()
    }
}
