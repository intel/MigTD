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
    use alloc::ffi::CString;
    use alloc::{string::String, string::ToString, vec::Vec};
    use attestation::verify_quote_with_collaterals;
    use chrono::DateTime;
    use lazy_static::lazy_static;
    use policy::*;
    use spin::Once;

    use crate::config::get_policy_issuer_chain;

    lazy_static! {
        pub static ref LOCAL_TCB_INFO: Once<PolicyEvaluationInfo> = Once::new();
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

    /// Initialize the global local TCB info once
    pub fn init_tcb_info() -> Result<(), PolicyError> {
        // Store in the global static
        LOCAL_TCB_INFO
            .try_call_once(|| {
                let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
                let tdx_report = tdx_tdcall::tdreport::tdcall_report(&[0u8; 64])
                    .map_err(|_| PolicyError::GetTdxReport)?;
                let quote = attestation::get_quote(tdx_report.as_bytes())
                    .map_err(|_| PolicyError::QuoteGeneration)?;
                let (fmspc, suppl_data) = verify_quote(&quote, policy.get_collaterals())?;
                setup_evaluation_data(fmspc, &suppl_data, &policy, policy.get_collaterals())
            })
            .map(|_| ())
    }

    pub fn get_local_tcb_evaluation_info() -> Result<PolicyEvaluationInfo, PolicyError> {
        LOCAL_TCB_INFO
            .get()
            .map(|info| info.clone())
            .ok_or(PolicyError::InvalidParameter)
    }

    /// Get reference to the global verified policy
    /// Returns None if the policy hasn't been initialized yet
    pub fn get_verified_policy() -> Option<&'static VerifiedPolicy<'static>> {
        VERIFIED_POLICY.get()
    }

    pub fn authenticate_remote(
        is_src: bool,
        quote_peer: &[u8],
        policy_peer: &[u8],
        event_log_peer: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        let policy_issuer_chain = get_policy_issuer_chain().ok_or(PolicyError::InvalidParameter)?;
        if is_src {
            authenticate_migration_dest(
                quote_peer,
                event_log_peer,
                policy_peer,
                policy_issuer_chain,
            )
        } else {
            authenticate_migration_source(
                quote_peer,
                event_log_peer,
                policy_peer,
                policy_issuer_chain,
            )
        }
    }

    fn authenticate_migration_dest(
        quote_dst: &[u8],
        event_log_dst: &[u8],
        mig_policy_dst: &[u8],
        policy_issuer_chain: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        let (evaluation_data_dst, verified_policy_dst, suppl_data) = authenticate_remote_common(
            quote_dst,
            event_log_dst,
            mig_policy_dst,
            policy_issuer_chain,
        )?;
        let relative_reference = get_local_tcb_evaluation_info()?;
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        policy
            .policy_data
            .evaluate_policy_common(&evaluation_data_dst, &relative_reference)?;
        policy
            .policy_data
            .evaluate_policy_forward(&evaluation_data_dst, &relative_reference)?;

        // Verify the destination's policy against local policy
        verified_policy_dst
            .policy_data
            .evaluate_against_policy(&policy.policy_data)?;

        Ok(suppl_data)
    }

    fn authenticate_migration_source(
        quote_src: &[u8],
        event_log_src: &[u8],
        mig_policy_src: &[u8],
        policy_issuer_chain: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        let (evaluation_data_src, _verified_policy_src, suppl_data) = authenticate_remote_common(
            quote_src,
            event_log_src,
            mig_policy_src,
            policy_issuer_chain,
        )?;
        let relative_reference = get_local_tcb_evaluation_info()?;
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        policy
            .policy_data
            .evaluate_policy_backward(&evaluation_data_src, &relative_reference)?;

        Ok(suppl_data)
    }

    fn authenticate_remote_common<'p>(
        quote: &[u8],
        event_log: &[u8],
        mig_policy: &'p [u8],
        policy_issuer_chain: &[u8],
    ) -> Result<(PolicyEvaluationInfo, VerifiedPolicy<'p>, Vec<u8>), PolicyError> {
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        let unverified_policy = RawPolicyData::deserialize_from_json(mig_policy)?;

        // 1. Verify quote & get supplemental data
        let (fmspc, suppl_data) = verify_quote(quote, policy.get_collaterals())
            .map_err(|_| PolicyError::QuoteVerification)?;

        // 2. Verify the event log integrity
        let _ = verify_event_log(
            event_log,
            suppl_data
                .get(..REPORT_DATA_SIZE)
                .ok_or(PolicyError::QuoteVerification)?,
        )?;

        // 3. Verify the integrity of migration policy, with the issuer chains from local policy
        let verified_policy = unverified_policy.verify(
            policy_issuer_chain,
            Some(policy.servtd_identity_issuer_chain.as_bytes()),
            Some(policy.servtd_tcb_mapping_issuer_chain.as_bytes()),
        )?;

        // 4. Check the integrity of the policy with its event log
        check_policy_integrity(mig_policy, event_log)?;

        // 5. Get TCB evaluation info from the collaterals
        let evaluation_data = setup_evaluation_data(
            fmspc,
            &suppl_data,
            &verified_policy,
            policy.get_collaterals(),
        )?;

        Ok((evaluation_data, verified_policy, suppl_data))
    }

    fn verify_quote(
        quote: &[u8],
        collaterals: &Collaterals,
    ) -> Result<([u8; 6], Vec<u8>), PolicyError> {
        let fmspc = get_fmspc_from_quote(&quote)?;
        let collateral = get_collateral_with_fmspc(&fmspc, collaterals)?;
        let collateral_cstr = convert_collateral_to_cstring(&collateral)?;
        let suppl_data = verify_quote_with_collaterals(&quote, collateral_cstr)
            .map_err(|_| PolicyError::QuoteVerification)?;

        Ok((fmspc, suppl_data))
    }

    fn setup_evaluation_data(
        fmspc: [u8; 6],
        suppl_data: &[u8],
        policy: &VerifiedPolicy,
        collaterals: &Collaterals,
    ) -> Result<PolicyEvaluationInfo, PolicyError> {
        let (tcb_date, tcb_status) = get_tcb_date_and_status_from_suppl_data(&suppl_data)?;
        let collateral = get_collateral_with_fmspc(&fmspc, collaterals)?;
        let tcb_evaluation_number = get_tcb_evaluation_number_from_collateral(&collateral)?;
        let report_value = Report::new(
            suppl_data
                .get(..REPORT_DATA_SIZE)
                .ok_or(PolicyError::InvalidParameter)?,
        )?;

        let migtd_svn = policy
            .servtd_tcb_mapping
            .get_engine_svn_by_report(&report_value);

        let migtd_tcb = migtd_svn.and_then(|svn| policy.servtd_identity.get_tcb_level_by_svn(svn));

        Ok(PolicyEvaluationInfo {
            tcb_date: Some(tcb_date.to_string()),
            tcb_status: Some(tcb_status.as_str().to_string()),
            tcb_evaluation_number: Some(tcb_evaluation_number),
            fmspc: Some(fmspc),
            migtd_tcb_date: migtd_tcb.map(|tcb| tcb.tcb_date.clone()),
            migtd_tcb_status: migtd_tcb.map(|tcb| tcb.tcb_status.clone()),
        })
    }

    fn get_tcb_date_and_status_from_suppl_data(
        suppl_data: &[u8],
    ) -> Result<(String, String), PolicyError> {
        if suppl_data.len() < REPORT_DATA_SIZE + 40 {
            panic!("Supplemental data too short");
        }
        let data = &suppl_data[REPORT_DATA_SIZE..REPORT_DATA_SIZE + 40];

        let tcb_date_bytes = &data[0..8];
        let tcb_status_bytes = &data[8..40];

        let tcb_date = u64::from_le_bytes(tcb_date_bytes.try_into().unwrap());
        let tcb_status = slice_to_string_null_terminated(tcb_status_bytes)?;

        Ok((unix_to_iso8601(tcb_date)?, tcb_status))
    }

    fn unix_to_iso8601(unix_timestamp: u64) -> Result<String, PolicyError> {
        DateTime::from_timestamp(unix_timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .ok_or(PolicyError::InvalidParameter)
    }

    fn slice_to_string_null_terminated(slice: &[u8]) -> Result<String, PolicyError> {
        // Find the null terminator or use the entire slice
        let end_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        let str_bytes = &slice[..end_pos];

        // Convert to String
        Ok(String::from_utf8(str_bytes.to_vec()).unwrap())
    }

    fn convert_collateral_to_cstring(
        collateral: &Collateral,
    ) -> Result<attestation::Collateral, PolicyError> {
        // Helper closure to convert &str to CString and map errors
        let cstring = |s: &str| -> Result<CString, PolicyError> {
            CString::new(s).map_err(|_| PolicyError::InvalidCollateral)
        };

        Ok(attestation::Collateral {
            major_version: collateral.major_version,
            minor_version: collateral.minor_version,
            tee_type: collateral.tee_type,
            pck_crl_issuer_chain: cstring(collateral.pck_crl_issuer_chain.as_str())?,
            root_ca_crl: cstring(collateral.root_ca_crl.as_str())?,
            pck_crl: cstring(collateral.pck_crl.as_str())?,
            tcb_info_issuer_chain: cstring(collateral.tcb_info_issuer_chain.as_str())?,
            tcb_info: cstring(collateral.tcb_info.as_str())?,
            qe_identity_issuer_chain: cstring(collateral.qe_identity_issuer_chain.as_str())?,
            qe_identity: cstring(collateral.qe_identity.as_str())?,
        })
    }

    #[test]
    fn test_unix_to_iso8601() {
        let timestamp = 1704067200; // Corresponds to 2024-01-01T00:00:00Z
        let iso_date = unix_to_iso8601(timestamp).unwrap();
        assert_eq!(iso_date, "2024-01-01T00:00:00Z");
    }
}
