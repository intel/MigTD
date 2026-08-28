// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crypto::SHA384_DIGEST_SIZE;
pub use policy::{PolicyError, Report, REPORT_DATA_SIZE};

#[cfg(not(feature = "policy_v2"))]
pub use v1::*;

#[cfg(not(feature = "policy_v2"))]
mod v1 {
    use policy::verify_policy;

    use super::{get_rtmrs_from_suppl_data, PolicyError};
    use crate::{
        config::get_policy,
        event_log::{get_event_log, parse_events, verify_event_log},
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

        verify_event_log(
            event_log_peer,
            &get_rtmrs_from_suppl_data(verified_report_peer)?,
        )
        .map_err(|_| PolicyError::InvalidEventLog)?;
        let event_log = parse_events(event_log).ok_or(PolicyError::InvalidParameter)?;
        let event_log_peer = parse_events(event_log_peer).ok_or(PolicyError::InvalidParameter)?;

        verify_policy(
            is_src,
            policy,
            verified_report_local,
            &event_log,
            verified_report_peer,
            &event_log_peer,
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
    use crypto::{crl::get_crl_number, hash::digest_sha384, pem_cert_to_der, SHA384_DIGEST_SIZE};
    use lazy_static::lazy_static;
    use policy::*;
    use spin::Once;
    use tdx_tdcall::tdreport::{tdcall_verify_report, TdInfo, TdxReport};

    use crate::event_log::{parse_events, verify_event_log};
    use crate::mig_policy::get_rtmrs_from_suppl_data;
    use crate::migration::pre_session_data::LogErr;
    use crate::migration::servtd_ext::ServtdExt;

    const SERVTD_ATTR_IGNORE_ATTRIBUTES: u64 = 0x1_0000_0000;
    const SERVTD_ATTR_IGNORE_XFAM: u64 = 0x2_0000_0000;
    const SERVTD_ATTR_IGNORE_MRTD: u64 = 0x4_0000_0000;
    const SERVTD_ATTR_IGNORE_MRCONFIGID: u64 = 0x8_0000_0000;
    const SERVTD_ATTR_IGNORE_MROWNER: u64 = 0x10_0000_0000;
    const SERVTD_ATTR_IGNORE_MROWNERCONFIG: u64 = 0x20_0000_0000;
    const SERVTD_ATTR_IGNORE_RTMR0: u64 = 0x40_0000_0000;
    const SERVTD_ATTR_IGNORE_RTMR1: u64 = 0x80_0000_0000;
    const SERVTD_ATTR_IGNORE_RTMR2: u64 = 0x100_0000_0000;
    const SERVTD_ATTR_IGNORE_RTMR3: u64 = 0x200_0000_0000;

    /// Compute the outer `tdinfo_hash` (attr=0) for the TD described by a
    /// `TdInfo` returned by `TDG.MR.REPORT`. This is the canonical lookup key
    /// for `servtd_tcb_mapping` after the TCB-mapping redesign.
    fn tdinfo_hash_from_td_info(td: &TdInfo) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
        policy::compute_tdinfo_hash_from_fields(
            &td.attributes,
            &td.xfam,
            &td.mrtd,
            &td.mrconfig_id,
            &td.mrowner,
            &td.mrownerconfig,
            &td.rtmr0,
            &td.rtmr1,
            &td.rtmr2,
            &td.rtmr3,
        )
    }

    lazy_static! {
        pub static ref VERIFIED_POLICY: Once<VerifiedPolicy<'static>> = Once::new();
    }

    /// Initialize the global verified policy once
    pub fn init_policy(
        policy_json: &'static [u8],
        cert_chain: &[u8],
    ) -> Result<String, PolicyError> {
        let raw = RawPolicyData::deserialize_from_json(policy_json)?;

        // Get the root CA from collaterals and set it for quote verification
        #[cfg_attr(not(feature = "servtd_corim"), allow(unused_mut))]
        let mut verified_policy = raw.verify(cert_chain)?;

        // Attach the optional CoRIM hash endorsement enrolled in the CFV. Its
        // COSE signer chain is bound to the SAME RTMR1 signer anchor as the CFV
        // policy issuer chain, so a CoRIM signed under a different root cert or
        // leaf signer EKU fails closed. The CoRIM is NOT measured
        // (`config::get_servtd_corim` is never read by `do_measurements`), so
        // enrolling it does not change the ServTD/`tdinfo_hash`.
        // `now_epoch_secs = 0`: MigTD has no wall clock, so the producer must
        // not set CWT `nbf`/`exp` on the CoRIM.
        #[cfg(feature = "servtd_corim")]
        if let Some(cose) = crate::config::get_servtd_corim() {
            let anchor = resolve_signer_anchor(cert_chain)?;
            let corim = ServtdCorim::decode_signed(cose, 0, &anchor)?;
            verified_policy.set_servtd_corim(corim);
        }

        let root_ca_der = pem_cert_to_der(verified_policy.get_collaterals().root_ca.as_bytes())
            .map_err(|_| PolicyError::InvalidCollateral)?;
        attestation::root_ca::set_ca(root_ca_der.as_ref())
            .map_err(|_| PolicyError::InvalidCollateral)?;

        VERIFIED_POLICY
            .try_call_once(|| Ok(verified_policy))
            .map(|p| p.get_version().to_string())
    }

    /// Generate a fresh local TCB evaluation info on demand by creating a
    /// quote and verifying it against the policy collaterals.
    pub fn get_local_tcb_evaluation_info() -> Result<PolicyEvaluationInfo, PolicyError> {
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        let (quote, _report) =
            crate::quote::get_quote_with_retry(&[0u8; 64]).map_err(|err| match err {
                crate::quote::QuoteError::ReportGenerationFailed => PolicyError::GetTdxReport,
                _ => PolicyError::QuoteGeneration,
            })?;
        let (fmspc, suppl_data) = verify_quote(&quote, policy.get_collaterals())?;
        setup_evaluation_data(fmspc, &suppl_data, policy, policy.get_collaterals())
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
        let (policy_peer, peer_issuer_chain) =
            crate::migration::pre_session_data::decode_peer_data(policy_peer)
                .ok_or(PolicyError::InvalidParameter)?;
        if is_src {
            authenticate_migration_dest(quote_peer, event_log_peer, policy_peer, peer_issuer_chain)
        } else {
            authenticate_migration_source(
                quote_peer,
                event_log_peer,
                policy_peer,
                peer_issuer_chain,
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

        policy.policy_data.evaluate_policy_common(
            &evaluation_data_dst,
            &relative_reference,
            false,
        )?;
        policy.policy_data.evaluate_policy_forward(
            &evaluation_data_dst,
            &relative_reference,
            false,
        )?;

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

        policy.policy_data.evaluate_policy_common(
            &evaluation_data_src,
            &relative_reference,
            false,
        )?;
        policy.policy_data.evaluate_policy_backward(
            &evaluation_data_src,
            &relative_reference,
            false,
        )?;

        Ok(suppl_data)
    }

    // Authenticate the migtd-new from migtd-old side
    pub fn authenticate_rebinding_new(
        tdreport_dst: &[u8],
        event_log_dst: &[u8],
        mig_policy_dst: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        let (mig_policy_dst, peer_issuer_chain) =
            crate::migration::pre_session_data::decode_peer_data(mig_policy_dst)
                .ok_or(PolicyError::InvalidParameter)?;
        let (evaluation_data_dst, verified_policy_dst, tdx_report) = authenticate_rebinding_common(
            tdreport_dst,
            event_log_dst,
            mig_policy_dst,
            peer_issuer_chain,
        )?;
        let relative_reference = get_local_tcb_evaluation_info()?;
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        policy.policy_data.evaluate_policy_common(
            &evaluation_data_dst,
            &relative_reference,
            true,
        )?;
        policy.policy_data.evaluate_policy_forward(
            &evaluation_data_dst,
            &relative_reference,
            true,
        )?;

        // Verify the destination's policy against local policy
        verified_policy_dst
            .policy_data
            .evaluate_against_policy(&policy.policy_data)?;

        Ok(tdx_report.as_bytes().to_vec())
    }

    // Authenticate the migtd-old from migtd-new side
    // Per GHCI 1.5: init_tdinfo is a TDINFO_STRUCT (not full TDREPORT),
    // and there is no separate init_policy JSON blob.
    pub fn authenticate_rebinding_old(
        tdreport_src: &[u8],
        event_log_src: &[u8],
        mig_policy_src: &[u8],
        init_tdinfo: &[u8],
        servtd_ext_src: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        let (mig_policy_src, peer_issuer_chain) =
            crate::migration::pre_session_data::decode_peer_data(mig_policy_src)
                .ok_or(PolicyError::InvalidParameter)?;
        // Verify quote src / event log src / policy src
        let (evaluation_data_src, _verified_policy_src, tdx_report) =
            authenticate_rebinding_common(
                tdreport_src,
                event_log_src,
                mig_policy_src,
                peer_issuer_chain,
            )?;
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        // When SERVTD_EXT is not supported (empty wire elements), skip init_tdinfo
        // verification — it cannot be verified without init_servtd_info_hash.
        // Fall back to standard policy evaluation using current tdreport data.
        if servtd_ext_src.is_empty() || init_tdinfo.is_empty() {
            log::info!("No SERVTD_EXT/init_tdinfo — skipping init verification in rebind-old\n");
            let relative_reference = get_local_tcb_evaluation_info()?;
            policy.policy_data.evaluate_policy_common(
                &evaluation_data_src,
                &relative_reference,
                true,
            )?;
            policy.policy_data.evaluate_policy_backward(
                &evaluation_data_src,
                &relative_reference,
                true,
            )?;
            return Ok(tdx_report.as_bytes().to_vec());
        }

        // Per GHCI 1.5: cross-check the peer's wire-claimed init TDINFO against
        // the peer's verified TDREPORT — init policy signer and init SVN must
        // be consistent with the peer's current self-report.
        verify_peer_init_tdinfo_against_owner(
            init_tdinfo,
            &tdx_report.td_info.mrowner,
            &tdx_report.td_info.mrownerconfig,
        )?;

        // Verify the init tdinfo against servtd_ext hash
        let servtd_ext_src_obj =
            ServtdExt::read_from_bytes(servtd_ext_src).ok_or(PolicyError::InvalidParameter)?;
        let init_td_info = verify_init_tdinfo(init_tdinfo, &servtd_ext_src_obj)?;
        let _engine_svn = policy
            .servtd_tcb_mapping
            .get_engine_svn_by_measurements(&Measurements::new_from_bytes(
                &init_td_info.mrtd,
                &init_td_info.rtmr0,
                &init_td_info.rtmr1,
                Some(&init_td_info.rtmr2),
                Some(&init_td_info.rtmr3),
            ))
            .ok_or(PolicyError::SvnMismatch)?;

        // If backward policy exists, evaluate the migration src based on it.
        let relative_reference = get_local_tcb_evaluation_info()?;
        policy.policy_data.evaluate_policy_backward(
            &evaluation_data_src,
            &relative_reference,
            true,
        )?;

        Ok(tdx_report.as_bytes().to_vec())
    }

    fn authenticate_remote_common<'p>(
        quote: &[u8],
        event_log: &[u8],
        mig_policy: &'p [u8],
        policy_issuer_chain: &[u8],
    ) -> Result<(PolicyEvaluationInfo, VerifiedPolicy<'p>, Vec<u8>), PolicyError> {
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        // 1. Verify quote & get supplemental data
        let (fmspc, suppl_data) = verify_quote(quote, policy.get_collaterals())
            .map_err(|_| PolicyError::QuoteVerification)?;

        // 2. Verify the signature of the provided policy and the integrity of the event log
        let verified_policy = verify_policy_and_event_log(
            event_log,
            mig_policy,
            policy_issuer_chain,
            &get_rtmrs_from_suppl_data(&suppl_data)?,
        )?;

        // 3. Get TCB evaluation info from the collaterals
        let evaluation_data = setup_evaluation_data(
            fmspc,
            &suppl_data,
            &verified_policy,
            policy.get_collaterals(),
        )?;

        Ok((evaluation_data, verified_policy, suppl_data))
    }

    fn authenticate_rebinding_common<'p>(
        tdreport: &[u8],
        event_log: &[u8],
        mig_policy: &'p [u8],
        policy_issuer_chain: &[u8],
    ) -> Result<(PolicyEvaluationInfo, VerifiedPolicy<'p>, TdxReport), PolicyError> {
        // 1. Verify quote & get supplemental data
        let tdreport_verified = verify_tdreport(tdreport)?;

        // 2. Verify the signature of the provided policy and the integrity of the event log
        let verified_policy = verify_policy_and_event_log(
            event_log,
            mig_policy,
            policy_issuer_chain,
            &get_rtmrs_from_tdreport(&tdreport_verified)?,
        )?;

        // 3. Get TCB evaluation info from the collaterals
        let evaluation_data =
            setup_evaluation_data_with_tdreport(&tdreport_verified, &verified_policy)?;

        Ok((evaluation_data, verified_policy, tdreport_verified))
    }

    fn get_rtmrs_from_tdreport(
        td_report: &TdxReport,
    ) -> Result<[[u8; SHA384_DIGEST_SIZE]; 4], PolicyError> {
        let mut rtmrs = [[0u8; SHA384_DIGEST_SIZE]; 4];
        rtmrs[0].copy_from_slice(&td_report.td_info.rtmr0);
        rtmrs[1].copy_from_slice(&td_report.td_info.rtmr1);
        rtmrs[2].copy_from_slice(&td_report.td_info.rtmr2);
        rtmrs[3].copy_from_slice(&td_report.td_info.rtmr3);

        Ok(rtmrs)
    }

    /// Verify a peer's migration policy and event log, then validate peer cert chains.
    fn verify_policy_and_event_log<'p>(
        event_log: &[u8],
        mig_policy: &'p [u8],
        policy_issuer_chain: &[u8],
        rtmrs: &[[u8; SHA384_DIGEST_SIZE]; 4],
    ) -> Result<VerifiedPolicy<'p>, PolicyError> {
        let unverified_policy = RawPolicyData::deserialize_from_json(mig_policy)?;

        // 1. Verify the event log integrity
        verify_event_log(event_log, rtmrs).map_err(|_| PolicyError::InvalidEventLog)?;

        // 2. Verify the peer policy using the peer's issuer chain
        let verified_policy = unverified_policy.verify(policy_issuer_chain)?;

        // 3. Validate that the peer's signer matches ours by comparing the
        //    RTMR1 signer anchor (root CA + leaf signer EKU) instead of the
        //    full policy issuer chain PEM. This supports the anchor-only (CoRIM)
        //    enrollment form, which carries no PEM. `verify()` has already
        //    bound the peer's embedded mapping chain to `signer_anchor`.
        let local_policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        if local_policy.signer_anchor != verified_policy.signer_anchor {
            return Err(PolicyError::PeerCertChainValidation);
        }

        // Cross-check the JSON mapping issuer chains when both sides ship one
        // (defense-in-depth; the signer_anchor equality above already binds the
        // signer). Absent on both sides (CoRIM-only) is fine; one-sided fails.
        match (
            local_policy.servtd_tcb_mapping_issuer_chain.as_deref(),
            verified_policy.servtd_tcb_mapping_issuer_chain.as_deref(),
        ) {
            (Some(local_mc), Some(peer_mc)) => {
                crypto::validate_peer_cert_chain(local_mc.as_bytes(), peer_mc.as_bytes())
                    .log_err("Peer tcb mapping cert chain validation")
                    .map_err(|_| PolicyError::PeerCertChainValidation)?;
            }
            (None, None) => {}
            _ => return Err(PolicyError::PeerCertChainValidation),
        }

        // Validate the peer's optional TD Identity issuer chain against ours
        // when both sides ship one. If exactly one side has it, the chains do
        // not match and it fails closed.
        match (
            local_policy.servtd_identity_issuer_chain.as_deref(),
            verified_policy.servtd_identity_issuer_chain.as_deref(),
        ) {
            (Some(local_identity_chain), Some(peer_identity_chain)) => {
                crypto::validate_peer_cert_chain(
                    local_identity_chain.as_bytes(),
                    peer_identity_chain.as_bytes(),
                )
                .log_err("Peer td identity cert chain validation")
                .map_err(|_| PolicyError::PeerCertChainValidation)?;
            }
            (None, None) => {}
            _ => return Err(PolicyError::PeerCertChainValidation),
        }

        // 3b. Cross-check the peer's signer chain against OUR locally-trusted
        //     CRL: a peer could ship a laundered (revocation-free) CRL of its
        //     own, so the authoritative revocation list is the local one.
        //     Fail-closed.
        if let Some(servtd_crl) = local_policy.servtd_crl.as_deref() {
            if let Some(peer_mc) = verified_policy.servtd_tcb_mapping_issuer_chain.as_deref() {
                crypto::verify_signer_chain_not_revoked(peer_mc.as_bytes(), servtd_crl.as_bytes())
                    .log_err("Peer tcb mapping signer revocation check")
                    .map_err(|_| PolicyError::SignerRevoked)?;
            }
            if let Some(peer_identity_chain) =
                verified_policy.servtd_identity_issuer_chain.as_deref()
            {
                crypto::verify_signer_chain_not_revoked(
                    peer_identity_chain.as_bytes(),
                    servtd_crl.as_bytes(),
                )
                .log_err("Peer td identity signer revocation check")
                .map_err(|_| PolicyError::SignerRevoked)?;
            }
        }

        // 4. Check the integrity of the policy with its event log
        let events = parse_events(event_log).ok_or(PolicyError::InvalidEventLog)?;
        check_policy_integrity(mig_policy, &events)?;

        Ok(verified_policy)
    }

    fn verify_quote(
        quote: &[u8],
        collaterals: &Collaterals,
    ) -> Result<([u8; 6], Vec<u8>), PolicyError> {
        let fmspc = get_fmspc_from_quote(quote)?;
        let collateral = get_collateral_with_fmspc(&fmspc, collaterals)?;
        let collateral_cstr = convert_collateral_to_cstring(&collateral)?;
        let suppl_data = verify_quote_with_collaterals(quote, collateral_cstr)
            .map_err(|_| PolicyError::QuoteVerification)?;

        Ok((fmspc, suppl_data))
    }

    fn verify_tdreport(tdreport: &[u8]) -> Result<TdxReport, PolicyError> {
        let tdx_report =
            TdxReport::read_from_bytes(tdreport).ok_or(PolicyError::InvalidTdReport)?;

        // Verify the REPORTMACSTRUCT
        tdcall_verify_report(tdx_report.report_mac.as_bytes())
            .map_err(|_| PolicyError::TdReportVerification)?;

        // Verify the TDINFO_STRUCT and TEE_TCB_INFO
        let tdinfo_hash = digest_sha384(tdx_report.td_info.as_bytes())
            .map_err(|_| PolicyError::HashCalculation)?;
        let tee_tcb_info_hash = digest_sha384(tdx_report.tee_tcb_info.as_bytes())
            .map_err(|_| PolicyError::HashCalculation)?;

        let mut validity = true;
        validity &= &tdx_report.report_mac.tee_tcb_info_hash == tee_tcb_info_hash.as_slice();
        validity &= tdx_report.report_mac.tee_info_hash != [0; 48];
        validity &= &tdx_report.report_mac.tee_info_hash == tdinfo_hash.as_slice();

        if !validity {
            return Err(PolicyError::InvalidTdReport);
        }
        Ok(tdx_report)
    }

    /// Per GHCI 1.5: verifies TDINFO_STRUCT integrity against ServtdExt info hash.
    ///
    /// Parses the TDINFO bytes, applies IGNORE masks from `servtd_attr`, computes
    /// `SHA384(masked_tdinfo)`, and compares to `init_servtd_info_hash`.
    /// Returns the parsed TdInfo on success.
    ///
    /// This function is only called when SERVTD_EXT is supported (the sender
    /// gates on TDCS.ATTRIBUTES bit 17 before sending init_tdinfo).
    fn verify_servtd_info_hash(
        tdinfo_bytes: &[u8],
        servtd_attr: u64,
        init_servtd_info_hash: &[u8],
    ) -> Result<TdInfo, PolicyError> {
        if tdinfo_bytes.len() < size_of::<TdInfo>() {
            return Err(PolicyError::InvalidParameter);
        }

        // Parse TdInfo directly from bytes
        let mut td_info = {
            let mut uninit = core::mem::MaybeUninit::<TdInfo>::uninit();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    tdinfo_bytes.as_ptr(),
                    uninit.as_mut_ptr() as *mut u8,
                    size_of::<TdInfo>(),
                );
                uninit.assume_init()
            }
        };

        if (servtd_attr & SERVTD_ATTR_IGNORE_ATTRIBUTES) != 0 {
            td_info.attributes.fill(0);
        }
        if (servtd_attr & SERVTD_ATTR_IGNORE_XFAM) != 0 {
            td_info.xfam.fill(0);
        }
        if (servtd_attr & SERVTD_ATTR_IGNORE_MRTD) != 0 {
            td_info.mrtd.fill(0);
        }
        if (servtd_attr & SERVTD_ATTR_IGNORE_MRCONFIGID) != 0 {
            td_info.mrconfig_id.fill(0);
        }
        if (servtd_attr & SERVTD_ATTR_IGNORE_MROWNER) != 0 {
            td_info.mrowner.fill(0);
        }
        if (servtd_attr & SERVTD_ATTR_IGNORE_MROWNERCONFIG) != 0 {
            td_info.mrownerconfig.fill(0);
        }
        if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR0) != 0 {
            td_info.rtmr0.fill(0);
        }
        if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR1) != 0 {
            td_info.rtmr1.fill(0);
        }
        if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR2) != 0 {
            td_info.rtmr2.fill(0);
        }
        if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR3) != 0 {
            td_info.rtmr3.fill(0);
        }

        let info_hash =
            digest_sha384(td_info.as_bytes()).map_err(|_| PolicyError::HashCalculation)?;

        if info_hash.as_slice() != init_servtd_info_hash {
            log::error!("verify_servtd_info_hash: HASH MISMATCH\n");
            return Err(PolicyError::InvalidTdReport);
        }

        Ok(td_info)
    }

    /// Per GHCI 1.5: verifies TDINFO_STRUCT against servtd_ext info hash
    fn verify_init_tdinfo(
        init_tdinfo: &[u8],
        servtd_ext: &ServtdExt,
    ) -> Result<TdInfo, PolicyError> {
        verify_servtd_info_hash(
            init_tdinfo,
            u64::from_le_bytes(servtd_ext.init_attr),
            &servtd_ext.init_servtd_info_hash,
        )
    }

    /// `getengineinfo` measurement scope: the design guide classifies a MigTD
    /// engine by `mrtd||rtmr[0-1]` only.
    fn engine_measurements(mrtd: &[u8], rtmr0: &[u8], rtmr1: &[u8]) -> Measurements {
        Measurements::new_from_bytes(mrtd, rtmr0, rtmr1, None, None)
    }

    fn engine_measurements_of(td_info: &TdInfo) -> Measurements {
        engine_measurements(&td_info.mrtd, &td_info.rtmr0, &td_info.rtmr1)
    }

    fn get_rtmrs_from_tdinfo(
        td_info: &TdInfo,
    ) -> Result<[[u8; SHA384_DIGEST_SIZE]; 4], PolicyError> {
        let mut rtmrs = [[0u8; SHA384_DIGEST_SIZE]; 4];
        rtmrs[0].copy_from_slice(&td_info.rtmr0);
        rtmrs[1].copy_from_slice(&td_info.rtmr1);
        rtmrs[2].copy_from_slice(&td_info.rtmr2);
        rtmrs[3].copy_from_slice(&td_info.rtmr3);
        Ok(rtmrs)
    }

    /// Compute the servtd signer CRL number from the verified policy, if a
    /// signer CRL is present (`servtdCollateral.servtdCrl`). `None` when it is
    /// absent (backward compatibility); `Some(n)` feeds the `servtd_crl_num`
    /// anti-rollback floor.
    fn servtd_crl_num_from_policy(policy: &VerifiedPolicy) -> Result<Option<u32>, PolicyError> {
        policy
            .servtd_crl
            .as_deref()
            .map(|crl| get_crl_number(crl.as_bytes()))
            .transpose()
            .map_err(|_| PolicyError::InvalidCollateral)
    }

    fn setup_evaluation_data(
        fmspc: [u8; 6],
        suppl_data: &[u8],
        policy: &VerifiedPolicy,
        collaterals: &Collaterals,
    ) -> Result<PolicyEvaluationInfo, PolicyError> {
        let (tcb_date, tcb_status) = get_tcb_date_and_status_from_suppl_data(suppl_data)?;
        let collateral = get_collateral_with_fmspc(&fmspc, collaterals)?;
        let tcb_evaluation_number = get_tcb_evaluation_number_from_collateral(&collateral)?;
        let report_value = Report::new(suppl_data)?;

        let migtd = policy.servtd_lookup_by_report(&report_value);
        let pck_crl_num = get_crl_number(collaterals.pck_crl.as_bytes())
            .map_err(|_| PolicyError::InvalidCollateral)?;
        let root_ca_crl_num = get_crl_number(collaterals.root_ca_crl.as_bytes())
            .map_err(|_| PolicyError::InvalidCollateral)?;

        Ok(PolicyEvaluationInfo {
            tee_tcb_svn: None,
            tcb_date: Some(tcb_date.to_string()),
            tcb_status: Some(tcb_status.as_str().to_string()),
            tcb_evaluation_number: Some(tcb_evaluation_number),
            fmspc: Some(fmspc),
            migtd_isvsvn: migtd.as_ref().map(|m| m.isvsvn),
            migtd_tcb_status: migtd.as_ref().and_then(|m| m.tcb_status.clone()),
            migtd_tcb_date: migtd.as_ref().and_then(|m| m.tcb_date.clone()),
            pck_crl_num: Some(pck_crl_num),
            root_ca_crl_num: Some(root_ca_crl_num),
            servtd_crl_num: servtd_crl_num_from_policy(policy)?,
        })
    }

    fn setup_evaluation_data_with_tdreport(
        tdreport: &TdxReport,
        policy: &VerifiedPolicy,
    ) -> Result<PolicyEvaluationInfo, PolicyError> {
        let tdinfo_hash = tdinfo_hash_from_td_info(&tdreport.td_info)?;
        let migtd = policy.servtd_lookup_by_tdinfo_hash(&tdinfo_hash);

        Ok(PolicyEvaluationInfo {
            tee_tcb_svn: Some(tdreport.tee_tcb_info.tee_tcb_svn),
            tcb_date: None,
            tcb_status: None,
            tcb_evaluation_number: None,
            fmspc: None,
            migtd_isvsvn: migtd.as_ref().map(|m| m.isvsvn),
            migtd_tcb_status: migtd.as_ref().and_then(|m| m.tcb_status.clone()),
            migtd_tcb_date: migtd.as_ref().and_then(|m| m.tcb_date.clone()),
            pck_crl_num: None,
            root_ca_crl_num: None,
            servtd_crl_num: servtd_crl_num_from_policy(policy)?,
        })
    }

    fn get_tcb_date_and_status_from_suppl_data(
        suppl_data: &[u8],
    ) -> Result<(String, String), PolicyError> {
        if suppl_data.len() < REPORT_DATA_SIZE {
            return Err(PolicyError::InvalidParameter);
        }

        let tcb_date_bytes = &suppl_data[Report::R_TCB_DATE];
        let tcb_status_bytes = &suppl_data[Report::R_TCB_STATUS];

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
        String::from_utf8(str_bytes.to_vec()).map_err(|_| PolicyError::InvalidParameter)
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

    /// Per GHCI 1.5: Verify that own TDINFO.MROWNERCONFIG matches policy SVN.
    ///
    /// NOTE: the `MROWNER == SHA384(policy-signer public key)` binding has been
    /// **deprecated** — the policy-signer trust root is now the RTMR1 signer
    /// anchor, and the CoRIM-only enrollment carries no signer public key in
    /// the image. Only the MROWNERCONFIG (policy SVN) binding is enforced.
    /// Must be called at MigTD startup to ensure VMM correctly provisioned the TD.
    pub fn verify_own_tdinfo() -> Result<(), PolicyError> {
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        let policy_svn = policy.policy_data.get_policy_svn();

        // Get own TDINFO from TDReport
        let tdx_report = tdx_tdcall::tdreport::tdcall_report(&[0u8; 64])
            .map_err(|_| PolicyError::GetTdxReport)?;
        let td_info = &tdx_report.td_info;

        // Verify MROWNERCONFIG == policy_svn (stored as little-endian u32 in first 4 bytes,
        // remaining 44 bytes must be zero)
        let mut expected_mrownerconfig = [0u8; SHA384_DIGEST_SIZE];
        expected_mrownerconfig[..4].copy_from_slice(&policy_svn.to_le_bytes());
        if td_info.mrownerconfig != expected_mrownerconfig {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }

    /// Per GHCI 1.5: Verify initMigtdData.MROWNERCONFIG <= own policy SVN.
    ///
    /// NOTE: the `MROWNER == own policy-signer key hash` binding has been
    /// **deprecated** (see [`verify_own_tdinfo`]); only the MROWNERCONFIG
    /// (policy SVN floor) binding is enforced.
    pub fn verify_init_migtd_data_policy_binding(
        init_td_info: &[u8; crate::migration::TD_INFO_SIZE],
    ) -> Result<(), PolicyError> {
        use crate::migration::td_info_mrownerconfig;

        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        let my_policy_svn = policy.policy_data.get_policy_svn();

        // Check MROWNERCONFIG (init policy_svn) <= my policy_svn
        let init_mrownerconfig = td_info_mrownerconfig(init_td_info);
        let mut init_svn_bytes = [0u8; 4];
        init_svn_bytes.copy_from_slice(&init_mrownerconfig[..4]);
        let init_policy_svn = u32::from_le_bytes(init_svn_bytes);
        // Remaining 44 bytes should be zero
        if init_mrownerconfig[4..] != [0u8; SHA384_DIGEST_SIZE - 4] {
            return Err(PolicyError::InvalidParameter);
        }
        if init_policy_svn > my_policy_svn {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }

    /// Per GHCI 1.5: Cross-check a peer's wire-supplied init TDINFO_STRUCT against
    /// the peer's authenticated TDREPORT (or equivalent verified report data).
    ///
    /// The peer's `init.MROWNER` must equal the peer's report MROWNER (policy
    /// signer hash). The peer's `init.MROWNERCONFIG` first 4 bytes encode the
    /// init policy SVN as little-endian u32 with the remaining 44 bytes zero;
    /// that init SVN must be less than or equal to the SVN encoded the same way
    /// in the peer's report MROWNERCONFIG.
    ///
    /// `peer_mrowner` and `peer_mrownerconfig` are the peer's authentic values,
    /// taken from a verified TDREPORT (`TdInfo::mrowner` / `mrownerconfig`) or
    /// from quote-verification supplemental data
    /// (`Report::R_MIGTD_MROWNER` / `R_MIGTD_MROWNERCONFIG`).
    pub fn verify_peer_init_tdinfo_against_owner(
        peer_init_td_info: &[u8],
        peer_mrowner: &[u8],
        peer_mrownerconfig: &[u8],
    ) -> Result<(), PolicyError> {
        use crate::migration::{td_info_mrowner, td_info_mrownerconfig, TD_INFO_SIZE};

        if peer_init_td_info.len() != TD_INFO_SIZE
            || peer_mrowner.len() != SHA384_DIGEST_SIZE
            || peer_mrownerconfig.len() != SHA384_DIGEST_SIZE
        {
            return Err(PolicyError::InvalidParameter);
        }

        let init: &[u8; TD_INFO_SIZE] = peer_init_td_info
            .try_into()
            .map_err(|_| PolicyError::InvalidParameter)?;
        let init_mrowner = td_info_mrowner(init);
        let init_mrownerconfig = td_info_mrownerconfig(init);

        // 1. MROWNER (policy signer key hash) must match peer's current report
        if init_mrowner.as_slice() != peer_mrowner {
            return Err(PolicyError::PolicyHashMismatch);
        }

        // 2. init MROWNERCONFIG must be well-formed: first 4 bytes encode SVN,
        //    remaining 44 bytes must be zero.
        if init_mrownerconfig[4..] != [0u8; SHA384_DIGEST_SIZE - 4] {
            return Err(PolicyError::InvalidParameter);
        }

        // 3. Peer report MROWNERCONFIG must also be well-formed: a genuine
        //    MigTD enforces this at startup, but we verify it locally instead
        //    of relying on the peer's self-check.
        if peer_mrownerconfig[4..] != [0u8; SHA384_DIGEST_SIZE - 4] {
            return Err(PolicyError::InvalidParameter);
        }

        // 4. init policy SVN must be ≤ peer report policy SVN.
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&init_mrownerconfig[..4]);
        let init_svn = u32::from_le_bytes(buf);
        buf.copy_from_slice(&peer_mrownerconfig[..4]);
        let peer_svn = u32::from_le_bytes(buf);
        if init_svn > peer_svn {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }

    /// Cross-check a peer's wire-supplied init `TDINFO_STRUCT` against the
    /// MROWNER/MROWNERCONFIG bytes carried in the peer's verified quote
    /// supplemental data (see `Report::R_MIGTD_MROWNER` /
    /// `Report::R_MIGTD_MROWNERCONFIG`).
    ///
    /// This is a pure function: it length-checks `verified_suppl_data` before
    /// slicing so it cannot panic on a too-short buffer, and it does not
    /// invoke quote verification. Callers that want the combined attestation
    /// + cross-check should use `authenticate_migration_source_with_init_tdinfo`.
    pub fn verify_peer_init_tdinfo_against_suppl_data(
        peer_init_td_info: &[u8],
        verified_suppl_data: &[u8],
    ) -> Result<(), PolicyError> {
        if verified_suppl_data.len() < REPORT_DATA_SIZE {
            return Err(PolicyError::InvalidParameter);
        }
        verify_peer_init_tdinfo_against_owner(
            peer_init_td_info,
            &verified_suppl_data[Report::R_MIGTD_MROWNER],
            &verified_suppl_data[Report::R_MIGTD_MROWNERCONFIG],
        )
    }

    /// Destination-side migration helper: verify the source MigTD's
    /// quote/event log, cross-check init TDINFO against the quote's
    /// supplemental data, verify init TDINFO integrity against ServtdExt,
    /// and allowlist-gate init measurements against servtd_tcb_mapping.
    ///
    /// This mirrors the checks that `authenticate_rebinding_old` performs
    /// for the rebinding path, ensuring parity between migration and
    /// rebinding attestation.
    ///
    /// Returns the verified supplemental data on success so the caller can
    /// reuse it for SPDM-level bindings (e.g., REPORTDATA / TH1).
    pub fn authenticate_migration_source_with_init_tdinfo(
        quote_src: &[u8],
        peer_data: &[u8],
        event_log_src: &[u8],
        init_tdinfo: &[u8],
        servtd_ext_src: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        let (mig_policy_src, peer_issuer_chain) =
            crate::migration::pre_session_data::decode_peer_data(peer_data)
                .ok_or(PolicyError::InvalidParameter)?;

        let (evaluation_data_src, _verified_policy_src, suppl_data) = authenticate_remote_common(
            quote_src,
            event_log_src,
            mig_policy_src,
            peer_issuer_chain,
        )?;

        let relative_reference = get_local_tcb_evaluation_info()?;
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        // Existing migration-source policy checks (common + backward)
        policy.policy_data.evaluate_policy_common(
            &evaluation_data_src,
            &relative_reference,
            false,
        )?;
        policy.policy_data.evaluate_policy_backward(
            &evaluation_data_src,
            &relative_reference,
            false,
        )?;

        // Cross-check init TDINFO against MROWNER/MROWNERCONFIG from
        // verified quote supplemental data, verify init TDINFO integrity
        // against ServtdExt hash, and allowlist-gate init measurements.
        //
        // Skipped when running with mock quotes/reports that carry static
        // test data — the mock init TDINFO does not have measurements
        // that match the policy servtd_tcb_mapping.
        #[cfg(not(any(
            feature = "AzCVMEmu",
            feature = "test_mock_report",
            feature = "use-mock-quote"
        )))]
        {
            verify_peer_init_tdinfo_against_suppl_data(init_tdinfo, &suppl_data)?;

            // Verify init TDINFO integrity against ServtdExt hash
            let servtd_ext_obj =
                ServtdExt::read_from_bytes(servtd_ext_src).ok_or(PolicyError::InvalidParameter)?;
            let init_td_info = verify_init_tdinfo(init_tdinfo, &servtd_ext_obj)?;

            // Allowlist gate: init MigTD measurements must be in servtd_tcb_mapping
            let _engine_svn = policy
                .servtd_tcb_mapping
                .get_engine_svn_by_measurements(&Measurements::new_from_bytes(
                    &init_td_info.mrtd,
                    &init_td_info.rtmr0,
                    &init_td_info.rtmr1,
                    Some(&init_td_info.rtmr2),
                    Some(&init_td_info.rtmr3),
                ))
                .ok_or(PolicyError::SvnMismatch)?;
        }

        Ok(suppl_data)
    }

    #[test]
    fn test_unix_to_iso8601() {
        let timestamp = 1704067200; // Corresponds to 2024-01-01T00:00:00Z
        let iso_date = unix_to_iso8601(timestamp).unwrap();
        assert_eq!(iso_date, "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_verify_servtd_info_hash_valid() {
        // Build a 512-byte TDINFO_STRUCT with known content
        let mut tdinfo_bytes = [0u8; 512];
        tdinfo_bytes[0..8].copy_from_slice(&[0x01; 8]); // attributes
        tdinfo_bytes[8..16].copy_from_slice(&[0x02; 8]); // xfam

        // Compute expected hash: SHA384(tdinfo)
        let servtd_attr: u64 = 0;
        let expected_hash = digest_sha384(&tdinfo_bytes).unwrap();

        let result = verify_servtd_info_hash(&tdinfo_bytes, servtd_attr, &expected_hash);
        assert!(result.is_ok());
        let td_info = result.unwrap();
        assert_eq!(td_info.attributes, [0x01; 8]);
        assert_eq!(td_info.xfam, [0x02; 8]);
    }

    #[test]
    fn test_verify_servtd_info_hash_wrong_hash() {
        let tdinfo_bytes = [0u8; 512];
        let wrong_hash = [0xFFu8; 48];
        let result = verify_servtd_info_hash(&tdinfo_bytes, 0, &wrong_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_servtd_info_hash_short_input() {
        let short = [0u8; 256]; // too small for TdInfo (512 bytes)
        let result = verify_servtd_info_hash(&short, 0, &[0u8; 48]);
        assert!(matches!(result, Err(PolicyError::InvalidParameter)));
    }

    #[test]
    fn test_verify_servtd_info_hash_all_zero_init_hash_fails() {
        // When init_servtd_info_hash is all-zero but SERVTD_EXT is present,
        // verify_servtd_info_hash should fail (the sender should not have sent
        // init_tdinfo when SERVTD_EXT is not properly provisioned).
        let mut tdinfo_bytes = [0u8; 512];
        tdinfo_bytes[0..8].copy_from_slice(&[0xAB; 8]); // non-zero attributes
        let all_zero_init = [0u8; 48];
        let result = verify_servtd_info_hash(&tdinfo_bytes, 0, &all_zero_init);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_servtd_info_hash_with_ignore_attributes() {
        // Build TdInfo with non-zero attributes
        let mut tdinfo_bytes = [0u8; 512];
        tdinfo_bytes[0..8].copy_from_slice(&[0xFF; 8]); // attributes

        // Compute hash with attributes zeroed (IGNORE_ATTRIBUTES flag)
        let servtd_attr = SERVTD_ATTR_IGNORE_ATTRIBUTES;
        let mut zeroed = tdinfo_bytes;
        zeroed[0..8].fill(0); // zero attributes for hash computation
        let expected_hash = digest_sha384(&zeroed).unwrap();

        let result = verify_servtd_info_hash(&tdinfo_bytes, servtd_attr, &expected_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_servtd_info_hash_with_ignore_mrowner() {
        // Build TdInfo with non-zero mrowner at offset 112..160
        let mut tdinfo_bytes = [0u8; 512];
        tdinfo_bytes[112..160].copy_from_slice(&[0xAA; 48]); // mrowner

        // Compute hash with mrowner zeroed (IGNORE_MROWNER flag)
        let servtd_attr = SERVTD_ATTR_IGNORE_MROWNER;
        let mut zeroed = tdinfo_bytes;
        zeroed[112..160].fill(0);
        let expected_hash = digest_sha384(&zeroed).unwrap();

        let result = verify_servtd_info_hash(&tdinfo_bytes, servtd_attr, &expected_hash);
        assert!(result.is_ok());
        // mrowner should be zeroed in the returned TdInfo
        assert_eq!(result.unwrap().mrowner, [0u8; 48]);
    }

    #[test]
    fn test_verify_servtd_info_hash_with_combined_ignore_flags() {
        // Build TdInfo with non-zero content in multiple fields
        let mut tdinfo_bytes = [0u8; 512];
        tdinfo_bytes[0..8].copy_from_slice(&[0xFF; 8]); // attributes (masked)
        tdinfo_bytes[8..16].copy_from_slice(&[0xEE; 8]); // xfam (masked)
        tdinfo_bytes[16..64].copy_from_slice(&[0xBB; 48]); // mrtd (not masked)
        tdinfo_bytes[112..160].copy_from_slice(&[0xCC; 48]); // mrowner (not masked)

        // Compute hash with attributes and xfam zeroed, mrtd and mrowner intact
        let servtd_attr = SERVTD_ATTR_IGNORE_ATTRIBUTES | SERVTD_ATTR_IGNORE_XFAM;
        let mut zeroed = tdinfo_bytes;
        zeroed[0..8].fill(0);
        zeroed[8..16].fill(0);
        let expected_hash = digest_sha384(&zeroed).unwrap();

        let result = verify_servtd_info_hash(&tdinfo_bytes, servtd_attr, &expected_hash);
        assert!(result.is_ok());
        let td_info = result.unwrap();
        assert_eq!(td_info.attributes, [0u8; 8]);
        assert_eq!(td_info.xfam, [0u8; 8]);
        assert_eq!(td_info.mrtd, [0xBB; 48]);
        assert_eq!(td_info.mrowner, [0xCC; 48]);
    }

    #[test]
    fn test_get_rtmrs_from_tdinfo() {
        use tdx_tdcall::tdreport::TdInfo;
        let mut tdinfo_bytes = [0u8; 512];
        // RTMR offsets in TdInfo: rtmr0 at 208, rtmr1 at 256, rtmr2 at 304, rtmr3 at 352
        tdinfo_bytes[208..256].copy_from_slice(&[0x01; 48]); // rtmr0
        tdinfo_bytes[256..304].copy_from_slice(&[0x02; 48]); // rtmr1
        tdinfo_bytes[304..352].copy_from_slice(&[0x03; 48]); // rtmr2
        tdinfo_bytes[352..400].copy_from_slice(&[0x04; 48]); // rtmr3

        let td_info = unsafe {
            let mut uninit = core::mem::MaybeUninit::<TdInfo>::uninit();
            core::ptr::copy_nonoverlapping(
                tdinfo_bytes.as_ptr(),
                uninit.as_mut_ptr() as *mut u8,
                size_of::<TdInfo>(),
            );
            uninit.assume_init()
        };

        let rtmrs = get_rtmrs_from_tdinfo(&td_info).unwrap();
        assert_eq!(rtmrs[0], [0x01; 48]);
        assert_eq!(rtmrs[1], [0x02; 48]);
        assert_eq!(rtmrs[2], [0x03; 48]);
        assert_eq!(rtmrs[3], [0x04; 48]);
    }

    // Build a 512-byte TDINFO_STRUCT with the supplied MROWNER bytes and an
    // MROWNERCONFIG whose first 4 LE bytes encode `svn` and trailing 44 are
    // zero (the well-formed shape defined by GHCI 1.5).
    fn make_init_tdinfo(mrowner: &[u8; 48], svn: u32) -> [u8; 512] {
        let mut bytes = [0u8; 512];
        bytes[112..160].copy_from_slice(mrowner); // mrowner
        let svn_le = svn.to_le_bytes();
        bytes[160..164].copy_from_slice(&svn_le);
        // bytes[164..208] already zero (trailing of mrownerconfig)
        bytes
    }

    fn make_peer_mrownerconfig(svn: u32) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[..4].copy_from_slice(&svn.to_le_bytes());
        buf
    }

    #[test]
    fn test_verify_peer_init_tdinfo_match_equal_svn() {
        let mrowner = [0xAAu8; 48];
        let init = make_init_tdinfo(&mrowner, 5);
        let peer_mrownerconfig = make_peer_mrownerconfig(5);

        let result = verify_peer_init_tdinfo_against_owner(&init, &mrowner, &peer_mrownerconfig);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_peer_init_tdinfo_init_svn_less_than_peer() {
        let mrowner = [0xAAu8; 48];
        let init = make_init_tdinfo(&mrowner, 3);
        let peer_mrownerconfig = make_peer_mrownerconfig(7);

        let result = verify_peer_init_tdinfo_against_owner(&init, &mrowner, &peer_mrownerconfig);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_peer_init_tdinfo_init_svn_greater_rejected() {
        let mrowner = [0xAAu8; 48];
        let init = make_init_tdinfo(&mrowner, 10);
        let peer_mrownerconfig = make_peer_mrownerconfig(5);

        let result = verify_peer_init_tdinfo_against_owner(&init, &mrowner, &peer_mrownerconfig);
        assert!(matches!(result, Err(PolicyError::SvnMismatch)));
    }

    #[test]
    fn test_verify_peer_init_tdinfo_mrowner_mismatch_rejected() {
        let init_mrowner = [0xAAu8; 48];
        let peer_mrowner = [0xBBu8; 48];
        let init = make_init_tdinfo(&init_mrowner, 5);
        let peer_mrownerconfig = make_peer_mrownerconfig(5);

        let result =
            verify_peer_init_tdinfo_against_owner(&init, &peer_mrowner, &peer_mrownerconfig);
        assert!(matches!(result, Err(PolicyError::PolicyHashMismatch)));
    }

    #[test]
    fn test_verify_peer_init_tdinfo_malformed_mrownerconfig_rejected() {
        let mrowner = [0xAAu8; 48];
        let mut init = make_init_tdinfo(&mrowner, 5);
        // Corrupt the trailing-zero portion of MROWNERCONFIG (bytes 164..208).
        init[200] = 0x01;
        let peer_mrownerconfig = make_peer_mrownerconfig(5);

        let result = verify_peer_init_tdinfo_against_owner(&init, &mrowner, &peer_mrownerconfig);
        assert!(matches!(result, Err(PolicyError::InvalidParameter)));
    }

    #[test]
    fn test_verify_peer_init_tdinfo_malformed_peer_mrownerconfig_rejected() {
        let mrowner = [0xAAu8; 48];
        let init = make_init_tdinfo(&mrowner, 5);
        let mut peer_mrownerconfig = make_peer_mrownerconfig(5);
        // Corrupt the trailing-zero portion of the peer's MROWNERCONFIG.
        peer_mrownerconfig[20] = 0x01;

        let result = verify_peer_init_tdinfo_against_owner(&init, &mrowner, &peer_mrownerconfig);
        assert!(matches!(result, Err(PolicyError::InvalidParameter)));
    }

    #[test]
    fn test_verify_peer_init_tdinfo_wrong_lengths_rejected() {
        let mrowner = [0xAAu8; 48];
        let init = make_init_tdinfo(&mrowner, 5);
        let peer_mrownerconfig = make_peer_mrownerconfig(5);

        // Short init buffer
        let short_init = &init[..256];
        assert!(matches!(
            verify_peer_init_tdinfo_against_owner(short_init, &mrowner, &peer_mrownerconfig),
            Err(PolicyError::InvalidParameter)
        ));

        // Wrong mrowner length
        let short_mrowner = &mrowner[..32];
        assert!(matches!(
            verify_peer_init_tdinfo_against_owner(&init, short_mrowner, &peer_mrownerconfig),
            Err(PolicyError::InvalidParameter)
        ));

        // Wrong mrownerconfig length
        let short_mrownerconfig = &peer_mrownerconfig[..32];
        assert!(matches!(
            verify_peer_init_tdinfo_against_owner(&init, &mrowner, short_mrownerconfig),
            Err(PolicyError::InvalidParameter)
        ));
    }

    fn make_suppl_data(mrowner: &[u8; 48], svn: u32) -> Vec<u8> {
        let mut suppl = alloc::vec![0u8; REPORT_DATA_SIZE];
        suppl[Report::R_MIGTD_MROWNER].copy_from_slice(mrowner);
        suppl[Report::R_MIGTD_MROWNERCONFIG][..4].copy_from_slice(&svn.to_le_bytes());
        suppl
    }

    #[test]
    fn test_verify_peer_init_tdinfo_against_suppl_data_ok() {
        let mrowner = [0xCDu8; 48];
        let init = make_init_tdinfo(&mrowner, 3);
        let suppl = make_suppl_data(&mrowner, 5);
        assert!(verify_peer_init_tdinfo_against_suppl_data(&init, &suppl).is_ok());
    }

    #[test]
    fn test_verify_peer_init_tdinfo_against_suppl_data_short_buffer() {
        let mrowner = [0xCDu8; 48];
        let init = make_init_tdinfo(&mrowner, 3);
        let short = alloc::vec![0u8; REPORT_DATA_SIZE - 1];
        // Must return InvalidParameter, not panic, even though
        // R_MIGTD_MROWNERCONFIG = 280..328 would otherwise slice OOB.
        assert!(matches!(
            verify_peer_init_tdinfo_against_suppl_data(&init, &short),
            Err(PolicyError::InvalidParameter)
        ));
    }

    #[test]
    fn test_verify_peer_init_tdinfo_against_suppl_data_mrowner_mismatch() {
        let init_mrowner = [0xCDu8; 48];
        let peer_mrowner = [0xEEu8; 48];
        let init = make_init_tdinfo(&init_mrowner, 3);
        let suppl = make_suppl_data(&peer_mrowner, 5);
        assert!(matches!(
            verify_peer_init_tdinfo_against_suppl_data(&init, &suppl),
            Err(PolicyError::PolicyHashMismatch)
        ));
    }

    #[test]
    fn test_verify_peer_init_tdinfo_against_suppl_data_svn_greater_rejected() {
        let mrowner = [0xCDu8; 48];
        let init = make_init_tdinfo(&mrowner, 7);
        let suppl = make_suppl_data(&mrowner, 5);
        assert!(matches!(
            verify_peer_init_tdinfo_against_suppl_data(&init, &suppl),
            Err(PolicyError::SvnMismatch)
        ));
    }
}

fn get_rtmrs_from_suppl_data(
    suppl_data: &[u8],
) -> Result<[[u8; SHA384_DIGEST_SIZE]; 4], PolicyError> {
    if suppl_data.len() < REPORT_DATA_SIZE {
        return Err(PolicyError::InvalidParameter);
    }

    let mut rtmrs = [[0u8; SHA384_DIGEST_SIZE]; 4];
    rtmrs[0].copy_from_slice(&suppl_data[Report::R_MIGTD_RTMR0]);
    rtmrs[1].copy_from_slice(&suppl_data[Report::R_MIGTD_RTMR1]);
    rtmrs[2].copy_from_slice(&suppl_data[Report::R_MIGTD_RTMR2]);
    rtmrs[3].copy_from_slice(&suppl_data[Report::R_MIGTD_RTMR3]);

    Ok(rtmrs)
}
