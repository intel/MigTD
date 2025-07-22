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
pub mod v2 {
    use alloc::{string::ToString, vec::Vec};
    use core::mem::size_of;
    use crypto::{hash::digest_sha384, SHA384_DIGEST_SIZE};
    use lazy_static::lazy_static;
    use policy::*;
    use scroll::Pread;
    use spin::Once;
    use tdx_tdcall::tdreport::TdxReport;

    use crate::config::{
        get_collaterals, get_engine, get_engine_public_key, get_policy, get_policy_public_key,
    };

    const SERVTD_TYPE_MIGTD: u16 = 0;
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

    lazy_static! {
        pub static ref LOCAL_TCB_INFO: Once<PolicyEvaluationInfo> = Once::new();
    }

    pub fn get_local_tcb_evaluation_info() -> Result<PolicyEvaluationInfo, PolicyError> {
        LOCAL_TCB_INFO
            .get()
            .map(|info| info.clone())
            .ok_or(PolicyError::InvalidParameter)
    }

    pub fn authenticate_migration_dest(
        tcb_date_dst: &str,
        tcb_status_dst: TcbStatus,
        quote_dst: &[u8],
        td_report_dst: &[u8],
        event_log_dst: &[u8],
        mig_policy_dst: &[u8],
        svn_map_dst: &[u8],
    ) -> Result<(), PolicyError> {
        let policy_pubkey_src = get_policy_public_key().ok_or(PolicyError::InvalidParameter)?;
        let engine_pubkey_src = get_engine_public_key().ok_or(PolicyError::InvalidParameter)?;
        let collaterals = get_collaterals().ok_or(PolicyError::InvalidParameter)?;
        let policy = get_policy().ok_or(PolicyError::InvalidParameter)?;
        let engine_svn_map = get_engine().ok_or(PolicyError::InvalidParameter)?;

        // Integrity checks
        // 1. Check event log integrity
        let report_values_dst = verify_event_log(event_log_dst, td_report_dst)?;
        // 2. Verify the migration policy integrity
        let mig_policy_obj_dst =
            verify_policy_integrity(mig_policy_dst, policy_pubkey_src, event_log_dst)?;
        // 3. Verify the engine-svn map integrity
        let engine_svn_map_obj_dst =
            verify_engine_integrity(svn_map_dst, engine_pubkey_src, event_log_dst)?;

        // TEE TCB check & MigTD engine check
        let mig_policy_obj =
            MigPolicy::deserialize_from_json(policy).map_err(|_| PolicyError::InvalidPolicy)?;
        let fmspc_dst = get_fmspc_from_quote(quote_dst)?;
        let collateral_dst = get_collateral_with_fmspc(&fmspc_dst, collaterals)?;
        let tcb_evaluation_number_dst = get_tcb_evaluation_number_from_collateral(&collateral_dst)?;
        let tee_tcb_info_dst = PolicyEvaluationInfo {
            tcb_date: Some(tcb_date_dst.to_string()),
            tcb_status: Some(tcb_status_dst.as_str().to_string()),
            tcb_evaluation_number: Some(tcb_evaluation_number_dst),
            engine_svn: Some(
                engine_svn_map_obj_dst
                    .get_engine_svn(&report_values_dst)
                    .ok_or(PolicyError::SvnMismatch)?,
            ),
        };
        let local_tcb_evaluation_info = get_local_tcb_evaluation_info()?;
        mig_policy_obj.evaluate_policy_common(&tee_tcb_info_dst, &local_tcb_evaluation_info)?;
        mig_policy_obj.evaluate_policy_forward(&tee_tcb_info_dst, &local_tcb_evaluation_info)?;

        // Verify the destination's policy
        mig_policy_obj.evaluate_against_policy(&mig_policy_obj_dst, &local_tcb_evaluation_info)
    }

    pub fn authenticate_migration_source(
        tcb_date_src: &str,
        tcb_status_src: TcbStatus,
        quote_src: &[u8],
        td_report_src: &[u8],
        event_log_src: &[u8],
        mig_policy_src: &[u8],
        td_report_init: &[u8],
        event_log_init: &[u8],
        mig_policy_init: &[u8],
        collaterals_init: &[u8],
        servtd_ext_init: &[u8],
    ) -> Result<(), PolicyError> {
        let policy_pubkey = get_policy_public_key().ok_or(PolicyError::InvalidParameter)?;
        let collaterals = get_collaterals().ok_or(PolicyError::InvalidParameter)?;
        let policy = get_policy().ok_or(PolicyError::InvalidParameter)?;
        let engine_svn_map = get_engine().ok_or(PolicyError::InvalidParameter)?;

        // Integrity checks
        // 1. Verify the source's event log integrity
        let report_values_src = verify_event_log(event_log_src, td_report_src)?;
        // 2. Verify the source's migration policy integrity
        let mig_policy_obj_src =
            verify_policy_integrity(mig_policy_src, policy_pubkey, event_log_src)?;
        // 3. Check the initial td report
        let engine_svn = check_td_report(td_report_init, servtd_ext_init, engine_svn_map)?;
        // 4. Verify the initial event log integrity
        let report_values_init = verify_event_log(event_log_init, td_report_init)?;
        // 5. Verify the initial migration policy integrity
        let mig_policy_obj_init =
            verify_policy_integrity(mig_policy_init, policy_pubkey, event_log_src)?;
        verify_collateral_integrity(collaterals_init, event_log_init)?;

        // TEE TCB check & MigTD engine check
        let fmspc_src = get_fmspc_from_quote(quote_src)?;
        let collateral_src = get_collateral_with_fmspc(&fmspc_src, collaterals)?;
        let tcb_evaluation_number_src = get_tcb_evaluation_number_from_collateral(&collateral_src)?;
        let tee_tcb_info_src = PolicyEvaluationInfo {
            tcb_date: Some(tcb_date_src.to_string()),
            tcb_status: Some(tcb_status_src.as_str().to_string()),
            tcb_evaluation_number: Some(tcb_evaluation_number_src),
            engine_svn: Some(get_engine_svn_from_map(engine_svn_map, td_report_src)?),
        };
        let local_tcb_evaluation_info = get_local_tcb_evaluation_info()?;
        mig_policy_obj_init
            .evaluate_policy_common(&tee_tcb_info_src, &local_tcb_evaluation_info)?;
        mig_policy_obj_init
            .evaluate_policy_forward(&tee_tcb_info_src, &local_tcb_evaluation_info)?;

        // Verify the source's policy
        mig_policy_obj_init.evaluate_against_policy(&mig_policy_obj_src, &local_tcb_evaluation_info)
    }

    // Dummy implementation for testing purposes
    pub fn read_servtd_ext() -> Result<ServtdExt, PolicyError> {
        let mut servtd_ext = ServtdExt {
            init_servtd_hash: [0; 48],
            cur_servtd_hash: [0; 48],
            init_servtd_attr: 0,
            init_servtd_tee_tcb_svn: [0; 16],
            init_servtd_tee_tcb_svn_2: [0; 16],
            init_servtd_fmspc: [0; 6],
            _padding: [0; 2],
            cur_servtd_attr: 0,
        };
        servtd_ext.init_servtd_attr = 0;
        let report = tdx_tdcall::tdreport::tdcall_report(&[0u8; 64])
            .map_err(|_| PolicyError::FailGetReport)?;
        servtd_ext
            .init_servtd_tee_tcb_svn
            .copy_from_slice(&report.tee_tcb_info.tee_tcb_svn);
        servtd_ext
            .init_servtd_tee_tcb_svn_2
            .copy_from_slice(&report.tee_tcb_info.tee_tcb_svn);
        servtd_ext.cur_servtd_attr = 0;
        let servtd_info_hash = calculate_servtd_info_hash(report, 0)?;
        let servtd_hash = calculate_servtd_hash(&servtd_info_hash, 0, 0)?;
        servtd_ext.init_servtd_hash.copy_from_slice(&servtd_hash);
        servtd_ext.cur_servtd_hash.copy_from_slice(&servtd_hash);

        Ok(servtd_ext)
    }

    pub fn check_td_report(
        td_report: &[u8],
        servtd_ext: &[u8],
        engine_svn_map: &[u8],
    ) -> Result<u32, PolicyError> {
        // Convert byte slice to ServtdExt struct
        let servtd_ext_obj = servtd_ext
            .pread::<ServtdExt>(0)
            .map_err(|_| PolicyError::InvalidParameter)?;

        // Verify CalcServTdHash (TDREPORTinit, SERVTD_EXT.INIT_SERVTD_ATTR) == SERVTD_EXT.INIT_SERVTD_HASH
        let td_report_obj = td_report
            .pread::<TdxReport>(0)
            .map_err(|_| PolicyError::InvalidParameter)?;
        let servtd_info_hash =
            calculate_servtd_info_hash(td_report_obj, servtd_ext_obj.init_servtd_attr)?;
        let servtd_hash = calculate_servtd_hash(
            &servtd_info_hash,
            SERVTD_TYPE_MIGTD,
            servtd_ext_obj.init_servtd_attr,
        )?;
        if servtd_hash != servtd_ext_obj.init_servtd_hash {
            return Err(PolicyError::InvalidTdxReport);
        }

        // Get engineSVNinit
        get_engine_svn_from_map(engine_svn_map, td_report)
    }

    fn apply_servtd_ignore_flags(td_info: &mut tdx_tdcall::tdreport::TdInfo, servtd_attr: u64) {
        let field_mappings = [
            (
                SERVTD_ATTR_IGNORE_ATTRIBUTES,
                &mut td_info.attributes as &mut [u8],
            ),
            (SERVTD_ATTR_IGNORE_XFAM, &mut td_info.xfam),
            (SERVTD_ATTR_IGNORE_MRTD, &mut td_info.mrtd),
            (SERVTD_ATTR_IGNORE_MRCONFIGID, &mut td_info.mrconfig_id),
            (SERVTD_ATTR_IGNORE_MROWNER, &mut td_info.mrowner),
            (SERVTD_ATTR_IGNORE_MROWNERCONFIG, &mut td_info.mrownerconfig),
            (SERVTD_ATTR_IGNORE_RTMR0, &mut td_info.rtmr0),
            (SERVTD_ATTR_IGNORE_RTMR1, &mut td_info.rtmr1),
            (SERVTD_ATTR_IGNORE_RTMR2, &mut td_info.rtmr2),
            (SERVTD_ATTR_IGNORE_RTMR3, &mut td_info.rtmr3),
        ];

        // Apply ignore flags
        for (flag, field) in field_mappings {
            if (servtd_attr & flag) != 0 {
                field.fill(0);
            }
        }
    }

    pub fn calculate_servtd_info_hash(
        mut td_report: TdxReport,
        servtd_attr: u64,
    ) -> Result<Vec<u8>, PolicyError> {
        apply_servtd_ignore_flags(&mut td_report.td_info, servtd_attr);
        digest_sha384(&td_report.as_bytes()[512..]).map_err(|_| PolicyError::HashCalculation)
    }

    pub fn calculate_servtd_hash(
        servtd_info_hash: &[u8],
        servtd_type: u16,
        servtd_attr: u64,
    ) -> Result<Vec<u8>, PolicyError> {
        let mut buffer = [0u8; SHA384_DIGEST_SIZE + size_of::<u16>() + size_of::<u64>()];
        let mut packed_size = 0usize;

        if servtd_info_hash.len() != SHA384_DIGEST_SIZE {
            return Err(PolicyError::InvalidParameter);
        }

        buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(servtd_info_hash);
        packed_size += SHA384_DIGEST_SIZE;
        buffer[packed_size..packed_size + size_of::<u16>()]
            .copy_from_slice(&servtd_type.to_le_bytes());
        packed_size += size_of::<u16>();
        buffer[packed_size..packed_size + size_of::<u64>()]
            .copy_from_slice(&servtd_attr.to_le_bytes());

        digest_sha384(&buffer).map_err(|_| PolicyError::HashCalculation)
    }

    #[repr(C, align(64))]
    #[derive(Debug, Pread)]
    pub struct ServtdExt {
        pub init_servtd_hash: [u8; 48],
        pub init_servtd_attr: u64,
        pub init_servtd_tee_tcb_svn: [u8; 16],
        pub init_servtd_tee_tcb_svn_2: [u8; 16],
        pub init_servtd_fmspc: [u8; 6],
        _padding: [u8; 2],
        pub cur_servtd_hash: [u8; 48],
        pub cur_servtd_attr: u64,
    }
}
