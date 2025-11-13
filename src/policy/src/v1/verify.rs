// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use super::{
    config::{MigPolicy, Property},
    format_bytes_hex, MigTdInfo, PlatformInfo, Policy, QeInfo,
};
use crate::{
    CcEvent, EventName, MigTdInfoProperty, PlatformInfoProperty, PolicyError, QeInfoProperty,
    Report, TdxModuleInfoProperty, REPORT_DATA_SIZE,
};

// Attributes Mask:
// Bits     Feature             Masked or Not   Notes
// 3:0      TD Under Debug      Not masked      Always 0
// 15:4     TD Under Profiling  Not masked      Always 0
// 26:16    Reserved            Masked          Always 0
// 27       LASS                Masked          Feature not required
// 28       SEPT_VE_DISABLE     Not masked      Always 0
// 29       MIGRATABLE          Not masked      Always 0
// 30       PKS                 Masked          Feature not required
// 31       KL (Key Locker)     Masked          Feature not required
// 61:32    Reserved            Masked          Always 0
// 62       TPA                 Not masked      Always 0
// 63       PERFMON             Masked          Feature not required
const MIGTD_ATTRIBUTES_MASK: [u8; 8] = [0xff, 0xff, 0x00, 0x30, 0x00, 0x00, 0x00, 0x40];

// XFAM Mask:
// Bits     Feature             Masked or Not   Notes
// 0        FP                  Not masked      Always enabled
// 1        SSE                 Not masked      Always enabled
// 2        AVX                 Masked          Feature not required
// 4:3      MPX                 Masked          Feature not required (MPX is being deprecated.)
// 7:5      AVX512              Masked          Feature not required
// 8        PT (RTIT)           Masked          Feature not required
// 9        PK                  Masked          Feature not required
// 10       ENQCMD              Masked          Feature not required
// 12:11    CET                 Not masked      Feature required
// 13       HDC                 Masked          Feature not required
// 14       ULI                 Masked          Feature not required
// 15       LBR                 Masked          Feature not required
// 16       HWP                 Masked          Feature not required
// 18:17    AMX                 Masked          Feature not required
// 19       APX                 Masked          Feature not required
const MIGTD_XFAM_MASK: [u8; 8] = [0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

pub fn verify_policy(
    is_src: bool,
    policy: &[u8],
    report: &[u8],
    events: &BTreeMap<EventName, CcEvent>,
    report_peer: &[u8],
    events_peer: &BTreeMap<EventName, CcEvent>,
) -> Result<(), PolicyError> {
    if report.len() < REPORT_DATA_SIZE || report_peer.len() < REPORT_DATA_SIZE {
        return Err(PolicyError::InvalidParameter);
    }

    // Remove the trailing zeros inside the utf8 string,
    // otherwise serde deserialize will fail
    let input = core::str::from_utf8(policy);
    let policy = match input {
        Ok(s) => s.trim_matches(char::from(0)),
        Err(_) => return Err(PolicyError::InvalidPolicy),
    };

    let policy = match serde_json::from_str::<MigPolicy>(policy) {
        Ok(policy) => policy,
        Err(_) => return Err(PolicyError::InvalidPolicy),
    };

    let report_local = Report::new(report)?;
    let report_peer = Report::new(report_peer)?;

    // There might be multiple supported platforms, filter out all the
    // platform info blocks.
    let platform_info: Vec<&super::PlatformInfo> = policy
        .blocks
        .iter()
        .filter_map(|block| match block {
            super::Policy::Platform(p) => Some(p),
            _ => None,
        })
        .collect();
    verify_platform_info(is_src, platform_info, &report_local, &report_peer)?;

    // There might be multiple supported TDX Modules, filter out all the
    // TDX Modules info blocks.
    verify_tdx_module_info(is_src, &policy, &report_local, &report_peer)?;

    for block in policy.blocks {
        match block {
            super::Policy::Platform(_) => continue,
            super::Policy::Qe(q) => verify_qe_info(is_src, &q, &report_local, &report_peer)?,
            super::Policy::TdxModule(_) => continue,
            super::Policy::Migtd(m) => {
                verify_migtd_info(is_src, &m, events, events_peer, &report_local, &report_peer)?
            }
        }
    }

    Ok(())
}

fn verify_platform_info(
    is_src: bool,
    policy: Vec<&PlatformInfo>,
    local_report: &Report,
    peer_report: &Report,
) -> Result<(), PolicyError> {
    let local_fmspc =
        format_bytes_hex(local_report.get_platform_info_property(&PlatformInfoProperty::Fmspc)?);
    let peer_fmspc =
        format_bytes_hex(peer_report.get_platform_info_property(&PlatformInfoProperty::Fmspc)?);

    let target_platform = if policy.len() == 1 && policy[0].fmspc.as_str() == "self" {
        if local_fmspc != peer_fmspc {
            return Err(PolicyError::PlatformNotMatch(local_fmspc, peer_fmspc));
        }
        &policy[0]
    } else {
        policy
            .iter()
            .find(|p| p.fmspc == peer_fmspc)
            .ok_or(PolicyError::PlatformNotFound(peer_fmspc.clone()))?
    };

    for (name, action) in &target_platform.platform.tcb_info {
        let property = PlatformInfoProperty::from(name.as_str());
        let local = local_report.get_platform_info_property(&property)?;
        let remote = peer_report.get_platform_info_property(&property)?;

        let verify_result = action.verify(is_src, local, remote);

        if !verify_result {
            log_error_status(
                name.clone(),
                action.clone(),
                Some(local_fmspc),
                Some(peer_fmspc),
                local,
                remote,
            );
            return Err(PolicyError::UnqualifiedPlatformInfo);
        }
    }

    Ok(())
}

fn verify_qe_info(
    is_src: bool,
    policy: &QeInfo,
    local_report: &Report,
    peer_report: &Report,
) -> Result<(), PolicyError> {
    for (name, action) in &policy.qe_identity.qe_identity {
        let property = QeInfoProperty::from(name.as_str());
        let local = local_report.get_qe_info_property(&property)?;
        let remote = peer_report.get_qe_info_property(&property)?;

        let verify_result = action.verify(is_src, local, remote);

        if !verify_result {
            log_error_status(name.clone(), action.clone(), None, None, local, remote);
            return Err(PolicyError::UnqualifiedQeInfo);
        }
    }

    Ok(())
}

fn verify_tdx_module_info(
    is_src: bool,
    policy: &MigPolicy,
    local_report: &Report,
    peer_report: &Report,
) -> Result<(), PolicyError> {
    let mut verify_result = true;

    for block in &policy.blocks {
        match block {
            Policy::TdxModule(t) => {
                verify_result = true;
                for (name, action) in &t.tdx_module.tdx_module_identity {
                    let property = TdxModuleInfoProperty::from(name.as_str());
                    let local = local_report.get_tdx_module_info_property(&property)?;
                    let remote = peer_report.get_tdx_module_info_property(&property)?;

                    if !action.verify(is_src, local, remote) {
                        verify_result = false;
                        break;
                    }
                }
            }
            _ => continue,
        }

        if verify_result {
            break;
        }
    }

    if !verify_result {
        // Display the policy information and the actual report data.
        #[cfg(feature = "log")]
        for block in &policy.blocks {
            match block {
                Policy::TdxModule(t) => {
                    for (name, action) in &t.tdx_module.tdx_module_identity {
                        let property = TdxModuleInfoProperty::from(name.as_str());
                        let local = local_report.get_tdx_module_info_property(&property)?;
                        let remote = peer_report.get_tdx_module_info_property(&property)?;
                        log_error_status(name.clone(), action.clone(), None, None, local, remote);
                    }
                }
                _ => continue,
            }
        }
        return Err(PolicyError::UnqualifiedTdxModuleInfo);
    }

    Ok(())
}

fn verify_migtd_info(
    is_src: bool,
    policy: &MigTdInfo,
    events_local: &BTreeMap<EventName, CcEvent>,
    events_peer: &BTreeMap<EventName, CcEvent>,
    local_report: &Report,
    peer_report: &Report,
) -> Result<(), PolicyError> {
    let mut masked_local = [0u8; 8];
    let mut masked_remote = [0u8; 8];

    for (name, action) in &policy.migtd.td_info {
        let property = MigTdInfoProperty::from(name.as_str());
        let local = local_report.get_migtd_info_property(&property)?;
        let remote = peer_report.get_migtd_info_property(&property)?;

        let (local, remote) = match property {
            // Mask the Attributes and XFAM
            MigTdInfoProperty::Attributes => {
                masked_local[..8].copy_from_slice(local);
                masked_remote[..8].copy_from_slice(remote);
                mask_bytes_array(&mut masked_local, &MIGTD_ATTRIBUTES_MASK);
                mask_bytes_array(&mut masked_remote, &MIGTD_ATTRIBUTES_MASK);
                (masked_local.as_slice(), masked_remote.as_slice())
            }
            MigTdInfoProperty::Xfam => {
                masked_local[..8].copy_from_slice(local);
                masked_remote[..8].copy_from_slice(remote);
                mask_bytes_array(&mut masked_local, &MIGTD_XFAM_MASK);
                mask_bytes_array(&mut masked_remote, &MIGTD_XFAM_MASK);
                (masked_local.as_slice(), masked_remote.as_slice())
            }
            _ => (local, remote),
        };

        let verify_result = action.verify(is_src, local, remote);

        if !verify_result {
            log_error_status(name.clone(), action.clone(), None, None, local, remote);
            return Err(PolicyError::UnqualifiedMigTdInfo);
        }
    }

    if let Some(event_log_policy) = &policy.migtd.event_log {
        verify_events(is_src, event_log_policy, events_local, events_peer)?;
    }

    Ok(())
}

fn mask_bytes_array(data: &mut [u8], mask: &[u8]) {
    for (x, mask) in data.iter_mut().zip(mask.iter()) {
        *x &= mask;
    }
}

fn verify_events(
    is_src: bool,
    policy: &BTreeMap<String, Property>,
    local_events: &BTreeMap<EventName, CcEvent>,
    peer_events: &BTreeMap<EventName, CcEvent>,
) -> Result<(), PolicyError> {
    for (name, value) in policy {
        let event_name = name.as_str().into();

        if event_name == EventName::Unknown {
            return Err(PolicyError::InvalidEventLog);
        }

        let verify_result = verify_event(is_src, &event_name, value, local_events, peer_events);

        if !verify_result {
            log_error_status(name.clone(), value.clone(), None, None, &[], &[]);
            return Err(PolicyError::UnqualifiedMigTdInfo);
        }
    }

    Ok(())
}

fn verify_event(
    is_src: bool,
    event_name: &EventName,
    policy: &Property,
    local_events: &BTreeMap<EventName, CcEvent>,
    peer_events: &BTreeMap<EventName, CcEvent>,
) -> bool {
    if let (Some(local), Some(peer)) = (local_events.get(event_name), peer_events.get(event_name)) {
        if let Some(data) = local.data.as_ref() {
            if let Some(data_peer) = peer.data.as_ref() {
                policy.verify(is_src, data, data_peer)
            } else {
                false
            }
        } else {
            policy.verify(
                is_src,
                &local.header.digest.digests[0].digest.sha384,
                &peer.header.digest.digests[0].digest.sha384,
            )
        }
    } else {
        false
    }
}

#[allow(unused_variables)]
fn log_error_status(
    property: String,
    policy: Property,
    local_fmspc: Option<String>,
    remote_fmspc: Option<String>,
    local: &[u8],
    remote: &[u8],
) {
    #[cfg(feature = "log")]
    {
        use alloc::format;
        use log::error;

        error!("Property: {:}\n", property);
        error!("Policy: {:?}\n", policy);
        error!("Local FMFPC: {:?}\n", local_fmspc);
        error!("Remote FMFPC: {:?}\n", remote_fmspc);
        error!("Local property value: {:?}\n", format!("{:x?}", local));
        error!("Remote property value: {:?}\n", format!("{:x?}", remote));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use alloc::vec;
    use cc_measurement::{
        TpmlDigestValues, TpmtHa, TpmuHa, UefiPlatformFirmwareBlob2,
        EV_EFI_PLATFORM_FIRMWARE_BLOB2, EV_PLATFORM_CONFIG_FLAGS, TPML_ALG_SHA384,
    };
    use core::convert::TryInto;
    use crypto::hash::digest_sha384;
    use td_shim::event_log::{
        TdShimPlatformConfigInfoHeader, PLATFORM_CONFIG_SECURE_AUTHORITY, PLATFORM_CONFIG_SVN,
        PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
    };

    #[test]
    fn test_verify_invalid_parameter() {
        let policy_bytes = include_bytes!("../../test/policy.json");
        let verify_result = verify_policy(
            true,
            policy_bytes,
            &[0u8; REPORT_DATA_SIZE - 1],
            &BTreeMap::new(),
            &[0u8; REPORT_DATA_SIZE],
            &BTreeMap::new(),
        );
        assert!(matches!(verify_result, Err(PolicyError::InvalidParameter)));

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &[0u8; REPORT_DATA_SIZE],
            &BTreeMap::new(),
            &[0u8; REPORT_DATA_SIZE - 1],
            &BTreeMap::new(),
        );
        assert!(matches!(verify_result, Err(PolicyError::InvalidParameter)));
    }

    #[test]
    fn test_verify_with_platform_info_comp() {
        let template = include_bytes!("../../test/report.dat");

        // Take `self` as reference
        let policy_bytes = include_bytes!("../../test/policy_001.json");
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            template,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        // Only same platform is allowed
        let mut report_peer = template.to_vec();
        report_peer[Report::R_PLATFORM_FMSPC].copy_from_slice(&[0x20, 0xC0, 0x6F, 0, 0, 0]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::PlatformNotMatch(_, _))
        ));

        let policy_bytes = include_bytes!("../../test/policy_full1.json");
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            template,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        let mut report_peer = template.to_vec();
        report_peer[Report::R_PLATFORM_FMSPC].copy_from_slice(&[0x30, 0x81, 0x6F, 0, 0, 0]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::PlatformNotFound(_))
        ));

        // peer's tdx tcb level lower than reference
        let mut report_peer = template.to_vec();
        let low_tdx_tcb = &[0u8; 16];
        report_peer[Report::R_PLATFORM_TDX_TCB_COMPONENTS].copy_from_slice(low_tdx_tcb);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedPlatformInfo)
        ));

        // dst's tdx tcb level is higher than reference
        let high_tdx_tcb = &[0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        report_peer[Report::R_PLATFORM_TDX_TCB_COMPONENTS].copy_from_slice(high_tdx_tcb);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        // Take self as reference
        let policy_bytes = include_bytes!("../../test/policy_full3.json");
        let mut report = template.to_vec();
        let mut report_peer = template.to_vec();

        // dst's tdx tcb level is higher than self
        report[Report::R_PLATFORM_TDX_TCB_COMPONENTS].copy_from_slice(&[1u8; 16]);
        report_peer[Report::R_PLATFORM_TDX_TCB_COMPONENTS].copy_from_slice(&[2u8; 16]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        // dst's svn is smaller than self
        report[Report::R_PLATFORM_TDX_TCB_COMPONENTS].copy_from_slice(&[2u8; 16]);
        report_peer[Report::R_PLATFORM_TDX_TCB_COMPONENTS].copy_from_slice(&[1u8; 16]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedPlatformInfo)
        ));
    }

    #[test]
    fn test_verify_tdx_module_info_comp() {
        let template = include_bytes!("../../test/report.dat");

        // Taking `self` as reference: pass
        let policy_bytes = include_bytes!("../../test/policy_001.json");
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            template,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        // Taking `self` as reference: mismatch tdx module major version
        let mut report_peer = template.to_vec();
        report_peer[Report::R_TDX_MODULE_MAJOR_VER].copy_from_slice(&[2]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedTdxModuleInfo)
        ));

        // Taking exact value as reference: pass
        let policy_bytes = include_bytes!("../../test/policy_full1.json");
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            template,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        // Taking exact value as reference: pass
        let mut report_peer = template.to_vec();
        report_peer[Report::R_TDX_MODULE_MAJOR_VER].copy_from_slice(&[2]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        // Taking exact value as reference: mismatch tdx module major version
        let mut report_peer = template.to_vec();
        report_peer[Report::R_TDX_MODULE_MAJOR_VER].copy_from_slice(&[0]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedTdxModuleInfo)
        ));

        // Taking exact value as reference: mismatch tdx module svn
        let mut report_peer = template.to_vec();
        report_peer[Report::R_TDX_MODULE_SVN].copy_from_slice(&[1]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedTdxModuleInfo)
        ));

        // Taking exact value as reference: mismatch mrsignerseam
        let mut report_peer = template.to_vec();
        report_peer[Report::R_TDX_MODULE_MRSEAMSIGNER].copy_from_slice(&[0xfeu8; 48]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedTdxModuleInfo)
        ));

        // Taking exact value as reference: mismatch attributes
        let mut report_peer = template.to_vec();
        report_peer[Report::R_TDX_MODULE_ATTR_SEAM].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedTdxModuleInfo)
        ));
    }

    // Different MRTD value, no MRTD policy in policy data
    #[test]
    fn test_verify_migtdinfo_comp() {
        let template = include_bytes!("../../test/report.dat");

        let policy_bytes = include_bytes!("../../test/policy_no.json");
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            template,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        // different attributes, not equal, but attributes is not in policy
        let policy_bytes = include_bytes!("../../test/policy_no_tdattr.json");
        let mut report_peer = template.to_vec();

        report_peer[Report::R_MIGTD_ATTR_TD].copy_from_slice(&[1u8; 8]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        let policy_bytes = include_bytes!("../../test/policy_full1.json");
        // different attributes, not equal
        report_peer[Report::R_MIGTD_ATTR_TD].copy_from_slice(&[1u8; 8]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));

        // verify the attributes mask, set masked bits
        report_peer[Report::R_MIGTD_ATTR_TD].copy_from_slice(&[0, 0, 0, 0x8, 0x1, 0, 0, 0]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        // verify the attributes mask, set bits that will not be masked but must be zero
        report_peer[Report::R_MIGTD_ATTR_TD].copy_from_slice(&[0, 0x1, 0, 0x3, 0, 0, 0, 0]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
        report_peer[Report::R_MIGTD_ATTR_TD].copy_from_slice(&template[Report::R_MIGTD_ATTR_TD]);

        // different xfam, not equal
        report_peer[Report::R_MIGTD_XFAM].copy_from_slice(&[1u8; 8]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));

        // verify xfam mask, set masked bits and required bits
        report_peer[Report::R_MIGTD_XFAM].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(verify_result.is_ok());

        // verify xfam mask, unset bits that is not masked but required
        report_peer[Report::R_MIGTD_XFAM].copy_from_slice(&[0x3, 0x08, 0, 0, 0, 0, 0, 0]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
        report_peer[Report::R_MIGTD_XFAM].copy_from_slice(&template[Report::R_MIGTD_XFAM]);

        // different mrtd, not equal
        report_peer[Report::R_MIGTD_MRTD].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
        report_peer[Report::R_MIGTD_MRTD].copy_from_slice(&[0u8; 48]);

        // different mrconfig_id, not equal
        report_peer[Report::R_MIGTD_MRCONFIGID].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
        report_peer[Report::R_MIGTD_MRCONFIGID]
            .copy_from_slice(&template[Report::R_MIGTD_MRCONFIGID]);

        // different mrowner, not equal
        report_peer[Report::R_MIGTD_MROWNER].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
        report_peer[Report::R_MIGTD_MROWNER].copy_from_slice(&template[Report::R_MIGTD_MROWNER]);

        // different mrownerconfig, not equal
        report_peer[Report::R_MIGTD_MROWNERCONFIG].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
        report_peer[Report::R_MIGTD_MROWNERCONFIG]
            .copy_from_slice(&template[Report::R_MIGTD_MROWNERCONFIG]);

        // different rtmr0, not equal
        report_peer[Report::R_MIGTD_RTMR0].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
        report_peer[Report::R_MIGTD_RTMR0].copy_from_slice(&template[Report::R_MIGTD_RTMR0]);

        // different rtmr1, not equal
        report_peer[Report::R_MIGTD_RTMR1].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
        report_peer[Report::R_MIGTD_RTMR1].copy_from_slice(&template[Report::R_MIGTD_RTMR1]);

        // different rtmr2, not equal
        report_peer[Report::R_MIGTD_RTMR2].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
        report_peer[Report::R_MIGTD_RTMR2].copy_from_slice(&template[Report::R_MIGTD_RTMR2]);

        // different rtmr3, not equal
        report_peer[Report::R_MIGTD_RTMR3].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            &report_peer,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
    }

    #[test]
    fn test_verify_eventlog_comp() {
        let template = include_bytes!("../../test/report.dat");

        let policy_bytes = include_bytes!("../../test/policy_full2.json");
        // Invalid event log
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &BTreeMap::new(),
            template,
            &BTreeMap::new(),
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));

        let mut evt1 = BTreeMap::new();
        let payload = [0, 1, 2];

        let blob2 = UefiPlatformFirmwareBlob2::new(
            PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
            payload.as_ptr() as u64,
            payload.len() as u64,
        )
        .expect("Invalid payload binary information or descriptor");

        evt1.insert(
            EventName::MigTdCore,
            create_event(
                2,
                EV_EFI_PLATFORM_FIRMWARE_BLOB2,
                &payload,
                &[blob2.as_bytes()],
                None,
            ),
        );

        let verify_result = verify_policy(true, policy_bytes, template, &evt1, template, &evt1);
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
    }

    fn create_event(
        mr_index: u32,
        event_type: u32,
        data_to_hash: &[u8],
        event_data: &[&[u8]],
        data: Option<Vec<u8>>,
    ) -> CcEvent {
        let digest = digest_sha384(&data_to_hash).unwrap();
        let event_header = CcEventHeader {
            mr_index,
            event_type,
            digest: TpmlDigestValues {
                count: 1,
                digests: [TpmtHa {
                    hash_alg: TPML_ALG_SHA384,
                    digest: TpmuHa {
                        sha384: digest.try_into().unwrap(),
                    },
                }],
            },
            event_size: event_data.iter().map(|s| s.len()).sum::<usize>() as u32,
        };

        CcEvent {
            header: event_header,
            data,
        }
    }

    fn create_events(
        payload: &[u8],
        trust_anchor: Option<&[u8]>,
        payload_svn: Option<&[u8]>,
        policy: &[u8],
        root_key: &[u8],
    ) -> BTreeMap<EventName, CcEvent> {
        const EVENT_TYPE: u32 = 0x00000006;
        const POLICY_EVENT_ID: u32 = 0x1;
        const ROOT_CA_EVENT_ID: u32 = 0x2;

        let mut events = BTreeMap::new();

        // Log the payload binary
        let blob2 = UefiPlatformFirmwareBlob2::new(
            PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
            payload.as_ptr() as u64,
            payload.len() as u64,
        )
        .unwrap();
        events.insert(
            EventName::MigTdCore,
            create_event(
                2,
                EV_EFI_PLATFORM_FIRMWARE_BLOB2,
                payload,
                &[blob2.as_bytes()],
                None,
            ),
        );

        // Log the trust_anchor (secure boot public key hash)
        trust_anchor.and_then(|anchor| {
            let config_header = TdShimPlatformConfigInfoHeader::new(
                PLATFORM_CONFIG_SECURE_AUTHORITY,
                anchor.len() as u32,
            )
            .unwrap();
            events.insert(
                EventName::SecureBootKey,
                create_event(
                    1,
                    EV_PLATFORM_CONFIG_FLAGS,
                    anchor,
                    &[config_header.as_bytes(), anchor],
                    None,
                ),
            )
        });
        // Log the payload svn
        payload_svn.and_then(|svn| {
            let config_header =
                TdShimPlatformConfigInfoHeader::new(PLATFORM_CONFIG_SVN, svn.len() as u32).unwrap();

            events.insert(
                EventName::MigTdCoreSvn,
                create_event(
                    1,
                    EV_PLATFORM_CONFIG_FLAGS,
                    svn,
                    &[config_header.as_bytes(), svn],
                    Some(svn.to_vec()),
                ),
            )
        });

        // Log the migration policy
        let mut policy_event = Vec::new();
        policy_event.extend_from_slice(&POLICY_EVENT_ID.to_le_bytes());
        policy_event.extend_from_slice(&(policy.len() as u32).to_le_bytes());
        policy_event.extend_from_slice(policy);
        events.insert(
            EventName::MigTdPolicy,
            create_event(3, EVENT_TYPE, policy, &[&policy_event], None),
        );

        // Log the sgx attestation root key
        let mut root_key_event = Vec::new();
        root_key_event.extend_from_slice(&ROOT_CA_EVENT_ID.to_le_bytes());
        root_key_event.extend_from_slice(&(root_key.len() as u32).to_le_bytes());
        root_key_event.extend_from_slice(root_key);
        events.insert(
            EventName::SgxRootKey,
            create_event(3, EVENT_TYPE, root_key, &[root_key_event.as_slice()], None),
        );

        events
    }

    #[test]
    fn test_eventlogpolicy_verify() {
        let payload = vec![0xffu8; 256];
        let policy = include_str!("../../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let local_events = create_events(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );
        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(true, &event_log_policy, &local_events, &local_events).is_ok());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_payload() {
        let payload = vec![0xffu8; 1024];
        let policy = include_str!("../../test/policy.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let local_events = create_events(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let payload_peer = vec![0xfeu8; 1024];
        let peer_events = create_events(
            payload_peer.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(true, &event_log_policy, &local_events, &peer_events,).is_err());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_trust_anchor() {
        let payload = vec![0xffu8; 1024];
        let policy = include_str!("../../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let local_events = create_events(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let trust_anchor_peer = vec![0xfeu8; 128];
        let peer_events = create_events(
            payload.as_slice(),
            Some(trust_anchor_peer.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(true, &event_log_policy, &local_events, &peer_events,).is_err());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_svn() {
        let payload = vec![0xffu8; 1024];
        let policy = include_str!("../../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0x20);
        let root_key = vec![0xffu8; 96];

        let local_events = create_events(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(true, &event_log_policy, &local_events, &local_events,).is_err());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_policy() {
        let payload: Vec<u8> = vec![0xffu8; 1024];
        let policy = include_str!("../../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let local_events = create_events(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let policy_peer = include_bytes!("../../test/policy_invalid_guid.json");
        let peer_events = create_events(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy_peer,
            root_key.as_slice(),
        );

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(true, &event_log_policy, &local_events, &peer_events,).is_err());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_root_key() {
        let payload = vec![0xffu8; 1024];
        let policy = include_str!("../../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let local_events = create_events(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let root_key_peer = vec![0xfeu8; 96];
        let peer_events = create_events(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key_peer.as_slice(),
        );

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(true, &event_log_policy, &local_events, &peer_events,).is_err());
    }

    #[test]
    fn test_xfam_mask() {
        let mut xfam = [0u8; 8];

        xfam.copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        mask_bytes_array(&mut xfam, &MIGTD_XFAM_MASK);
        assert_eq!(&xfam, &[0x3, 0x18, 0x0, 0, 0, 0, 0, 0]);

        xfam.copy_from_slice(&[0x3, 0x18, 0x0, 0, 0, 0, 0, 0]);
        mask_bytes_array(&mut xfam, &MIGTD_XFAM_MASK);
        assert_eq!(&xfam, &[0x3, 0x18, 0x0, 0, 0, 0, 0, 0]);

        xfam.copy_from_slice(&[0xe7, 0x1a, 0x6, 0, 0, 0, 0, 0]);
        mask_bytes_array(&mut xfam, &MIGTD_XFAM_MASK);
        assert_eq!(&xfam, &[0x3, 0x18, 0x0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_attribute_mask() {
        let mut attributes = [0u8; 8];

        attributes.copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        mask_bytes_array(&mut attributes, &MIGTD_ATTRIBUTES_MASK);
        assert_eq!(
            &attributes,
            &[0xff, 0xff, 0x00, 0x30, 0x00, 0x00, 0x00, 0x40]
        );

        attributes.copy_from_slice(&[0xff, 0xff, 0x00, 0x30, 0x00, 0x00, 0x00, 0x40]);
        mask_bytes_array(&mut attributes, &MIGTD_ATTRIBUTES_MASK);
        assert_eq!(
            &attributes,
            &[0xff, 0xff, 0x00, 0x30, 0x00, 0x00, 0x00, 0x40]
        );

        attributes.copy_from_slice(&[0, 0, 0, 0x8, 0, 0, 0, 0]);
        mask_bytes_array(&mut attributes, &MIGTD_ATTRIBUTES_MASK);
        assert_eq!(&attributes, &[0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
