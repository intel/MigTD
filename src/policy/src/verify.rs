// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{convert::TryInto, ops::Range};

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use cc_measurement::{
    log::CcEventLogReader, CcEventHeader, EV_EFI_PLATFORM_FIRMWARE_BLOB2, EV_PLATFORM_CONFIG_FLAGS,
};
use crypto::hash::digest_sha384;
use td_shim::event_log::{
    PLATFORM_CONFIG_SECURE_AUTHORITY, PLATFORM_CONFIG_SVN, PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
};

use crate::{
    config::{MigPolicy, Property},
    PolicyError,
};

const TD_REPORT_LEN: usize = 1024;
const MAX_RTMR_INDEX: usize = 3;
const EV_EVENT_TAG: u32 = 0x00000006;
const TAGGED_EVENT_ID_POLICY: u32 = 0x1;
const TAGGED_EVENT_ID_ROOT_CA: u32 = 0x2;

struct Report<'a> {
    tee_tcb_info: BTreeMap<TeeTcbInfoProperty, &'a [u8]>,
    td_info: BTreeMap<TdInfoProperty, &'a [u8]>,
}

impl<'a> Report<'a> {
    const R_TEE_TCB_SVN: Range<usize> = 264..280;
    const R_MRSEAM: Range<usize> = 280..328;
    const R_MRSEAMSIGNER: Range<usize> = 328..376;
    const R_ATTR_SEAM: Range<usize> = 376..384;
    const R_ATTR_TD: Range<usize> = 512..520;
    const R_XFAM: Range<usize> = 520..528;
    const R_MRTD: Range<usize> = 528..576;
    const R_MRCONFIGID: Range<usize> = 576..624;
    const R_MROWNER: Range<usize> = 624..672;
    const R_MROWNERCONFIG: Range<usize> = 672..720;
    const R_RTMR0: Range<usize> = 720..768;
    const R_RTMR1: Range<usize> = 768..816;
    const R_RTMR2: Range<usize> = 816..864;
    const R_RTMR3: Range<usize> = 864..912;

    pub fn read_from_raw_report(report: &'a [u8]) -> Self {
        let mut tee_tcb_info = BTreeMap::new();

        tee_tcb_info.insert(TeeTcbInfoProperty::TeeTcbSvn, &report[Self::R_TEE_TCB_SVN]);
        tee_tcb_info.insert(TeeTcbInfoProperty::MrSeam, &report[Self::R_MRSEAM]);
        tee_tcb_info.insert(
            TeeTcbInfoProperty::MrSignerSeam,
            &report[Self::R_MRSEAMSIGNER],
        );
        tee_tcb_info.insert(TeeTcbInfoProperty::Attributes, &report[Self::R_ATTR_SEAM]);

        let mut td_info = BTreeMap::new();
        td_info.insert(TdInfoProperty::Attributes, &report[Self::R_ATTR_TD]);
        td_info.insert(TdInfoProperty::Xfam, &report[Self::R_XFAM]);
        td_info.insert(TdInfoProperty::MrTd, &report[Self::R_MRTD]);
        td_info.insert(TdInfoProperty::MrConfigId, &report[Self::R_MRCONFIGID]);
        td_info.insert(TdInfoProperty::MrOwner, &report[Self::R_MROWNER]);
        td_info.insert(
            TdInfoProperty::MrOwnerConfig,
            &report[Self::R_MROWNERCONFIG],
        );
        td_info.insert(TdInfoProperty::Rtmr0, &report[Self::R_RTMR0]);
        td_info.insert(TdInfoProperty::Rtmr1, &report[Self::R_RTMR1]);
        td_info.insert(TdInfoProperty::Rtmr2, &report[Self::R_RTMR2]);
        td_info.insert(TdInfoProperty::Rtmr3, &report[Self::R_RTMR3]);

        Report {
            tee_tcb_info,
            td_info,
        }
    }

    pub fn get_td_info_property(&self, name: &TdInfoProperty) -> Result<&[u8], PolicyError> {
        self.td_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
    }

    pub fn get_tee_tcb_info_property(
        &self,
        name: &TeeTcbInfoProperty,
    ) -> Result<&[u8], PolicyError> {
        self.tee_tcb_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TeeTcbInfoProperty {
    TeeTcbSvn,
    MrSeam,
    MrSignerSeam,
    Attributes,
    Unknown,
}

impl From<&str> for TeeTcbInfoProperty {
    fn from(value: &str) -> Self {
        match value {
            "TEE_TCB_SVN.SEAM" => Self::TeeTcbSvn,
            "MRSEAM" => Self::MrSeam,
            "MRSIGNERSEAM" => Self::MrSignerSeam,
            "ATTRIBUTES" => Self::Attributes,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TdInfoProperty {
    Attributes,
    Xfam,
    MrTd,
    MrConfigId,
    MrOwner,
    MrOwnerConfig,
    Rtmr0,
    Rtmr1,
    Rtmr2,
    Rtmr3,
    Unknown,
}

impl From<&str> for TdInfoProperty {
    fn from(value: &str) -> Self {
        match value {
            "ATTRIBUTES" => Self::Attributes,
            "XFAM" => Self::Xfam,
            "MRTD" => Self::MrTd,
            "MRCONFIGID" => Self::MrConfigId,
            "MROWNER" => Self::MrOwner,
            "MROWNERCONFIG" => Self::MrOwnerConfig,
            "RTMR0" => Self::Rtmr0,
            "RTMR1" => Self::Rtmr1,
            "RTMR2" => Self::Rtmr2,
            "RTMR3" => Self::Rtmr3,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum EventName {
    TdShim,
    SecureBootKey,
    MigTdCore,
    MigTdCoreSvn,
    MigTdPolicy,
    SgxRootKey,
    Unknown,
}

impl From<&str> for EventName {
    fn from(value: &str) -> Self {
        match value {
            "Digest.TdShim" => Self::TdShim,
            "Digest.SecureBootKey" => Self::SecureBootKey,
            "Digest.MigTdCore" => Self::MigTdCore,
            "Digest.MigTdCoreSvn" => Self::MigTdCoreSvn,
            "Digest.MigTdPolicy" => Self::MigTdPolicy,
            "Digest.MigTdSgxRootKey" => Self::SgxRootKey,
            _ => Self::Unknown,
        }
    }
}

pub fn verify_policy(
    is_src: bool,
    policy: &[u8],
    report: &[u8],
    event_log: &[u8],
    report_peer: &[u8],
    event_log_peer: &[u8],
) -> Result<(), PolicyError> {
    if report.len() < TD_REPORT_LEN || report_peer.len() < TD_REPORT_LEN {
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

    let report_local = Report::read_from_raw_report(report);
    let report_peer = Report::read_from_raw_report(report_peer);

    if let Some(policy) = policy.migtd.tee_tcb_info.as_ref() {
        verify_tee_tcb_info(is_src, policy, &report_local, &report_peer)?;
    }

    if let Some(policy) = policy.migtd.td_info.as_ref() {
        verify_td_info(is_src, policy, &report_local, &report_peer)?;
    }

    if let Some(policy) = policy.migtd.event_log.as_ref() {
        replay_event_log(event_log_peer, &report_peer)?;

        if let (Some(log_local), Some(log_peer)) =
            (parse_events(event_log), parse_events(event_log_peer))
        {
            verify_event_log(is_src, policy, &log_local, &log_peer)?;
        } else {
            return Err(PolicyError::InvalidEventLog);
        }
    }

    Ok(())
}

fn verify_tee_tcb_info(
    is_src: bool,
    policy: &BTreeMap<String, Property>,
    local_report: &Report,
    peer_report: &Report,
) -> Result<(), PolicyError> {
    let mut verify_result = true;

    for (property, action) in policy {
        let property = TeeTcbInfoProperty::from(property.as_str());
        verify_result &= action.verify(
            is_src,
            local_report.get_tee_tcb_info_property(&property)?,
            peer_report.get_tee_tcb_info_property(&property)?,
        );
    }

    if verify_result {
        Ok(())
    } else {
        Err(PolicyError::UnqulifiedTeeTcbInfo)
    }
}

fn verify_td_info(
    is_src: bool,
    policy: &BTreeMap<String, Property>,
    local_report: &Report,
    peer_report: &Report,
) -> Result<(), PolicyError> {
    let mut verify_result = true;

    for (property, action) in policy {
        let property = TdInfoProperty::from(property.as_str());
        verify_result &= action.verify(
            is_src,
            local_report.get_td_info_property(&property)?,
            peer_report.get_td_info_property(&property)?,
        );
    }

    if verify_result {
        Ok(())
    } else {
        Err(PolicyError::UnqulifiedTdInfo)
    }
}

struct CcEvent {
    header: CcEventHeader,
    data: Option<Vec<u8>>,
}

impl CcEvent {
    pub fn new(header: CcEventHeader, data: Option<Vec<u8>>) -> Self {
        Self { header, data }
    }
}

fn parse_events(event_log: &[u8]) -> Option<BTreeMap<EventName, CcEvent>> {
    let mut map: BTreeMap<EventName, CcEvent> = BTreeMap::new();
    let reader = CcEventLogReader::new(event_log)?;

    for (event_header, event_data) in reader.cc_events {
        match event_header.event_type {
            EV_EFI_PLATFORM_FIRMWARE_BLOB2 => {
                let desc_size = event_data[0] as usize;
                if &event_data[1..1 + desc_size] == PLATFORM_FIRMWARE_BLOB2_PAYLOAD {
                    map.insert(EventName::MigTdCore, CcEvent::new(event_header, None));
                }
            }
            EV_PLATFORM_CONFIG_FLAGS => {
                if event_data.starts_with(PLATFORM_CONFIG_SECURE_AUTHORITY) {
                    map.insert(EventName::SecureBootKey, CcEvent::new(event_header, None));
                } else if event_data.starts_with(PLATFORM_CONFIG_SVN) {
                    if event_data.len() < 20 {
                        return None;
                    }
                    let info_size: usize =
                        u32::from_le_bytes(event_data[16..20].try_into().unwrap()) as usize;
                    if event_data.len() < 20 + info_size {
                        return None;
                    }
                    map.insert(
                        EventName::MigTdCoreSvn,
                        CcEvent::new(event_header, Some(event_data[20..20 + info_size].to_vec())),
                    );
                }
            }
            EV_EVENT_TAG => {
                let tag_id = u32::from_le_bytes(event_data[..4].try_into().ok()?);
                if tag_id == TAGGED_EVENT_ID_POLICY {
                    map.insert(EventName::MigTdPolicy, CcEvent::new(event_header, None));
                } else if tag_id == TAGGED_EVENT_ID_ROOT_CA {
                    map.insert(EventName::SgxRootKey, CcEvent::new(event_header, None));
                }
            }
            _ => {}
        }
    }

    Some(map)
}

fn replay_event_log(event_log: &[u8], report_peer: &Report) -> Result<(), PolicyError> {
    let mut rtmrs: [[u8; 96]; 4] = [[0; 96]; 4];

    let event_log = if let Some(event_log) = CcEventLogReader::new(event_log) {
        event_log
    } else {
        return Err(PolicyError::InvalidEventLog);
    };

    for (event_header, _) in event_log.cc_events {
        let rtmr_index = match event_header.mr_index {
            0 => 0xFF,
            1..=4 => event_header.mr_index - 1,
            _ => 0xFF,
        } as usize;

        if rtmr_index <= MAX_RTMR_INDEX {
            rtmrs[rtmr_index][48..].copy_from_slice(&event_header.digest.digests[0].digest.sha384);
            if let Ok(digest) = digest_sha384(&rtmrs[rtmr_index]) {
                rtmrs[rtmr_index][0..48].copy_from_slice(&digest);
            } else {
                return Err(PolicyError::Crypto);
            }
        } else {
            return Err(PolicyError::InvalidEventLog);
        }
    }

    if report_peer.get_td_info_property(&TdInfoProperty::Rtmr0)? == &rtmrs[0][0..48]
        && report_peer.get_td_info_property(&TdInfoProperty::Rtmr1)? == &rtmrs[1][0..48]
        && report_peer.get_td_info_property(&TdInfoProperty::Rtmr2)? == &rtmrs[2][0..48]
        && report_peer.get_td_info_property(&TdInfoProperty::Rtmr3)? == &rtmrs[3][0..48]
    {
        Ok(())
    } else {
        Err(PolicyError::InvalidEventLog)
    }
}

fn verify_event_log(
    is_src: bool,
    policy: &BTreeMap<String, Property>,
    local_event_log: &BTreeMap<EventName, CcEvent>,
    peer_event_log: &BTreeMap<EventName, CcEvent>,
) -> Result<(), PolicyError> {
    let mut verify_result = true;

    for (property, value) in policy {
        let event_name = property.as_str().into();

        if event_name == EventName::Unknown {
            return Err(PolicyError::InvalidEventLog);
        }

        verify_result &= verify_event(is_src, &event_name, value, local_event_log, peer_event_log);
    }

    if verify_result {
        Ok(())
    } else {
        Err(PolicyError::UnqulifiedEventLog)
    }
}

fn verify_event(
    is_src: bool,
    event_name: &EventName,
    policy: &Property,
    local_event_log: &BTreeMap<EventName, CcEvent>,
    peer_event_log: &BTreeMap<EventName, CcEvent>,
) -> bool {
    if let (Some(local), Some(peer)) = (
        local_event_log.get(event_name),
        peer_event_log.get(event_name),
    ) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec};
    use cc_measurement::log::{CcEventLogError, CcEventLogWriter};
    use cc_measurement::UefiPlatformFirmwareBlob2;

    const SHA384_DIGEST_SIZE: usize = 48;
    type Result<T> = core::result::Result<T, CcEventLogError>;

    fn extender(_digest: &[u8; SHA384_DIGEST_SIZE], _mr_index: u32) -> Result<()> {
        // Do nothing
        Ok(())
    }

    #[test]
    fn test_verify_invalid_parameter() {
        let policy_bytes = include_bytes!("../test/policy.json");
        let verify_result = verify_policy(
            true,
            policy_bytes,
            &[0u8; TD_REPORT_LEN - 1],
            &[0u8; 8],
            &[0u8; TD_REPORT_LEN],
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::InvalidParameter));

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &[0u8; TD_REPORT_LEN],
            &[0u8; 8],
            &[0u8; TD_REPORT_LEN - 1],
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::InvalidParameter));
    }

    #[test]
    fn test_verify_with_tee_tcb_info_comp() {
        let mut report = [0u8; 1024];

        // TEE_TCB_SVN.SEAM
        report[264..280].copy_from_slice(&[1u8; 16]);

        let policy_bytes = include_bytes!("../test/policy_full1.json");
        let verify_result =
            verify_policy(true, policy_bytes, &report, &[0u8; 8], &report, &[0u8; 8]);
        assert!(verify_result.is_ok());

        // peer's svn smaller than src
        let mut report_peer = [0u8; 1024];

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTeeTcbInfo));

        // dst's svn is greater than src
        report_peer[Report::R_TEE_TCB_SVN].copy_from_slice(&[2u8; 16]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(verify_result.is_ok());

        // src's svn is greater than dst
        let verify_result = verify_policy(
            false,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTeeTcbInfo));

        // different mrseam, not equal
        report_peer[Report::R_MRSEAM].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTeeTcbInfo));
        report_peer[Report::R_MRSEAM].copy_from_slice(&[0u8; 48]);

        // different mrsigner_seam, not equal
        report_peer[Report::R_MRSEAMSIGNER].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTeeTcbInfo));
        report_peer[Report::R_MRSEAMSIGNER].copy_from_slice(&[0u8; 48]);

        // different attributes, not equal
        report_peer[Report::R_ATTR_SEAM].copy_from_slice(&[1u8; 8]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTeeTcbInfo));
    }

    // Different MRTD value, no MRTD policy in policy data
    #[test]
    fn test_verify_tdinfo_comp() {
        let report = [0u8; 1024];

        let policy_bytes = include_bytes!("../test/policy_no.json");
        let verify_result =
            verify_policy(true, policy_bytes, &report, &[0u8; 8], &report, &[0u8; 8]);
        assert!(verify_result.is_ok());

        // different attributes, not equal, but attributes is not in policy
        let policy_bytes = include_bytes!("../test/policy_no_tdattr.json");
        let mut report_peer = [0u8; 1024];

        report_peer[Report::R_ATTR_TD].copy_from_slice(&[1u8; 8]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(verify_result.is_ok());
        report_peer[Report::R_ATTR_TD].copy_from_slice(&[0u8; 8]);

        let policy_bytes = include_bytes!("../test/policy_full1.json");
        // different attributes, not equal
        report_peer[Report::R_ATTR_TD].copy_from_slice(&[1u8; 8]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
        report_peer[Report::R_ATTR_TD].copy_from_slice(&[0u8; 8]);

        // different xfam, not equal
        report_peer[Report::R_XFAM].copy_from_slice(&[1u8; 8]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
        report_peer[Report::R_XFAM].copy_from_slice(&[0u8; 8]);

        // different mrtd, not equal
        report_peer[Report::R_MRTD].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
        report_peer[Report::R_MRTD].copy_from_slice(&[0u8; 48]);

        // different mrconfig_id, not equal
        report_peer[Report::R_MRCONFIGID].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
        report_peer[Report::R_MRCONFIGID].copy_from_slice(&[0u8; 48]);

        // different mrowner, not equal
        report_peer[Report::R_MROWNER].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
        report_peer[Report::R_MROWNER].copy_from_slice(&[0u8; 48]);

        // different mrownerconfig, not equal
        report_peer[Report::R_MROWNERCONFIG].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
        report_peer[Report::R_MROWNERCONFIG].copy_from_slice(&[0u8; 48]);

        // different rtmr0, not equal
        report_peer[Report::R_RTMR0].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
        report_peer[Report::R_RTMR0].copy_from_slice(&[0u8; 48]);

        // different rtmr1, not equal
        report_peer[Report::R_RTMR1].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
        report_peer[Report::R_RTMR1].copy_from_slice(&[0u8; 48]);

        // different rtmr2, not equal
        report_peer[Report::R_RTMR2].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
        report_peer[Report::R_RTMR2].copy_from_slice(&[0u8; 48]);

        // different rtmr3, not equal
        report_peer[Report::R_RTMR3].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert_eq!(verify_result, Err(PolicyError::UnqulifiedTdInfo));
    }

    #[test]
    fn test_verify_eventlog_comp() {
        let report = [0u8; 1024];

        let policy_bytes = include_bytes!("../test/policy_full2.json");
        // Invalid event log
        let verify_result =
            verify_policy(true, policy_bytes, &report, &[0u8; 8], &report, &[0u8; 8]);
        assert_eq!(verify_result, Err(PolicyError::InvalidEventLog));

        let mut evt1 = vec![0u8; 0x1000];
        let payload = [0, 1, 2];

        let mut writter = CcEventLogWriter::new(&mut evt1, Box::new(extender)).unwrap();

        let blob2 = UefiPlatformFirmwareBlob2::new(
            PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
            payload.as_ptr() as u64,
            payload.len() as u64,
        )
        .expect("Invalid payload binary information or descriptor");

        writter
            .create_event_log(
                2,
                EV_EFI_PLATFORM_FIRMWARE_BLOB2,
                &[blob2.as_bytes()],
                &payload,
            )
            .unwrap();

        let verify_result = verify_policy(true, policy_bytes, &report, &evt1, &report, &evt1);
        assert_eq!(verify_result, Err(PolicyError::InvalidEventLog));
    }

    fn create_event_log(
        payload: &[u8],
        trust_anchor: Option<&[u8]>,
        payload_svn: Option<&[u8]>,
        policy: &[u8],
        root_key: &[u8],
    ) -> Vec<u8> {
        let mut event_log = vec![0u8; 4096];

        fn extender(
            _digest: &[u8; 48],
            _mr_index: u32,
        ) -> core::result::Result<(), CcEventLogError> {
            Ok(())
        }
        let mut writter = CcEventLogWriter::new(&mut event_log, Box::new(extender)).unwrap();

        // Log the payload binary
        td_shim::event_log::log_payload_binary(payload, &mut writter);
        // Log the trust_anchor (secure boot public key hash)
        trust_anchor.and_then(|anchor| {
            td_shim::event_log::create_event_log_platform_config(
                &mut writter,
                1,
                PLATFORM_CONFIG_SECURE_AUTHORITY,
                anchor,
            )
            .ok()
        });
        // Log the payload svn
        payload_svn.and_then(|svn| {
            td_shim::event_log::create_event_log_platform_config(
                &mut writter,
                1,
                PLATFORM_CONFIG_SVN,
                svn,
            )
            .ok()
        });

        // Log the migration policy
        let mut policy_event = Vec::new();
        policy_event.extend_from_slice(&TAGGED_EVENT_ID_POLICY.to_le_bytes());
        policy_event.extend_from_slice(&(policy.len() as u32).to_le_bytes());
        policy_event.extend_from_slice(policy);
        writter
            .create_event_log(3, EV_EVENT_TAG, &[policy_event.as_slice()], policy)
            .unwrap();

        // Log the sgx attestation root key
        let mut root_key_event = Vec::new();
        root_key_event.extend_from_slice(&TAGGED_EVENT_ID_ROOT_CA.to_le_bytes());
        root_key_event.extend_from_slice(&(root_key.len() as u32).to_le_bytes());
        root_key_event.extend_from_slice(root_key);
        writter
            .create_event_log(3, EV_EVENT_TAG, &[root_key_event.as_slice()], root_key)
            .unwrap();

        event_log
    }

    #[test]
    fn test_eventlogpolicy_verify() {
        let payload = vec![0xffu8; 256];
        let policy = include_str!("../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let event_log = create_event_log(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );
        let event_log_policy = serde_json::from_str::<MigPolicy>(policy)
            .unwrap()
            .migtd
            .event_log
            .unwrap();
        let local_events = parse_events(&event_log).unwrap();

        assert!(verify_event_log(true, &event_log_policy, &local_events, &local_events).is_ok());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_payload() {
        let payload = vec![0xffu8; 1024];
        let policy = include_str!("../test/policy.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let local_events = create_event_log(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let payload_peer = vec![0xfeu8; 1024];
        let peer_events = create_event_log(
            payload_peer.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let event_log_policy = serde_json::from_str::<MigPolicy>(policy)
            .unwrap()
            .migtd
            .event_log
            .unwrap();

        assert!(verify_event_log(
            true,
            &event_log_policy,
            &parse_events(&local_events).unwrap(),
            &parse_events(&peer_events).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_trust_anchor() {
        let payload = vec![0xffu8; 1024];
        let policy = include_str!("../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let local_events = create_event_log(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let trust_anchor_peer = vec![0xfeu8; 128];
        let peer_events = create_event_log(
            payload.as_slice(),
            Some(trust_anchor_peer.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let event_log_policy = serde_json::from_str::<MigPolicy>(policy)
            .unwrap()
            .migtd
            .event_log
            .unwrap();

        assert!(verify_event_log(
            true,
            &event_log_policy,
            &parse_events(&local_events).unwrap(),
            &parse_events(&peer_events).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_svn() {
        let payload = vec![0xffu8; 1024];
        let policy = include_str!("../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0x20);
        let root_key = vec![0xffu8; 96];

        let local_events = create_event_log(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let event_log_policy = serde_json::from_str::<MigPolicy>(policy)
            .unwrap()
            .migtd
            .event_log
            .unwrap();

        assert!(verify_event_log(
            true,
            &event_log_policy,
            &parse_events(&local_events).unwrap(),
            &parse_events(&local_events).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_policy() {
        let payload: Vec<u8> = vec![0xffu8; 1024];
        let policy = include_str!("../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let local_events = create_event_log(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let policy_peer = include_bytes!("../test/policy_invalid_guid.json");
        let peer_events = create_event_log(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy_peer,
            root_key.as_slice(),
        );

        let event_log_policy =
            serde_json::from_str::<MigPolicy>(include_str!("../test/policy_full2.json"))
                .unwrap()
                .migtd
                .event_log
                .unwrap();

        assert!(verify_event_log(
            true,
            &event_log_policy,
            &parse_events(&local_events).unwrap(),
            &parse_events(&peer_events).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn test_eventlogpolicy_verify_mismatch_root_key() {
        let payload = vec![0xffu8; 1024];
        let policy = include_str!("../test/policy_full2.json");
        let trust_anchor = vec![0xffu8; 128];
        let svn = u64::to_le_bytes(0xf);
        let root_key = vec![0xffu8; 96];

        let local_events = create_event_log(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key.as_slice(),
        );

        let root_key_peer = vec![0xfeu8; 96];
        let peer_events = create_event_log(
            payload.as_slice(),
            Some(trust_anchor.as_slice()),
            Some(svn.as_slice()),
            policy.as_bytes(),
            root_key_peer.as_slice(),
        );

        let event_log_policy = serde_json::from_str::<MigPolicy>(policy)
            .unwrap()
            .migtd
            .event_log
            .unwrap();

        assert!(verify_event_log(
            true,
            &event_log_policy,
            &parse_events(&local_events).unwrap(),
            &parse_events(&peer_events).unwrap(),
        )
        .is_err());
    }
}
