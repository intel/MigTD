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
    format_bytes_hex, MigTdInfo, PlatformInfo, PolicyError, PolicyErrorDetails, QeInfo,
    TdxModuleInfo,
};

const REPORT_DATA_SIZE: usize = 734;
const MAX_RTMR_INDEX: usize = 3;
const EV_EVENT_TAG: u32 = 0x00000006;
const TAGGED_EVENT_ID_POLICY: u32 = 0x1;
const TAGGED_EVENT_ID_ROOT_CA: u32 = 0x2;

struct Report<'a> {
    platform_info: BTreeMap<PlatformInfoProperty, &'a [u8]>,
    qe_info: BTreeMap<QeInfoProperty, &'a [u8]>,
    tdx_module_info: BTreeMap<TdxModuleInfoProperty, &'a [u8]>,
    migtd_info: BTreeMap<MigTdInfoProperty, &'a [u8]>,
}

impl<'a> Report<'a> {
    const R_MRSEAM: Range<usize> = 16..64;
    const R_MRSEAMSIGNER: Range<usize> = 64..112;
    const R_ATTR_SEAM: Range<usize> = 112..120;
    const R_ATTR_TD: Range<usize> = 120..128;
    const R_XFAM: Range<usize> = 128..136;
    const R_MRTD: Range<usize> = 136..184;
    const R_MRCONFIGID: Range<usize> = 184..232;
    const R_MROWNER: Range<usize> = 232..280;
    const R_MROWNERCONFIG: Range<usize> = 280..328;
    const R_RTMR0: Range<usize> = 328..376;
    const R_RTMR1: Range<usize> = 376..424;
    const R_RTMR2: Range<usize> = 424..472;
    const R_RTMR3: Range<usize> = 472..520;
    const R_FMSPC: Range<usize> = 584..590;
    const R_TDX_TCB_COMPONENTS: Range<usize> = 590..606;
    const R_PCE_SVN: Range<usize> = 606..608;
    const R_SGX_TCB_COMPONENTS: Range<usize> = 608..624;
    const R_TDX_MODULE_MAJOR_VER: Range<usize> = 624..625;
    const R_TDX_MODULE_SVN: Range<usize> = 625..626;
    const R_MISC_SELECT: Range<usize> = 626..630;
    const R_ATTRIBUTES: Range<usize> = 634..650;
    const R_MRENCLAVE: Range<usize> = 666..698;
    const R_MRSIGNER: Range<usize> = 698..730;
    const R_ISV_PRO_ID: Range<usize> = 730..732;
    const R_ISV_SVN: Range<usize> = 732..734;

    pub fn new(report: &'a [u8]) -> Result<Self, PolicyError> {
        if report.len() != REPORT_DATA_SIZE {
            return Err(PolicyError::InvalidParameter);
        }

        let mut platform_info = BTreeMap::new();
        platform_info.insert(PlatformInfoProperty::Fmspc, &report[Self::R_FMSPC]);
        platform_info.insert(
            PlatformInfoProperty::SgxTcbComponents,
            &report[Self::R_SGX_TCB_COMPONENTS],
        );
        platform_info.insert(PlatformInfoProperty::PceSvn, &report[Self::R_PCE_SVN]);
        platform_info.insert(
            PlatformInfoProperty::TdxTcbComponents,
            &report[Self::R_TDX_TCB_COMPONENTS],
        );

        let mut qe_info = BTreeMap::new();
        qe_info.insert(QeInfoProperty::MiscSelect, &report[Self::R_MISC_SELECT]);
        qe_info.insert(QeInfoProperty::Attributes, &report[Self::R_ATTRIBUTES]);
        qe_info.insert(QeInfoProperty::MrEnclave, &report[Self::R_MRENCLAVE]);
        qe_info.insert(QeInfoProperty::MrSigner, &report[Self::R_MRSIGNER]);
        qe_info.insert(QeInfoProperty::IsvProID, &report[Self::R_ISV_PRO_ID]);
        qe_info.insert(QeInfoProperty::IsvSvn, &report[Self::R_ISV_SVN]);

        let mut tdx_module_info = BTreeMap::new();
        tdx_module_info.insert(
            TdxModuleInfoProperty::TdxModuleMajorVersion,
            &report[Self::R_TDX_MODULE_MAJOR_VER],
        );
        tdx_module_info.insert(
            TdxModuleInfoProperty::TdxModuleSvn,
            &report[Self::R_TDX_MODULE_SVN],
        );
        tdx_module_info.insert(TdxModuleInfoProperty::MrSeam, &report[Self::R_MRSEAM]);
        tdx_module_info.insert(
            TdxModuleInfoProperty::MrSignerSeam,
            &report[Self::R_MRSEAMSIGNER],
        );
        tdx_module_info.insert(
            TdxModuleInfoProperty::Attributes,
            &report[Self::R_ATTR_SEAM],
        );

        let mut migtd_info = BTreeMap::new();
        migtd_info.insert(MigTdInfoProperty::Attributes, &report[Self::R_ATTR_TD]);
        migtd_info.insert(MigTdInfoProperty::Xfam, &report[Self::R_XFAM]);
        migtd_info.insert(MigTdInfoProperty::MrTd, &report[Self::R_MRTD]);
        migtd_info.insert(MigTdInfoProperty::MrConfigId, &report[Self::R_MRCONFIGID]);
        migtd_info.insert(MigTdInfoProperty::MrOwner, &report[Self::R_MROWNER]);
        migtd_info.insert(
            MigTdInfoProperty::MrOwnerConfig,
            &report[Self::R_MROWNERCONFIG],
        );
        migtd_info.insert(MigTdInfoProperty::Rtmr0, &report[Self::R_RTMR0]);
        migtd_info.insert(MigTdInfoProperty::Rtmr1, &report[Self::R_RTMR1]);
        migtd_info.insert(MigTdInfoProperty::Rtmr2, &report[Self::R_RTMR2]);
        migtd_info.insert(MigTdInfoProperty::Rtmr3, &report[Self::R_RTMR3]);

        Ok(Report {
            platform_info,
            qe_info,
            tdx_module_info,
            migtd_info,
        })
    }

    pub fn get_platform_info_property(
        &self,
        name: &PlatformInfoProperty,
    ) -> Result<&[u8], PolicyError> {
        self.platform_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
    }

    pub fn get_qe_info_property(&self, name: &QeInfoProperty) -> Result<&[u8], PolicyError> {
        self.qe_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
    }

    pub fn get_tdx_module_info_property(
        &self,
        name: &TdxModuleInfoProperty,
    ) -> Result<&[u8], PolicyError> {
        self.tdx_module_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
    }

    pub fn get_migtd_info_property(&self, name: &MigTdInfoProperty) -> Result<&[u8], PolicyError> {
        self.migtd_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PlatformInfoProperty {
    Fmspc,
    SgxTcbComponents,
    PceSvn,
    TdxTcbComponents,
    Unknown,
}

impl From<&str> for PlatformInfoProperty {
    fn from(value: &str) -> Self {
        match value {
            "fmspc" => Self::Fmspc,
            "sgxtcbcomponents" => Self::SgxTcbComponents,
            "pcesvn" => Self::PceSvn,
            "tdxtcbcomponents" => Self::TdxTcbComponents,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum QeInfoProperty {
    MiscSelect,
    Attributes,
    MrEnclave,
    MrSigner,
    IsvProID,
    IsvSvn,
    Unknown,
}

impl From<&str> for QeInfoProperty {
    fn from(value: &str) -> Self {
        match value {
            "MISCSELECT" => Self::MiscSelect,
            "ATTRIBUTES" => Self::Attributes,
            "MRSIGNER" => Self::MrSigner,
            "ISVPRODID" => Self::IsvProID,
            "ISVSVN" => Self::IsvSvn,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TdxModuleInfoProperty {
    TdxModuleMajorVersion,
    TdxModuleSvn,
    MrSeam,
    MrSignerSeam,
    Attributes,
    Unknown,
}

impl From<&str> for TdxModuleInfoProperty {
    fn from(value: &str) -> Self {
        match value {
            "TDXModuleMajorVersion" => Self::TdxModuleMajorVersion,
            "TDXModuleSVN" => Self::TdxModuleSvn,
            "MRSEAM" => Self::MrSeam,
            "MRSIGNERSEAM" => Self::MrSignerSeam,
            "ATTRIBUTES" => Self::Attributes,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MigTdInfoProperty {
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

impl From<&str> for MigTdInfoProperty {
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
    let platform_info: Vec<&crate::PlatformInfo> = policy
        .blocks
        .iter()
        .filter_map(|block| match block {
            crate::Policy::Platform(p) => Some(p),
            _ => None,
        })
        .collect();
    verify_platform_info(is_src, platform_info, &report_local, &report_peer)?;

    for block in policy.blocks {
        match block {
            crate::Policy::Platform(_) => continue,
            crate::Policy::Qe(q) => verify_qe_info(is_src, &q, &report_local, &report_peer)?,
            crate::Policy::TdxModule(t) => {
                verify_tdx_module_info(is_src, &t, &report_local, &report_peer)?
            }
            crate::Policy::Migtd(m) => verify_migtd_info(
                is_src,
                &m,
                event_log,
                event_log_peer,
                &report_local,
                &report_peer,
            )?,
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
    let local_fmspc = local_report.get_platform_info_property(&PlatformInfoProperty::Fmspc)?;
    let peer_fmspc = peer_report.get_platform_info_property(&PlatformInfoProperty::Fmspc)?;

    let target_platform = if policy.len() == 1 && policy[0].fmspc.as_str() == "self" {
        if local_fmspc != peer_fmspc {
            return Err(PolicyError::PlatformNotMatch(format_bytes_hex(peer_fmspc)));
        }
        &policy[0]
    } else {
        let peer_fmspc = format_bytes_hex(peer_fmspc);
        policy
            .iter()
            .find(|p| p.fmspc == peer_fmspc)
            .ok_or(PolicyError::PlatformNotFound(peer_fmspc))?
    };

    for (name, action) in &target_platform.platform.tcb_info {
        let property = PlatformInfoProperty::from(name.as_str());
        let local = local_report.get_platform_info_property(&property)?;
        let remote = peer_report.get_platform_info_property(&property)?;

        let verify_result = action.verify(is_src, local, remote);

        if !verify_result {
            return Err(PolicyError::UnqulifiedPlatformInfo(
                PolicyErrorDetails::new(name.clone(), action.clone(), local, remote),
            ));
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
            return Err(PolicyError::UnqulifiedQeInfo(PolicyErrorDetails::new(
                name.clone(),
                action.clone(),
                local,
                remote,
            )));
        }
    }

    Ok(())
}

fn verify_tdx_module_info(
    is_src: bool,
    policy: &TdxModuleInfo,
    local_report: &Report,
    peer_report: &Report,
) -> Result<(), PolicyError> {
    for (name, action) in &policy.tdx_module.tdx_module_identity {
        let property = TdxModuleInfoProperty::from(name.as_str());
        let local = local_report.get_tdx_module_info_property(&property)?;
        let remote = peer_report.get_tdx_module_info_property(&property)?;

        let verify_result = action.verify(is_src, local, remote);

        if !verify_result {
            return Err(PolicyError::UnqulifiedTdxModuleInfo(
                PolicyErrorDetails::new(name.clone(), action.clone(), local, remote),
            ));
        }
    }

    Ok(())
}

fn verify_migtd_info(
    is_src: bool,
    policy: &MigTdInfo,
    event_log_local: &[u8],
    event_log_peer: &[u8],
    local_report: &Report,
    peer_report: &Report,
) -> Result<(), PolicyError> {
    for (name, action) in &policy.migtd.td_info {
        let property = MigTdInfoProperty::from(name.as_str());
        let local = local_report.get_migtd_info_property(&property)?;
        let remote = peer_report.get_migtd_info_property(&property)?;

        let verify_result = action.verify(is_src, local, remote);

        if !verify_result {
            return Err(PolicyError::UnqulifiedMigTdInfo(PolicyErrorDetails::new(
                name.clone(),
                action.clone(),
                local,
                remote,
            )));
        }
    }

    if let Some(event_log_policy) = &policy.migtd.event_log {
        verify_event_log(
            is_src,
            event_log_policy,
            event_log_local,
            event_log_peer,
            peer_report,
        )?;
    }

    Ok(())
}

fn verify_event_log(
    is_src: bool,
    policy: &BTreeMap<String, Property>,
    event_log_local: &[u8],
    event_log_peer: &[u8],
    peer_report: &Report,
) -> Result<(), PolicyError> {
    replay_event_log(event_log_peer, peer_report)?;

    if let (Some(log_local), Some(log_peer)) =
        (parse_events(event_log_local), parse_events(event_log_peer))
    {
        verify_events(is_src, policy, &log_local, &log_peer)
    } else {
        Err(PolicyError::InvalidEventLog)
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

    if report_peer.get_migtd_info_property(&MigTdInfoProperty::Rtmr0)? == &rtmrs[0][0..48]
        && report_peer.get_migtd_info_property(&MigTdInfoProperty::Rtmr1)? == &rtmrs[1][0..48]
        && report_peer.get_migtd_info_property(&MigTdInfoProperty::Rtmr2)? == &rtmrs[2][0..48]
        && report_peer.get_migtd_info_property(&MigTdInfoProperty::Rtmr3)? == &rtmrs[3][0..48]
    {
        Ok(())
    } else {
        Err(PolicyError::InvalidEventLog)
    }
}

fn verify_events(
    is_src: bool,
    policy: &BTreeMap<String, Property>,
    local_event_log: &BTreeMap<EventName, CcEvent>,
    peer_event_log: &BTreeMap<EventName, CcEvent>,
) -> Result<(), PolicyError> {
    for (name, value) in policy {
        let event_name = name.as_str().into();

        if event_name == EventName::Unknown {
            return Err(PolicyError::InvalidEventLog);
        }

        let verify_result =
            verify_event(is_src, &event_name, value, local_event_log, peer_event_log);

        if !verify_result {
            return Err(PolicyError::UnqulifiedMigTdInfo(PolicyErrorDetails::new(
                name.clone(),
                value.clone(),
                &[],
                &[],
            )));
        }
    }

    Ok(())
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
            &[0u8; REPORT_DATA_SIZE - 1],
            &[0u8; 8],
            &[0u8; REPORT_DATA_SIZE],
            &[0u8; 8],
        );
        assert!(matches!(verify_result, Err(PolicyError::InvalidParameter)));

        let verify_result = verify_policy(
            true,
            policy_bytes,
            &[0u8; REPORT_DATA_SIZE],
            &[0u8; 8],
            &[0u8; REPORT_DATA_SIZE - 1],
            &[0u8; 8],
        );
        assert!(matches!(verify_result, Err(PolicyError::InvalidParameter)));
    }

    #[test]
    fn test_verify_with_platform_info_comp() {
        let template = include_bytes!("../test/report.dat");

        let policy_bytes = include_bytes!("../test/policy_full1.json");
        let verify_result =
            verify_policy(true, policy_bytes, template, &[0u8; 8], template, &[0u8; 8]);
        assert!(verify_result.is_ok());

        let mut report_peer = template.to_vec();
        report_peer[Report::R_FMSPC].copy_from_slice(&[0x30, 0x81, 0x6F, 0, 0, 0]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::PlatformNotFound(_))
        ));

        // peer's tdx tcb level lower than reference
        let mut report_peer = template.to_vec();
        let low_tdx_tcb = &[0u8; 16];
        report_peer[Report::R_TDX_TCB_COMPONENTS].copy_from_slice(low_tdx_tcb);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedPlatformInfo(_))
        ));

        // dst's tdx tcb level is higher than reference
        let high_tdx_tcb = &[0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        report_peer[Report::R_TDX_TCB_COMPONENTS].copy_from_slice(high_tdx_tcb);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(verify_result.is_ok());

        // Take self as reference
        let policy_bytes = include_bytes!("../test/policy_full3.json");
        let mut report = template.to_vec();
        let mut report_peer = template.to_vec();

        // dst's tdx tcb level is higher than self
        report[Report::R_TDX_TCB_COMPONENTS].copy_from_slice(&[1u8; 16]);
        report_peer[Report::R_TDX_TCB_COMPONENTS].copy_from_slice(&[2u8; 16]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(verify_result.is_ok());

        // dst's svn is smaller than self
        report[Report::R_TDX_TCB_COMPONENTS].copy_from_slice(&[2u8; 16]);
        report_peer[Report::R_TDX_TCB_COMPONENTS].copy_from_slice(&[1u8; 16]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            &report,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedPlatformInfo(_))
        ));
    }

    // Different MRTD value, no MRTD policy in policy data
    #[test]
    fn test_verify_migtdinfo_comp() {
        let template = include_bytes!("../test/report.dat");

        let policy_bytes = include_bytes!("../test/policy_no.json");
        let verify_result =
            verify_policy(true, policy_bytes, template, &[0u8; 8], template, &[0u8; 8]);
        assert!(verify_result.is_ok());

        // different attributes, not equal, but attributes is not in policy
        let policy_bytes = include_bytes!("../test/policy_no_tdattr.json");
        let mut report_peer = template.to_vec();

        report_peer[Report::R_ATTR_TD].copy_from_slice(&[1u8; 8]);
        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(verify_result.is_ok());

        let policy_bytes = include_bytes!("../test/policy_full1.json");
        // different attributes, not equal
        report_peer[Report::R_ATTR_TD].copy_from_slice(&[1u8; 8]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
        report_peer[Report::R_ATTR_TD].copy_from_slice(&template[Report::R_ATTR_TD]);

        // different xfam, not equal
        report_peer[Report::R_XFAM].copy_from_slice(&[1u8; 8]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
        report_peer[Report::R_XFAM].copy_from_slice(&template[Report::R_XFAM]);

        // different mrtd, not equal
        report_peer[Report::R_MRTD].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
        report_peer[Report::R_MRTD].copy_from_slice(&[0u8; 48]);

        // different mrconfig_id, not equal
        report_peer[Report::R_MRCONFIGID].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
        report_peer[Report::R_MRCONFIGID].copy_from_slice(&template[Report::R_MRCONFIGID]);

        // different mrowner, not equal
        report_peer[Report::R_MROWNER].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
        report_peer[Report::R_MROWNER].copy_from_slice(&template[Report::R_MROWNER]);

        // different mrownerconfig, not equal
        report_peer[Report::R_MROWNERCONFIG].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
        report_peer[Report::R_MROWNERCONFIG].copy_from_slice(&template[Report::R_MROWNERCONFIG]);

        // different rtmr0, not equal
        report_peer[Report::R_RTMR0].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
        report_peer[Report::R_RTMR0].copy_from_slice(&template[Report::R_RTMR0]);

        // different rtmr1, not equal
        report_peer[Report::R_RTMR1].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
        report_peer[Report::R_RTMR1].copy_from_slice(&template[Report::R_RTMR1]);

        // different rtmr2, not equal
        report_peer[Report::R_RTMR2].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
        report_peer[Report::R_RTMR2].copy_from_slice(&template[Report::R_RTMR2]);

        // different rtmr3, not equal
        report_peer[Report::R_RTMR3].copy_from_slice(&[1u8; 48]);

        let verify_result = verify_policy(
            true,
            policy_bytes,
            template,
            &[0u8; 8],
            &report_peer,
            &[0u8; 8],
        );
        assert!(matches!(
            verify_result,
            Err(PolicyError::UnqulifiedMigTdInfo(_))
        ));
    }

    #[test]
    fn test_verify_eventlog_comp() {
        let template = include_bytes!("../test/report.dat");

        let policy_bytes = include_bytes!("../test/policy_full2.json");
        // Invalid event log
        let verify_result =
            verify_policy(true, policy_bytes, template, &[0u8; 8], template, &[0u8; 8]);
        assert!(matches!(verify_result, Err(PolicyError::InvalidEventLog)));

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

        let verify_result = verify_policy(true, policy_bytes, template, &evt1, template, &evt1);
        assert!(matches!(verify_result, Err(PolicyError::InvalidEventLog)));
    }

    fn create_event_log(
        payload: &[u8],
        trust_anchor: Option<&[u8]>,
        payload_svn: Option<&[u8]>,
        policy: &[u8],
        root_key: &[u8],
    ) -> Vec<u8> {
        let mut event_log = vec![0u8; 8192];

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
        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();
        let local_events = parse_events(&event_log).unwrap();

        assert!(verify_events(true, &event_log_policy, &local_events, &local_events).is_ok());
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

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(
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

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(
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

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(
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

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(
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

        let policy = serde_json::from_str::<MigPolicy>(policy).unwrap();
        let event_log_policy = policy
            .get_migtd_info_policy()
            .unwrap()
            .migtd
            .event_log
            .as_ref()
            .unwrap();

        assert!(verify_events(
            true,
            &event_log_policy,
            &parse_events(&local_events).unwrap(),
            &parse_events(&peer_events).unwrap(),
        )
        .is_err());
    }
}
