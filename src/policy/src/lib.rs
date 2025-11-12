// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(any(test, feature = "AzCVMEmu")), no_std)]
extern crate alloc;

#[cfg(not(feature = "policy_v2"))]
mod v1;
#[cfg(not(feature = "policy_v2"))]
pub use v1::*;
#[cfg(feature = "policy_v2")]
mod v2;
#[cfg(feature = "policy_v2")]
pub use v2::*;

use core::{convert::TryInto, ops::Range};

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use cc_measurement::{
    log::CcEventLogReader, CcEventHeader, EV_EFI_PLATFORM_FIRMWARE_BLOB2, EV_PLATFORM_CONFIG_FLAGS,
};
use crypto::hash::digest_sha384;
use td_shim::event_log::{
    PLATFORM_CONFIG_SECURE_AUTHORITY, PLATFORM_CONFIG_SVN, PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
};

pub const REPORT_DATA_SIZE: usize = 774;
const MAX_RTMR_INDEX: usize = 3;
const EV_EVENT_TAG: u32 = 0x00000006;
const TAGGED_EVENT_ID_POLICY: u32 = 0x1;
const TAGGED_EVENT_ID_ROOT_CA: u32 = 0x2;
const TAGGED_EVENT_ID_POLICY_SIGNER: u32 = 0x3;

#[repr(C)]
#[derive(Debug)]
pub enum PolicyError {
    FailGetReport,
    InvalidParameter,
    InvalidPolicy,
    InvalidEventLog,
    PlatformNotFound(String),
    PlatformNotMatch(String, String),
    UnqualifiedPlatformInfo,
    UnqualifiedQeInfo,
    UnqualifiedTdxModuleInfo,
    UnqualifiedMigTdInfo,
    Crypto,
    SignatureVerificationFailed,
    InvalidCollateral,
    InvalidOperation,
    InvalidReference,
    InvalidServtdIdentity,
    InvalidServtdTcbMapping,
    PlatformTcbNotFound,
    ServtdTcbNotFound,
    PolicyHashMismatch,
    InvalidQuote,
    SvnMismatch,
    TcbEvaluation,
    HashCalculation,
    QuoteVerification,
    QuoteGeneration,
    GetTdxReport,
}

pub struct Report<'a> {
    platform_info: BTreeMap<PlatformInfoProperty, &'a [u8]>,
    qe_info: BTreeMap<QeInfoProperty, &'a [u8]>,
    tdx_module_info: BTreeMap<TdxModuleInfoProperty, &'a [u8]>,
    migtd_info: BTreeMap<MigTdInfoProperty, &'a [u8]>,
}

impl<'a> Report<'a> {
    // The following definition should match struct servtd_tdx_quote_suppl_data.
    const R_TDX_MODULE_MRSEAM: Range<usize> = 16..64;
    const R_TDX_MODULE_MRSEAMSIGNER: Range<usize> = 64..112;
    const R_TDX_MODULE_ATTR_SEAM: Range<usize> = 112..120;
    const R_MIGTD_ATTR_TD: Range<usize> = 120..128;
    const R_MIGTD_XFAM: Range<usize> = 128..136;
    const R_MIGTD_MRTD: Range<usize> = 136..184;
    const R_MIGTD_MRCONFIGID: Range<usize> = 184..232;
    const R_MIGTD_MROWNER: Range<usize> = 232..280;
    const R_MIGTD_MROWNERCONFIG: Range<usize> = 280..328;
    const R_MIGTD_RTMR0: Range<usize> = 328..376;
    const R_MIGTD_RTMR1: Range<usize> = 376..424;
    const R_MIGTD_RTMR2: Range<usize> = 424..472;
    const R_MIGTD_RTMR3: Range<usize> = 472..520;
    const R_PLATFORM_FMSPC: Range<usize> = 584..590;
    const R_PLATFORM_TDX_TCB_COMPONENTS: Range<usize> = 590..606;
    const R_PLATFORM_PCE_SVN: Range<usize> = 606..608;
    const R_PLATFORM_SGX_TCB_COMPONENTS: Range<usize> = 608..624;
    const R_TDX_MODULE_MAJOR_VER: Range<usize> = 624..625;
    const R_TDX_MODULE_SVN: Range<usize> = 625..626;
    const R_QE_MISC_SELECT: Range<usize> = 626..630;
    const R_QE_ATTRIBUTES: Range<usize> = 634..650;
    const R_QE_MRENCLAVE: Range<usize> = 666..698;
    const R_QE_MRSIGNER: Range<usize> = 698..730;
    const R_QE_ISV_PRO_ID: Range<usize> = 730..732;
    const R_QE_ISV_SVN: Range<usize> = 732..734;
    pub const R_TCB_DATE: Range<usize> = 734..742;
    pub const R_TCB_STATUS: Range<usize> = 742..774;

    pub fn new(report: &'a [u8]) -> Result<Self, PolicyError> {
        if report.len() != REPORT_DATA_SIZE {
            return Err(PolicyError::InvalidParameter);
        }

        let mut platform_info = BTreeMap::new();
        platform_info.insert(PlatformInfoProperty::Fmspc, &report[Self::R_PLATFORM_FMSPC]);
        platform_info.insert(
            PlatformInfoProperty::SgxTcbComponents,
            &report[Self::R_PLATFORM_SGX_TCB_COMPONENTS],
        );
        platform_info.insert(
            PlatformInfoProperty::PceSvn,
            &report[Self::R_PLATFORM_PCE_SVN],
        );
        platform_info.insert(
            PlatformInfoProperty::TdxTcbComponents,
            &report[Self::R_PLATFORM_TDX_TCB_COMPONENTS],
        );

        let mut qe_info = BTreeMap::new();
        qe_info.insert(QeInfoProperty::MiscSelect, &report[Self::R_QE_MISC_SELECT]);
        qe_info.insert(QeInfoProperty::Attributes, &report[Self::R_QE_ATTRIBUTES]);
        qe_info.insert(QeInfoProperty::MrEnclave, &report[Self::R_QE_MRENCLAVE]);
        qe_info.insert(QeInfoProperty::MrSigner, &report[Self::R_QE_MRSIGNER]);
        qe_info.insert(QeInfoProperty::IsvProID, &report[Self::R_QE_ISV_PRO_ID]);
        qe_info.insert(QeInfoProperty::IsvSvn, &report[Self::R_QE_ISV_SVN]);

        let mut tdx_module_info = BTreeMap::new();
        tdx_module_info.insert(
            TdxModuleInfoProperty::TdxModuleMajorVersion,
            &report[Self::R_TDX_MODULE_MAJOR_VER],
        );
        tdx_module_info.insert(
            TdxModuleInfoProperty::TdxModuleSvn,
            &report[Self::R_TDX_MODULE_SVN],
        );
        tdx_module_info.insert(
            TdxModuleInfoProperty::MrSeam,
            &report[Self::R_TDX_MODULE_MRSEAM],
        );
        tdx_module_info.insert(
            TdxModuleInfoProperty::MrSignerSeam,
            &report[Self::R_TDX_MODULE_MRSEAMSIGNER],
        );
        tdx_module_info.insert(
            TdxModuleInfoProperty::Attributes,
            &report[Self::R_TDX_MODULE_ATTR_SEAM],
        );

        let mut migtd_info = BTreeMap::new();
        migtd_info.insert(
            MigTdInfoProperty::Attributes,
            &report[Self::R_MIGTD_ATTR_TD],
        );
        migtd_info.insert(MigTdInfoProperty::Xfam, &report[Self::R_MIGTD_XFAM]);
        migtd_info.insert(MigTdInfoProperty::MrTd, &report[Self::R_MIGTD_MRTD]);
        migtd_info.insert(
            MigTdInfoProperty::MrConfigId,
            &report[Self::R_MIGTD_MRCONFIGID],
        );
        migtd_info.insert(MigTdInfoProperty::MrOwner, &report[Self::R_MIGTD_MROWNER]);
        migtd_info.insert(
            MigTdInfoProperty::MrOwnerConfig,
            &report[Self::R_MIGTD_MROWNERCONFIG],
        );
        migtd_info.insert(MigTdInfoProperty::Rtmr0, &report[Self::R_MIGTD_RTMR0]);
        migtd_info.insert(MigTdInfoProperty::Rtmr1, &report[Self::R_MIGTD_RTMR1]);
        migtd_info.insert(MigTdInfoProperty::Rtmr2, &report[Self::R_MIGTD_RTMR2]);
        migtd_info.insert(MigTdInfoProperty::Rtmr3, &report[Self::R_MIGTD_RTMR3]);

        Ok(Report {
            platform_info,
            qe_info,
            tdx_module_info,
            migtd_info,
        })
    }

    pub(crate) fn get_platform_info_property(
        &self,
        name: &PlatformInfoProperty,
    ) -> Result<&[u8], PolicyError> {
        self.platform_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
    }

    pub(crate) fn get_qe_info_property(&self, name: &QeInfoProperty) -> Result<&[u8], PolicyError> {
        self.qe_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
    }

    pub(crate) fn get_tdx_module_info_property(
        &self,
        name: &TdxModuleInfoProperty,
    ) -> Result<&[u8], PolicyError> {
        self.tdx_module_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
    }

    pub(crate) fn get_migtd_info_property(
        &self,
        name: &MigTdInfoProperty,
    ) -> Result<&[u8], PolicyError> {
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
pub(crate) enum MigTdInfoProperty {
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

pub(crate) struct CcEvent {
    header: CcEventHeader,
    data: Option<Vec<u8>>,
}

impl CcEvent {
    pub fn new(header: CcEventHeader, data: Option<Vec<u8>>) -> Self {
        Self { header, data }
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
    MigTdPolicySigner,
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

pub(crate) fn parse_events(event_log: &[u8]) -> Option<BTreeMap<EventName, CcEvent>> {
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
                } else if tag_id == TAGGED_EVENT_ID_POLICY_SIGNER {
                    map.insert(
                        EventName::MigTdPolicySigner,
                        CcEvent::new(event_header, None),
                    );
                }
            }
            _ => {}
        }
    }

    Some(map)
}

pub fn verify_event_log<'a>(event_log: &[u8], report: &'a [u8]) -> Result<Report<'a>, PolicyError> {
    let report_values = Report::new(report).map_err(|_| PolicyError::InvalidParameter)?;
    replay_event_log_with_report_values(event_log, &report_values)?;
    Ok(report_values)
}

pub(crate) fn replay_event_log_with_report_values(
    event_log: &[u8],
    report: &Report,
) -> Result<(), PolicyError> {
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

    if report.get_migtd_info_property(&MigTdInfoProperty::Rtmr0)? == &rtmrs[0][0..48]
        && report.get_migtd_info_property(&MigTdInfoProperty::Rtmr1)? == &rtmrs[1][0..48]
        && report.get_migtd_info_property(&MigTdInfoProperty::Rtmr2)? == &rtmrs[2][0..48]
        && report.get_migtd_info_property(&MigTdInfoProperty::Rtmr3)? == &rtmrs[3][0..48]
    {
        Ok(())
    } else {
        //In AzCVMEmu mode, RTMR extension is emulated (no-op), RTMR in MigTD QUOTE won't match eventlog.
        //Return OK in this development environment.
        #[cfg(feature = "AzCVMEmu")]
        {
            Ok(())
        }
        #[cfg(not(feature = "AzCVMEmu"))]
        Err(PolicyError::InvalidEventLog)
    }
}
