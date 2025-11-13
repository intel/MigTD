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

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use cc_measurement::CcEventHeader;
use core::ops::Range;

pub const REPORT_DATA_SIZE: usize = 774;

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
    pub const R_MIGTD_RTMR0: Range<usize> = 328..376;
    pub const R_MIGTD_RTMR1: Range<usize> = 376..424;
    pub const R_MIGTD_RTMR2: Range<usize> = 424..472;
    pub const R_MIGTD_RTMR3: Range<usize> = 472..520;
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
pub enum MigTdInfoProperty {
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

pub struct CcEvent {
    header: CcEventHeader,
    data: Option<Vec<u8>>,
}

impl CcEvent {
    pub fn new(header: CcEventHeader, data: Option<Vec<u8>>) -> Self {
        Self { header, data }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventName {
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
