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
    CrlEvaluation,
    HashCalculation,
    QuoteVerification,
    QuoteGeneration,
    GetTdxReport,
}

pub struct Report<'a> {
    #[cfg(not(feature = "policy_v2"))]
    platform_info: BTreeMap<PlatformInfoProperty, &'a [u8]>,
    #[cfg(not(feature = "policy_v2"))]
    qe_info: BTreeMap<QeInfoProperty, &'a [u8]>,
    #[cfg(not(feature = "policy_v2"))]
    tdx_module_info: BTreeMap<TdxModuleInfoProperty, &'a [u8]>,
    migtd_info: BTreeMap<MigTdInfoProperty, &'a [u8]>,
}

impl<'a> Report<'a> {
    // The following definition should match struct servtd_tdx_quote_suppl_data.
    pub const R_TDX_MODULE_MRSEAM: Range<usize> = 16..64;
    pub const R_TDX_MODULE_MRSEAMSIGNER: Range<usize> = 64..112;
    pub const R_TDX_MODULE_ATTR_SEAM: Range<usize> = 112..120;
    pub const R_MIGTD_ATTR_TD: Range<usize> = 120..128;
    pub const R_MIGTD_XFAM: Range<usize> = 128..136;
    pub const R_MIGTD_MRTD: Range<usize> = 136..184;
    pub const R_MIGTD_MRCONFIGID: Range<usize> = 184..232;
    pub const R_MIGTD_MROWNER: Range<usize> = 232..280;
    pub const R_MIGTD_MROWNERCONFIG: Range<usize> = 280..328;
    pub const R_MIGTD_RTMR0: Range<usize> = 328..376;
    pub const R_MIGTD_RTMR1: Range<usize> = 376..424;
    pub const R_MIGTD_RTMR2: Range<usize> = 424..472;
    pub const R_MIGTD_RTMR3: Range<usize> = 472..520;
    pub const R_PLATFORM_FMSPC: Range<usize> = 584..590;
    pub const R_PLATFORM_TDX_TCB_COMPONENTS: Range<usize> = 590..606;
    pub const R_PLATFORM_PCE_SVN: Range<usize> = 606..608;
    pub const R_PLATFORM_SGX_TCB_COMPONENTS: Range<usize> = 608..624;
    pub const R_TDX_MODULE_MAJOR_VER: Range<usize> = 624..625;
    pub const R_TDX_MODULE_SVN: Range<usize> = 625..626;
    pub const R_QE_MISC_SELECT: Range<usize> = 626..630;
    pub const R_QE_ATTRIBUTES: Range<usize> = 634..650;
    pub const R_QE_MRENCLAVE: Range<usize> = 666..698;
    pub const R_QE_MRSIGNER: Range<usize> = 698..730;
    pub const R_QE_ISV_PRO_ID: Range<usize> = 730..732;
    pub const R_QE_ISV_SVN: Range<usize> = 732..734;
    pub const R_TCB_DATE: Range<usize> = 734..742;
    pub const R_TCB_STATUS: Range<usize> = 742..774;

    fn setup_migtd_info(
        report: &'a [u8],
    ) -> Result<BTreeMap<MigTdInfoProperty, &'a [u8]>, PolicyError> {
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

        Ok(migtd_info)
    }

    fn get_migtd_info_property(&self, name: &MigTdInfoProperty) -> Result<&[u8], PolicyError> {
        self.migtd_info
            .get(name)
            .ok_or(PolicyError::InvalidParameter)
            .copied()
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

pub struct CcEvent {
    header: CcEventHeader,
    #[allow(unused)]
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
