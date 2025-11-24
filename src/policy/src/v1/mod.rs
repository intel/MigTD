// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod config;
mod verify;

use alloc::collections::BTreeMap;
pub use config::*;
pub use verify::*;

use crate::{PolicyError, Report, REPORT_DATA_SIZE};

impl<'a> Report<'a> {
    pub fn new(report: &'a [u8]) -> Result<Self, PolicyError> {
        if report.len() != REPORT_DATA_SIZE {
            return Err(PolicyError::InvalidParameter);
        }

        Ok(Report {
            platform_info: Self::setup_platform_info(report)?,
            qe_info: Self::setup_qe_info(report)?,
            tdx_module_info: Self::setup_tdx_module_info(report)?,
            migtd_info: Self::setup_migtd_info(report)?,
        })
    }

    fn setup_platform_info(
        report: &'a [u8],
    ) -> Result<BTreeMap<PlatformInfoProperty, &'a [u8]>, PolicyError> {
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

        Ok(platform_info)
    }

    fn setup_qe_info(report: &'a [u8]) -> Result<BTreeMap<QeInfoProperty, &'a [u8]>, PolicyError> {
        let mut qe_info = BTreeMap::new();

        qe_info.insert(QeInfoProperty::MiscSelect, &report[Self::R_QE_MISC_SELECT]);
        qe_info.insert(QeInfoProperty::Attributes, &report[Self::R_QE_ATTRIBUTES]);
        qe_info.insert(QeInfoProperty::MrEnclave, &report[Self::R_QE_MRENCLAVE]);
        qe_info.insert(QeInfoProperty::MrSigner, &report[Self::R_QE_MRSIGNER]);
        qe_info.insert(QeInfoProperty::IsvProID, &report[Self::R_QE_ISV_PRO_ID]);
        qe_info.insert(QeInfoProperty::IsvSvn, &report[Self::R_QE_ISV_SVN]);

        Ok(qe_info)
    }

    fn setup_tdx_module_info(
        report: &'a [u8],
    ) -> Result<BTreeMap<TdxModuleInfoProperty, &'a [u8]>, PolicyError> {
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

        Ok(tdx_module_info)
    }

    fn get_platform_info_property(
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
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PlatformInfoProperty {
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
pub(crate) enum QeInfoProperty {
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
pub(crate) enum TdxModuleInfoProperty {
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
