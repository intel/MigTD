// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use std::{fs, io::Write, path::PathBuf};

use crate::collateral::Collaterals;

pub mod collateral;
pub mod pcs_client;
pub mod pcs_types;

// Intel PCS base URLs - matching constants from Python PCS client
const INTEL_PCS_BASE_URL_PRODUCTION: &str = "https://api.trustedservices.intel.com/";
const INTEL_PCS_BASE_URL_SANDBOX: &str = "https://sbx.api.trustedservices.intel.com/";

// Intel Root CA certificate URLs
const INTEL_ROOT_CA_URL: &str = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer";
const INTEL_ROOT_CA_URL_SBX: &str = "https://sbx-certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer";

/// Configuration for PCS client connections
#[derive(Debug, Clone)]
pub struct PcsConfig {
    /// Whether to use production endpoints (vs sandbox/pre-production)
    for_production: bool,
    /// Azure region for THIM service (None for Intel PCS)
    azure_region: Option<String>,
}

impl PcsConfig {
    /// Create a new PcsConfig for Intel PCS
    pub fn intel(for_production: bool) -> Self {
        Self {
            for_production,
            azure_region: None,
        }
    }

    /// Create a new PcsConfig for Azure THIM
    pub fn azure_thim(region: &str) -> Self {
        Self {
            for_production: true, // Azure THIM always uses production
            azure_region: Some(region.to_string()),
        }
    }

    /// Get base URL for general endpoints (QE identity, TCB info)
    pub(crate) fn get_base_url(&self) -> String {
        match &self.azure_region {
            Some(region) => format!("https://{}.thim.azure.net", region),
            None => self.get_intel_pcs_base_url(),
        }
    }

    /// Get base URL for PCK CRL endpoint
    pub(crate) fn get_base_url_pck_crl(&self) -> String {
        match &self.azure_region {
            Some(region) => format!("https://{}.thim.azure.net", region),
            None => self.get_intel_pcs_base_url(),
        }
    }

    /// Get base URL for FMSPC list endpoint
    /// FMSPC lists are always fetched from Intel PCS (Azure THIM doesn't cache them)
    pub(crate) fn get_base_url_fmspc_list(&self) -> String {
        // Always use Intel PCS for FMSPC lists, regardless of provider
        self.get_intel_pcs_base_url()
    }

    /// Get root CA certificate URL
    /// Root CA is always fetched from Intel (Azure THIM doesn't cache it)
    pub(crate) fn get_root_ca_url(&self) -> &'static str {
        // Always use Intel for root CA, regardless of provider
        if self.for_production {
            INTEL_ROOT_CA_URL
        } else {
            INTEL_ROOT_CA_URL_SBX
        }
    }

    /// Helper method to get Intel PCS base URL (production vs sandbox)
    fn get_intel_pcs_base_url(&self) -> String {
        let base = if self.for_production {
            INTEL_PCS_BASE_URL_PRODUCTION
        } else {
            INTEL_PCS_BASE_URL_SANDBOX
        };
        base.to_string()
    }
}

/// Generate collaterals using the specified configuration and write to file
pub fn generate_collaterals(config: &PcsConfig, output_collateral: &PathBuf) -> Result<()> {
    let collaterals = collateral::get_collateral(config)?;
    write_collaterals_file(output_collateral, &collaterals)?;
    Ok(())
}

fn write_collaterals_file(collateral_output: &PathBuf, collaterals: &Collaterals) -> Result<()> {
    let mut file = fs::File::create(collateral_output)?;
    file.write_all(serde_json::to_vec(collaterals)?.as_slice())?;
    Ok(())
}
