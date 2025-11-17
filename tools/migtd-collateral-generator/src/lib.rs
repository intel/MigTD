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

/// Trait defining the interface for PCS (Provisioning Certification Service) endpoints
///
/// This abstraction allows supporting multiple PCS cache providers that follow the same APIs
/// defined by Intel PCS, e.g., Intel PCS itself, Azure THIM, or other cloud provider PCS caches.
pub trait PcsConfig {
    /// Get base URL for general endpoints (QE identity, TCB info)
    fn get_base_url(&self) -> String;

    /// Get base URL for PCK CRL endpoint
    fn get_base_url_pck_crl(&self) -> String;

    /// Get base URL for FMSPC list endpoint
    fn get_base_url_fmspc_list(&self) -> String;

    /// Get root CA certificate URL
    fn get_root_ca_url(&self) -> &'static str;
}

/// Intel PCS configuration
#[derive(Debug, Clone)]
pub struct IntelPcsConfig {
    /// Whether to use production endpoints (vs sandbox/pre-production)
    for_production: bool,
}

impl IntelPcsConfig {
    /// Create a new Intel PCS configuration
    pub fn new(for_production: bool) -> Self {
        Self { for_production }
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

impl PcsConfig for IntelPcsConfig {
    fn get_base_url(&self) -> String {
        self.get_intel_pcs_base_url()
    }

    fn get_base_url_pck_crl(&self) -> String {
        self.get_intel_pcs_base_url()
    }

    fn get_base_url_fmspc_list(&self) -> String {
        self.get_intel_pcs_base_url()
    }

    fn get_root_ca_url(&self) -> &'static str {
        if self.for_production {
            INTEL_ROOT_CA_URL
        } else {
            INTEL_ROOT_CA_URL_SBX
        }
    }
}

/// Generate collaterals using the specified configuration and write to file
pub fn generate_collaterals(config: &dyn PcsConfig, output_collateral: &PathBuf) -> Result<()> {
    let collaterals = collateral::get_collateral(config)?;
    write_collaterals_file(output_collateral, &collaterals)?;
    Ok(())
}

fn write_collaterals_file(collateral_output: &PathBuf, collaterals: &Collaterals) -> Result<()> {
    let mut file = fs::File::create(collateral_output)?;
    file.write_all(serde_json::to_vec(collaterals)?.as_slice())?;
    Ok(())
}
