// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::Parser;
use migtd_collateral_generator::{generate_collaterals, AzureThimConfig, IntelPcsConfig};
use std::{path::PathBuf, process::exit};

#[derive(Debug, Clone, Parser)]
struct Config {
    /// Service provider: "intel" (default) or "azure-thim"
    #[clap(long, default_value = "intel")]
    provider: String,

    /// Set to use pre-production server. Only applies to Intel PCS provider.
    /// Azure THIM always uses production. Production server is used by default.
    #[clap(long)]
    pre_production: bool,

    /// Azure region for THIM service.
    /// Only applies when provider is "azure-thim". Default: "useast"
    #[clap(long, default_value = "useast")]
    azure_region: String,

    /// Where to write the generated collaterals
    #[clap(long, short)]
    output: PathBuf,
}

fn main() {
    let config = Config::parse();

    let result = match config.provider.to_lowercase().as_str() {
        "intel" => {
            let pcs_config = IntelPcsConfig::new(!config.pre_production);
            generate_collaterals(&pcs_config, &config.output)
        }
        "azure-thim" | "azure" | "thim" => {
            let pcs_config = AzureThimConfig::new(&config.azure_region);
            generate_collaterals(&pcs_config, &config.output)
        }
        _ => {
            eprintln!("Error: Invalid provider: {}", config.provider);
            exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error generating collaterals: {}", e);
        exit(1);
    }
}
