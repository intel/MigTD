// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::Parser;
use migtd_collateral_generator::generate_collaterals;
use std::{path::PathBuf, process::exit};

#[derive(Debug, Parser)]
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

    let pcs_config = match config.provider.to_lowercase().as_str() {
        "intel" => migtd_collateral_generator::PcsConfig::intel(!config.pre_production),
        "azure-thim" | "azure" | "thim" => {
            migtd_collateral_generator::PcsConfig::azure_thim(&config.azure_region)
        }
        _ => {
            eprintln!("Error: Invalid provider: {}", config.provider);
            exit(1);
        }
    };

    if let Err(e) = generate_collaterals(&pcs_config, &config.output) {
        eprintln!("Error generating collaterals: {}", e);
        exit(1);
    }
}
