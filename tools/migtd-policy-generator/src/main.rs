// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::Parser;
use migtd_policy_generator::{generate_policy_v1, generate_policy_v2};
use std::{path::PathBuf, process::exit};

#[derive(Debug, Clone, Parser)]
struct Config {
    /// Set to use pre-prodution server. Production server is used by
    /// default.
    #[clap(long)]
    pub pre_production: bool,
    /// Where to write the generated policy
    #[clap(long, short)]
    pub output: PathBuf,
    /// Policy version to generate
    #[clap(long, short, default_value_t = 1)]
    pub version: u16,
    /// Where to write the generated collaterals
    #[clap(long, short)]
    pub collateral_output: Option<PathBuf>,
}

fn main() {
    let config = Config::parse();

    // Enforce collateral_output is required for version 2
    if config.version == 2 && config.collateral_output.is_none() {
        eprintln!("Error: --collateral-output is required when policy version is 2");
        std::process::exit(1);
    }

    match config.version {
        1 => {
            if let Err(e) = generate_policy_v1(!config.pre_production, &config.output) {
                eprintln!("Error generating policy v1: {}", e);
                exit(1);
            }
        }
        2 => {
            if let Err(e) = generate_policy_v2(
                !config.pre_production,
                &config.output,
                config.collateral_output.as_ref().unwrap(), // Safe to unwrap since we checked above
            ) {
                eprintln!("Error generating policy v2: {}", e);
                exit(1);
            }
        }
        _ => {
            eprintln!("Unsupported policy version: {}", config.version);
            exit(1);
        }
    }
}
