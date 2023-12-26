// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::Parser;
use migtd_policy_generator::policy::generate_policy;
use std::{fs, path::PathBuf, process::exit};

#[derive(Debug, Clone, Parser)]
struct Config {
    /// Set to use pre-prodution server. Production server is used by
    /// default.
    #[clap(long)]
    pub pre_production: bool,
    /// Where to write the generated policy
    #[clap(long, short)]
    pub output: PathBuf,
}

fn main() {
    let config = Config::parse();

    let policy = generate_policy(!config.pre_production).unwrap_or_else(|e| {
        eprintln!("Failed to generate policy: {}", e);
        exit(1);
    });
    fs::write(config.output, &policy).unwrap_or_else(|e| {
        eprintln!("Failed to write output file: {}", e);
        exit(1);
    })
}
