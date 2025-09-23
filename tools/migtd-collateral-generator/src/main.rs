// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::Parser;
use migtd_collateral_generator::generate_collaterals;
use std::{path::PathBuf, process::exit};

#[derive(Debug, Clone, Parser)]
struct Config {
    /// Set to use pre-prodution server. Production server is used by
    /// default.
    #[clap(long)]
    pub pre_production: bool,
    /// Where to write the generated collaterals
    #[clap(long, short)]
    pub output: PathBuf,
}

fn main() {
    let config = Config::parse();

    if let Err(e) = generate_collaterals(!config.pre_production, &config.output) {
        eprintln!("Error generating collaterals: {}", e);
        exit(1);
    }
}
