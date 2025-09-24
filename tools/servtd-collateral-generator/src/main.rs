// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::Parser;
use std::{fs, path::PathBuf, process::exit};

mod build;

use build::build_servtd_collateral;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "MigTD Servtd Collateral Generator",
    propagate_version = true
)]
struct Cli {
    /// Signed ServTD identity JSON file (contains identity and signature)
    #[arg(long, value_name = "FILE")]
    identity: PathBuf,
    /// PEM issuer chain for identity
    #[arg(long, value_name = "FILE")]
    identity_chain: PathBuf,
    /// Signed ServTD TCB mapping JSON file (contains tcb mapping and signature)
    #[arg(long, value_name = "FILE")]
    mapping: PathBuf,
    /// PEM issuer chain for mapping
    #[arg(long, value_name = "FILE")]
    mapping_chain: PathBuf,
    /// Where to write the generated file
    #[arg(long, short, value_name = "FILE")]
    output: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    let bytes = build_servtd_collateral(
        &cli.identity,
        &cli.identity_chain,
        &cli.mapping,
        &cli.mapping_chain,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to build ServTD collateral: {}", e);
        exit(1);
    });
    if let Err(e) = fs::write(&cli.output, bytes) {
        eprintln!("Failed to write output file: {}", e);
        exit(1);
    }
}
