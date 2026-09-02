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
    /// Optional signed ServTD identity JSON file (contains identity and
    /// signature). The TD Identity is optional; omit it (together with
    /// `--identity-chain`) to produce SVN-only collateral.
    #[arg(long, value_name = "FILE", requires = "identity_chain")]
    identity: Option<PathBuf>,
    /// PEM issuer chain for identity (required iff `--identity` is given)
    #[arg(long, value_name = "FILE", requires = "identity")]
    identity_chain: Option<PathBuf>,
    /// Signed ServTD TCB mapping JSON file (contains tcb mapping and signature)
    #[arg(long, value_name = "FILE")]
    mapping: PathBuf,
    /// PEM issuer chain for mapping
    #[arg(long, value_name = "FILE")]
    mapping_chain: PathBuf,
    /// Optional PEM CRL for the servTD signer chain (embedded as `servtdCrl`)
    #[arg(long, value_name = "FILE")]
    servtd_crl: Option<PathBuf>,
    /// Where to write the generated file
    #[arg(long, short, value_name = "FILE")]
    output: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    let bytes = build_servtd_collateral(
        cli.identity.as_deref(),
        cli.identity_chain.as_deref(),
        &cli.mapping,
        &cli.mapping_chain,
        cli.servtd_crl.as_deref(),
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
