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
    /// Required CA-signed PEM CRL with a CRL-number extension for the servTD signer
    /// chains, even if its revocation list is empty.
    #[arg(long, value_name = "FILE")]
    servtd_crl: PathBuf,
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
        &cli.servtd_crl,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servtd_crl_is_required() {
        let args = [
            "servtd-collateral-generator",
            "--identity",
            "identity.json",
            "--identity-chain",
            "chain.pem",
            "--mapping",
            "mapping.json",
            "--output",
            "collateral.json",
        ];
        let error = Cli::try_parse_from(args).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(error.to_string().contains("--servtd-crl"));

        let cli = Cli::try_parse_from(args.into_iter().chain(["--servtd-crl", "servtd.crl.pem"]))
            .unwrap();
        assert_eq!(cli.servtd_crl, PathBuf::from("servtd.crl.pem"));
    }
}
