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
    /// PEM issuer chain for mapping. When omitted, MigTD uses the policy
    /// issuer chain enrolled in its CFV, not the identity issuer chain.
    #[arg(long, value_name = "FILE")]
    mapping_chain: Option<PathBuf>,
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
        cli.identity.as_deref(),
        cli.identity_chain.as_deref(),
        &cli.mapping,
        cli.mapping_chain.as_deref(),
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
