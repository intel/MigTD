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
    /// PEM issuer chain for mapping (required even when an identity chain
    /// is supplied).
    #[arg(long, value_name = "FILE")]
    mapping_chain: PathBuf,
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
        &cli.mapping_chain,
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
            "--mapping-chain",
            "mapping-chain.pem",
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
        assert_eq!(cli.mapping_chain, PathBuf::from("mapping-chain.pem"));
        assert_eq!(cli.identity_chain, Some(PathBuf::from("chain.pem")));
    }

    #[test]
    fn mapping_chain_is_required_with_or_without_identity() {
        let args = [
            "servtd-collateral-generator",
            "--mapping",
            "mapping.json",
            "--servtd-crl",
            "servtd.crl.pem",
            "--output",
            "collateral.json",
        ];
        for identity_args in [
            &[][..],
            &[
                "--identity",
                "identity.json",
                "--identity-chain",
                "identity-chain.pem",
            ][..],
        ] {
            let error = Cli::try_parse_from(args.into_iter().chain(identity_args.iter().copied()))
                .unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
            assert!(error.to_string().contains("--mapping-chain"));
        }
    }

    #[test]
    fn identity_remains_optional_and_paired_with_its_chain() {
        let args = [
            "servtd-collateral-generator",
            "--mapping",
            "mapping.json",
            "--mapping-chain",
            "mapping-chain.pem",
            "--servtd-crl",
            "servtd.crl.pem",
            "--output",
            "collateral.json",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(cli.identity.is_none());
        assert!(cli.identity_chain.is_none());

        for (option, required) in [
            ("--identity", "--identity-chain"),
            ("--identity-chain", "--identity"),
        ] {
            let error = Cli::try_parse_from(args.into_iter().chain([option, "file"])).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
            assert!(error.to_string().contains(required));
        }
    }
}
