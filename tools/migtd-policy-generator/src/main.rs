// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::{Args, Parser, Subcommand};
use migtd_policy_generator::{policy::generate_policy, policy_v2::build_v2_policy_data};
use std::{fs, path::PathBuf, process::exit};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "MigTD Policy Generator",
    propagate_version = true
)]
struct Cli {
    /// Set to use pre-production server (production by default)
    #[arg(long, global = true)]
    pre_production: bool,

    /// Sub-command for policy v2 (default mode without subcommand will still generate v1 policy)
    #[command(subcommand)]
    command: Option<Commands>,

    /// Where to write the generated (legacy v1) policy if no subcommand provided (required only in legacy mode)
    #[arg(long, short, global = true)]
    output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Policy v2 generation utilities
    V2(V2Command),
}

#[derive(Debug, Args)]
struct V2Command {
    /// Input policy data JSON file (used with --set-signature to embed signature)
    #[arg(long, value_name = "FILE")]
    policy_data: PathBuf,

    /// Quote verification collaterals file
    #[arg(long, value_name = "FILE")]
    collaterals: Option<PathBuf>,

    /// ServTD collaterals JSON file
    #[arg(long, value_name = "FILE")]
    servtd_collateral: Option<PathBuf>,

    /// Output file path
    #[arg(long, short, value_name = "FILE")]
    output: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // v1 policy generation
            let output = cli.output.unwrap_or_else(|| {
                eprintln!("--output is required in legacy mode (no subcommand provided)");
                exit(2);
            });
            let policy = generate_policy(!cli.pre_production).unwrap_or_else(|e| {
                eprintln!("Failed to generate policy: {}", e);
                exit(1);
            });
            fs::write(output, &policy).unwrap_or_else(|e| {
                eprintln!("Failed to write output file: {}", e);
                exit(1);
            });
        }
        Some(Commands::V2(cmd)) => {
            let collateral_path = cmd.collaterals.as_ref().unwrap_or_else(|| {
                eprintln!("error: the required arguments were not provided: --collaterals <FILE>");
                exit(1);
            });
            let servtd_collateral_path = cmd.servtd_collateral.as_ref().unwrap_or_else(|| {
                eprintln!(
                    "error: the required arguments were not provided: --servtd-collateral <FILE>"
                );
                exit(1);
            });
            let merged =
                build_v2_policy_data(&cmd.policy_data, collateral_path, servtd_collateral_path)
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to generate v2 policy data: {}", e);
                        exit(1);
                    });
            if let Err(e) = fs::write(&cmd.output, merged) {
                eprintln!("Failed to write output file: {}", e);
                exit(1);
            }
        }
    }
}
