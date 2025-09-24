// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{Context, Result};
use clap::Parser;
use json_signer::{json_set_signature, json_sign};
use std::{
    fs,
    path::{Path, PathBuf},
    process::exit,
};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Sign a JSON file or package a provided signature.",
    propagate_version = true
)]

struct Cli {
    /// Finalize the JSON object by embedding the provided signature (requires --signature)
    #[arg(long, requires = "signature")]
    finalize: bool,

    /// Sign and finalize the JSON object (requires --private-key)
    #[arg(long, requires = "private_key")]
    sign: bool,

    /// Provide a signature file to finalize the JSON object.
    #[arg(long, value_name = "FILE")]
    signature: Option<PathBuf>,

    /// Provide the private key to sign the JSON object.
    #[arg(long, value_name = "FILE")]
    private_key: Option<PathBuf>,

    /// Name of the JSON object to sign (e.g., "policyData")
    #[arg(long, short)]
    name: String,

    /// Input JSON file
    #[arg(long, short, value_name = "FILE")]
    input: PathBuf,

    /// Where to write the generated file
    #[arg(long, short, value_name = "FILE")]
    output: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    let input = read_file(&cli.input).unwrap_or_else(|e| {
        eprintln!("Failed to read input file: {}", e);
        exit(1);
    });

    if cli.sign {
        // clap guarantees private_key present
        let private_key = read_file(&cli.private_key.unwrap()).unwrap_or_else(|e| {
            eprintln!("Failed to read private key file: {}", e);
            exit(1);
        });

        let output_bytes = json_sign(&cli.name, &input, &private_key).unwrap_or_else(|e| {
            eprintln!("Failed to sign input json: {:?}", e);
            exit(1);
        });
        if let Err(e) = fs::write(&cli.output, output_bytes) {
            eprintln!("Failed to write output file: {}", e);
            exit(1);
        }
    } else if cli.finalize {
        // clap guarantees signature present
        let signature = read_file(&cli.signature.unwrap()).unwrap_or_else(|e| {
            eprintln!("Failed to read signature file: {}", e);
            exit(1);
        });

        let output_bytes = json_set_signature(&cli.name, &input, &signature).unwrap_or_else(|e| {
            eprintln!("Failed to sign input json: {:?}", e);
            exit(1);
        });
        if let Err(e) = fs::write(&cli.output, output_bytes) {
            eprintln!("Failed to write output file: {}", e);
            exit(1);
        }
    } else {
        eprintln!("Either --finalize or --sign must be specified");
        exit(1);
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read {}", path.display()))
}
