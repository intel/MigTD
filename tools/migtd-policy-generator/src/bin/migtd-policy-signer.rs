// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use clap::Parser;
use policy::v2::MigPolicy;
use std::{fs, path::PathBuf, process::exit};

#[derive(Debug, Clone, Parser)]
struct Config {
    /// The path of policy to be signed
    #[clap(long)]
    pub policy: PathBuf,
    /// The path of private key to sign the policy
    #[clap(long)]
    pub privkey: PathBuf,
    /// Where to write the generated policy
    #[clap(long, short)]
    pub output: PathBuf,
}

fn main() {
    let config = Config::parse();

    let policy_bytes = fs::read(&config.policy).unwrap_or_else(|e| {
        eprintln!("Failed to read policy file: {}", e);
        exit(1);
    });
    let signing_key = fs::read(&config.privkey).unwrap_or_else(|e| {
        eprintln!("Failed to read policy file: {}", e);
        exit(1);
    });

    let signed_policy = sign_policy(&policy_bytes, &signing_key).unwrap_or_else(|e| {
        eprintln!("Failed to sign policy: {}", e);
        exit(1);
    });
    fs::write(config.output, &signed_policy).unwrap_or_else(|e| {
        eprintln!("Failed to write output file: {}", e);
        exit(1);
    })
}

// Sign and return the signed policy in bytes
fn sign_policy(policy_bytes: &[u8], signing_key: &[u8]) -> Result<Vec<u8>> {
    let mut policy: MigPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|e| anyhow::anyhow!("deserialize unsigned policy: {:?}", e))?;
    policy
        .sign(signing_key)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    serde_json::to_vec(&policy).map_err(|e| anyhow::anyhow!("serialize signed policy: {}", e))
}
