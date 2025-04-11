// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::Parser;
use migtd_hash::calculate_servtd_hash;
use std::{
    fs::{self, File},
    path::PathBuf,
    process::exit,
};

#[derive(Clone, Parser)]
struct Config {
    /// A json format manifest that contains values of TD info fields
    #[clap(short, long)]
    pub manifest: String,
    /// Path of MigTD image file
    #[clap(short, long)]
    pub image: String,
    /// Output binary of tee info hash
    #[clap(short, long)]
    pub output_file: Option<PathBuf>,
    /// The input MigTD image enables the `test_disable_ra_and_accept_all` feature
    #[clap(short, long)]
    pub test_disable_ra_and_accept_all: bool,
}

fn main() {
    let config = Config::parse();

    let image = File::open(config.image).unwrap_or_else(|e| {
        eprintln!("Failed to open MigTD image: {}", e);
        exit(1);
    });
    let manifest = fs::read(config.manifest).unwrap_or_else(|e| {
        eprintln!("Failed to open manifest file: {}", e);
        exit(1);
    });

    let hash = calculate_servtd_hash(&manifest, image, config.test_disable_ra_and_accept_all)
        .unwrap_or_else(|e| {
            eprintln!("Failed to calculate hash: {:?}", e);
            exit(1);
        });

    if let Some(output_file) = config.output_file {
        fs::write(output_file, &hash).unwrap_or_else(|e| {
            eprintln!("Failed to write output file: {}", e);
            exit(1);
        })
    } else {
        println!(
            "{}",
            hash.iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>()
        )
    }
}
