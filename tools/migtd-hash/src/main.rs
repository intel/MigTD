// Copyright (c) 2023 - 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::Parser;
use log::debug;
use migtd_hash::{
    build_td_info, calculate_servtd_hash, calculate_servtd_info_hash, SERVTD_TYPE_MIGTD,
};
use serde_json::json;
use std::{
    fs::{self, File},
    path::PathBuf,
    process::exit,
};

const SERVTD_HASH_KEY: &str = "servtdHash";
const SERVTD_INFO_HASH_KEY: &str = "servtdInfoHash";

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
    /// Output the servtd_hash or servtd_info_hash in JSON.
    #[clap(long)]
    pub json: bool,
    /// The input MigTD image enables the `test_disable_ra_and_accept_all` feature
    #[clap(short, long)]
    pub test_disable_ra_and_accept_all: bool,
    /// The input MigTD image enables the `policy_v2` feature
    #[clap(long)]
    pub policy_v2: bool,
    /// Servtd_attr value (default 0)
    #[clap(short, long)]
    pub servtd_attr: Option<u64>,
    /// Indicator to calculate final servtd_hash instead of servtd_info_hash (default false)
    #[clap(short, long)]
    pub calc_servtd_hash: bool,
    /// Output in TD Info in JSON format
    #[clap(long)]
    pub output_td_info: Option<PathBuf>,
    /// Enable verbose logging
    #[clap(short, long)]
    pub verbose: bool,
}

fn main() {
    let config = Config::parse();

    // Initialize logger based on verbose flag
    if config.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Off)
            .init();
    }

    debug!("Starting migtd-hash tool");
    debug!("Image: {}", config.image);
    debug!("Manifest: {}", config.manifest);
    let imagename = config.image.clone();
    let mut igvmformat = false;

    debug!("Opening image file: {}", config.image);
    let image = File::open(config.image).unwrap_or_else(|e| {
        eprintln!("Failed to open MigTD image: {}", e);
        exit(1);
    });

    debug!("Reading manifest file: {}", config.manifest);
    let manifest = fs::read(config.manifest).unwrap_or_else(|e| {
        eprintln!("Failed to open manifest file: {}", e);
        exit(1);
    });

    assert_eq!(
        imagename.contains(".igvm") || imagename.contains(".bin"),
        true
    );

    if imagename.contains(".igvm") {
        igvmformat = true;
        debug!("Detected IGVM format");
    } else {
        debug!("Detected BIN format");
    }

    let servtd_attr = config.servtd_attr.unwrap_or(0);
    debug!("ServTD attributes: {:#x}", servtd_attr);

    debug!("Building TD info structure...");
    let td_info = build_td_info(
        &manifest,
        image,
        config.test_disable_ra_and_accept_all,
        config.policy_v2,
        servtd_attr,
        igvmformat,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to build TD info: {:?}", e);
        exit(1);
    });

    debug!("td_info: {:?}", td_info);
    debug!(
        "MRTD: {}",
        td_info
            .mrtd
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    debug!(
        "RTMR0: {}",
        td_info
            .rtmr0
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    debug!(
        "RTMR1: {}",
        td_info
            .rtmr1
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    debug!(
        "RTMR2: {}",
        td_info
            .rtmr2
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    debug!(
        "RTMR3: {}",
        td_info
            .rtmr3
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    if let Some(output_td_info) = config.output_td_info {
        debug!("Writing TD Info to: {:?}", output_td_info);
        let td_info_json = json!({
            "mrtd": td_info.mrtd.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "rtmr0": td_info.rtmr0.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "rtmr1": td_info.rtmr1.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "rtmr2": td_info.rtmr2.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "rtmr3": td_info.rtmr3.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        });

        fs::write(
            output_td_info,
            serde_json::to_string(&td_info_json).unwrap(),
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to write output file: {}", e);
            exit(1);
        })
    }

    debug!("Calculating servtd_info_hash...");
    let servtd_info_hash = calculate_servtd_info_hash(td_info).unwrap_or_else(|e| {
        eprintln!("Failed to calculate hash: {:?}", e);
        exit(1);
    });
    debug!(
        "servtd_info_hash: {}",
        servtd_info_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    debug!("Calculating servtd_hash...");
    let servtd_hash = calculate_servtd_hash(&servtd_info_hash, SERVTD_TYPE_MIGTD, servtd_attr)
        .unwrap_or_else(|e| {
            eprintln!("Failed to calculate hash: {:?}", e);
            exit(1);
        });
    debug!(
        "servtd_hash: {}",
        servtd_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    let (hash, key) = if config.calc_servtd_hash {
        debug!("Using servtd_hash (final hash)");
        (servtd_hash, SERVTD_HASH_KEY)
    } else {
        debug!("Using servtd_info_hash");
        (servtd_info_hash, SERVTD_INFO_HASH_KEY)
    };

    if let Some(output_file) = config.output_file {
        debug!("Writing hash to file: {:?}", output_file);
        if config.json {
            let json = json!({
                key: hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            });
            fs::write(output_file, serde_json::to_string(&json).unwrap()).unwrap_or_else(|e| {
                eprintln!("Failed to write output file: {}", e);
                exit(1);
            });
        } else {
            fs::write(output_file, &hash).unwrap_or_else(|e| {
                eprintln!("Failed to write output file: {}", e);
                exit(1);
            })
        }
    } else {
        debug!("Hash calculation complete");
        if config.json {
            let json = json!({
                key: hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap())
        } else {
            println!(
                "{}",
                hash.iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<String>()
            )
        }
    }
}
