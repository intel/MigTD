// Copyright (c) 2023 - 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Context};
use clap::Parser;
use log::debug;
use migtd_hash::{
    build_td_info, calculate_servtd_hash, calculate_servtd_info_hash, SERVTD_TYPE_MIGTD,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::exit,
};

const SERVTD_HASH_KEY: &str = "servtdHash";
const SERVTD_INFO_HASH_KEY: &str = "servtdInfoHash";

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn update_tcb_mapping_file(
    path: &Path,
    mrtd: &[u8],
    rtmr0: &[u8],
    rtmr1: &[u8],
) -> anyhow::Result<()> {
    let manifest =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let mut tcb_mapping: Value = serde_json::from_str(&manifest)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    let svn_mappings = tcb_mapping
        .get_mut("svnMappings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            anyhow!(
                "'svnMappings' missing or not an array in {}",
                path.display()
            )
        })?;
    let td_measurements = svn_mappings
        .get_mut(0)
        .ok_or_else(|| anyhow!("'svnMappings' array is empty in {}", path.display()))?
        .get_mut("tdMeasurements")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            anyhow!(
                "'tdMeasurements' missing or not an object in {}",
                path.display()
            )
        })?;

    for (key, value) in [("mrtd", mrtd), ("rtmr0", rtmr0), ("rtmr1", rtmr1)] {
        if !td_measurements.contains_key(key) {
            eprintln!("Warning: '{}' not found in tdMeasurements, adding it.", key);
        }
        td_measurements.insert(
            key.to_string(),
            Value::String(bytes_to_hex(value).to_uppercase()),
        );
    }

    let serialized = serde_json::to_string(&tcb_mapping).with_context(|| {
        format!(
            "Failed to serialize updated tcb mapping for {}",
            path.display()
        )
    })?;
    fs::write(path, serialized)
        .with_context(|| format!("Failed to write updated tcb mapping to {}", path.display()))?;
    println!("Updated {} successfully.", path.display());
    Ok(())
}
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
    /// Update the provided tcb_mapping JSON with the generated TD measurements
    #[clap(long)]
    pub update_tcb_mapping: Option<PathBuf>,
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
            "mrtd": bytes_to_hex(&td_info.mrtd),
            "rtmr0": bytes_to_hex(&td_info.rtmr0),
            "rtmr1": bytes_to_hex(&td_info.rtmr1),
            "rtmr2": bytes_to_hex(&td_info.rtmr2),
            "rtmr3": bytes_to_hex(&td_info.rtmr3),
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

    debug!("Updating tcb_mapping file...");
    if let Some(tcb_mapping_path) = &config.update_tcb_mapping {
        if let Err(e) = update_tcb_mapping_file(
            tcb_mapping_path,
            &td_info.mrtd,
            &td_info.rtmr0,
            &td_info.rtmr1,
        ) {
            eprintln!("Failed to update tcb_mapping file: {}", e);
            exit(1);
        }
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
