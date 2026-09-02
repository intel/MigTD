// Copyright (c) 2023 - 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Context};
use clap::Parser;
use log::debug;
use migtd_hash::{
    apply_servtd_attr_masks, build_td_info_unmasked, calculate_servtd_hash,
    calculate_servtd_info_hash, calculate_tdinfo_hash, clone_td_info, SERVTD_TYPE_MIGTD,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::exit,
};
use td_shim_tools::tee_info_hash::TdInfoStruct;

const SERVTD_HASH_KEY: &str = "servtdHash";
const SERVTD_INFO_HASH_KEY: &str = "servtdInfoHash";

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Decode `field` from a hex string in `value`, expecting `expected_len` bytes.
fn decode_hex_field(value: &Value, field: &str, expected_len: usize) -> anyhow::Result<Vec<u8>> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("'{}' missing or not a string in report JSON", field))?;
    let bytes = hex::decode(s.trim())
        .with_context(|| format!("Failed to hex-decode '{}': {}", field, s))?;
    if bytes.len() != expected_len {
        return Err(anyhow!(
            "'{}' is {} bytes, expected {}",
            field,
            bytes.len(),
            expected_len
        ));
    }
    Ok(bytes)
}

/// Build an unmasked TdInfoStruct directly from an azcvm-extract-report JSON
/// dump. The report's RTMR2 value is taken verbatim (it is already the
/// runtime measurement extended by the live MigTD; no offline recomputation
/// is needed or possible without the matching IGVM + policy).
fn build_td_info_from_report(report_path: &Path) -> anyhow::Result<TdInfoStruct> {
    let raw = fs::read(report_path)
        .with_context(|| format!("Failed to read {}", report_path.display()))?;
    let v: Value = serde_json::from_slice(&raw)
        .with_context(|| format!("Failed to parse {}", report_path.display()))?;

    let mut td = TdInfoStruct::default();
    td.attributes
        .copy_from_slice(&decode_hex_field(&v, "attributes", 8)?);
    td.xfam.copy_from_slice(&decode_hex_field(&v, "xfam", 8)?);
    td.mrtd.copy_from_slice(&decode_hex_field(&v, "mrtd", 48)?);
    td.mrconfig_id
        .copy_from_slice(&decode_hex_field(&v, "mrConfigId", 48)?);
    td.mrowner
        .copy_from_slice(&decode_hex_field(&v, "mrOwner", 48)?);
    td.mrownerconfig
        .copy_from_slice(&decode_hex_field(&v, "mrOwnerConfig", 48)?);
    td.rtmr0
        .copy_from_slice(&decode_hex_field(&v, "rtmr0", 48)?);
    td.rtmr1
        .copy_from_slice(&decode_hex_field(&v, "rtmr1", 48)?);
    td.rtmr2
        .copy_from_slice(&decode_hex_field(&v, "rtmr2", 48)?);
    td.rtmr3
        .copy_from_slice(&decode_hex_field(&v, "rtmr3", 48)?);
    Ok(td)
}

/// Write the v2-style `tdinfo_hash` into the TCB mapping JSON at
/// `svnMappings[0].tdMeasurements`. Removes the legacy
/// `{mrtd, rtmr0, rtmr1}` fields if present.
fn update_tcb_mapping_file_v2(path: &Path, tdinfo_hash: &[u8]) -> anyhow::Result<()> {
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

    // Remove legacy fields if present so the file matches the v2 schema exactly.
    for legacy_key in ["mrtd", "rtmr0", "rtmr1"] {
        td_measurements.remove(legacy_key);
    }

    td_measurements.insert(
        "tdinfo_hash".to_string(),
        Value::String(bytes_to_hex(tdinfo_hash).to_uppercase()),
    );

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

/// Legacy v1 writer: writes mrtd/rtmr0/rtmr1 into the TCB mapping file.
fn update_tcb_mapping_file_v1(
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
    /// A json format manifest that contains values of TD info fields.
    /// Required when using `--image`; ignored with `--from-report`.
    #[clap(short, long)]
    pub manifest: Option<String>,
    /// Path of MigTD image file.
    /// Required when computing measurements from a build artifact; mutually
    /// exclusive with `--from-report`.
    #[clap(short, long)]
    pub image: Option<String>,
    /// Path of a `migtd_report_data.json` produced by `azcvm-extract-report`
    /// (camelCase fields: mrtd, rtmr0..3, attributes, xfam, mrConfigId,
    /// mrOwner, mrOwnerConfig — all hex). When set, the TDINFO_STRUCT is
    /// taken verbatim from the report and `--image`/`--manifest` are not
    /// needed. Intended for the AzCVMEmu mock-report flow where no IGVM is
    /// available. Requires `--policy-v2`.
    #[clap(long, conflicts_with_all = ["image", "manifest"])]
    pub from_report: Option<PathBuf>,
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
    /// Output the v2-style `tdinfo_hash` (= SHA384(TDINFO_STRUCT), equals
    /// `init_servtd_info_hash` for attr=0) as a hex-encoded text file.
    /// ALWAYS uses unmasked TDINFO regardless of `--servtd-attr`.
    #[clap(long)]
    pub output_tdinfo_hash: Option<PathBuf>,
    /// Enable verbose logging
    #[clap(short, long)]
    pub verbose: bool,
    /// Update the provided tcb_mapping JSON with the generated TD measurements.
    /// For v2 (`--policy-v2`), writes `tdinfo_hash` to `tdMeasurements`.
    /// For v1, writes `mrtd`/`rtmr0`/`rtmr1`.
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

    let servtd_attr = config.servtd_attr.unwrap_or(0);
    debug!("ServTD attributes: {:#x}", servtd_attr);

    // Branch 1: --from-report mode. Build TDINFO from the saved report JSON
    // directly. RTMR2 is taken verbatim from the report (it was extended at
    // runtime by the live MigTD). --image / --manifest are rejected by clap,
    // so we only need to honor the output flags.
    let unmasked_td_info = if let Some(report_path) = &config.from_report {
        if !config.policy_v2 {
            eprintln!("--from-report requires --policy-v2");
            exit(1);
        }
        debug!("Loading TDINFO from report JSON: {}", report_path.display());
        build_td_info_from_report(report_path).unwrap_or_else(|e| {
            eprintln!("Failed to build TD info from report: {:?}", e);
            exit(1);
        })
    } else {
        // Branch 2: image+manifest mode (original behavior). What we measure
        // is what the IGVM's CFV contains; the release pipeline uses
        // `td-shim-enroll` (no Rust rebuild) to inject the production policy
        // and issuer chain into the base IGVM before calling this tool.
        let image_path = config.image.as_deref().unwrap_or_else(|| {
            eprintln!("Either --image (with --manifest) or --from-report must be supplied");
            exit(1);
        });
        let manifest_path = config.manifest.as_deref().unwrap_or_else(|| {
            eprintln!("--image requires --manifest");
            exit(1);
        });

        debug!("Image: {}", image_path);
        debug!("Manifest: {}", manifest_path);
        let imagename = image_path.to_string();
        let mut igvmformat = false;

        debug!("Opening image file: {}", image_path);
        let image = File::open(image_path).unwrap_or_else(|e| {
            eprintln!("Failed to open MigTD image: {}", e);
            exit(1);
        });

        debug!("Reading manifest file: {}", manifest_path);
        let manifest = fs::read(manifest_path).unwrap_or_else(|e| {
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

        debug!("Building TD info structure (unmasked)...");
        build_td_info_unmasked(
            &manifest,
            image,
            config.test_disable_ra_and_accept_all,
            config.policy_v2,
            igvmformat,
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to build TD info: {:?}", e);
            exit(1);
        })
    };

    // v2 mappings use the unmasked TDINFO hash (attr=0).
    let tdinfo_hash_v2 = if config.policy_v2 {
        Some(
            calculate_tdinfo_hash(clone_td_info(&unmasked_td_info)).unwrap_or_else(|e| {
                eprintln!("Failed to calculate tdinfo_hash: {:?}", e);
                exit(1);
            }),
        )
    } else {
        None
    };

    if let Some(ref hash) = tdinfo_hash_v2 {
        debug!("tdinfo_hash (unmasked, attr=0): {}", bytes_to_hex(hash));
    }

    if let Some(output_tdinfo_hash) = &config.output_tdinfo_hash {
        let hash = tdinfo_hash_v2
            .as_ref()
            .expect("--output-tdinfo-hash requires --policy-v2");
        debug!("Writing tdinfo_hash to: {:?}", output_tdinfo_hash);
        fs::write(output_tdinfo_hash, bytes_to_hex(hash)).unwrap_or_else(|e| {
            eprintln!("Failed to write tdinfo_hash file: {}", e);
            exit(1);
        });
    }

    // Apply the (possibly masked) servtd_attr to produce the td_info used for
    // the remaining outputs (`--output-file`, `--output-td-info`).
    let mut td_info = clone_td_info(&unmasked_td_info);
    apply_servtd_attr_masks(&mut td_info, servtd_attr);

    debug!("td_info: {:?}", td_info);
    debug!("MRTD: {}", bytes_to_hex(&td_info.mrtd));
    debug!("RTMR0: {}", bytes_to_hex(&td_info.rtmr0));
    debug!("RTMR1: {}", bytes_to_hex(&td_info.rtmr1));
    debug!("RTMR2: {}", bytes_to_hex(&td_info.rtmr2));
    debug!("RTMR3: {}", bytes_to_hex(&td_info.rtmr3));

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
        let result = if config.policy_v2 {
            let hash = tdinfo_hash_v2
                .as_ref()
                .expect("v2 tcb-mapping update requires tdinfo_hash to be computed");
            update_tcb_mapping_file_v2(tcb_mapping_path, hash)
        } else {
            update_tcb_mapping_file_v1(
                tcb_mapping_path,
                &td_info.mrtd,
                &td_info.rtmr0,
                &td_info.rtmr1,
            )
        };
        if let Err(e) = result {
            eprintln!("Failed to update tcb_mapping file: {}", e);
            exit(1);
        }
    }

    debug!("Calculating servtd_info_hash...");
    let servtd_info_hash = calculate_servtd_info_hash(td_info).unwrap_or_else(|e| {
        eprintln!("Failed to calculate hash: {:?}", e);
        exit(1);
    });
    debug!("servtd_info_hash: {}", bytes_to_hex(&servtd_info_hash));

    debug!("Calculating servtd_hash...");
    let servtd_hash = calculate_servtd_hash(&servtd_info_hash, SERVTD_TYPE_MIGTD, servtd_attr)
        .unwrap_or_else(|e| {
            eprintln!("Failed to calculate hash: {:?}", e);
            exit(1);
        });
    debug!("servtd_hash: {}", bytes_to_hex(&servtd_hash));

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
                key: bytes_to_hex(&hash),
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
                key: bytes_to_hex(&hash),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap())
        } else {
            println!("{}", bytes_to_hex(&hash))
        }
    }
}
