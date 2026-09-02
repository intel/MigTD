// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::config;
use anyhow::{Context, Ok, Result};
use clap::{Args, ValueEnum};
use lazy_static::lazy_static;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use xshell::{cmd, Shell};

const MIGTD_DEFAULT_FEATURES: &str = "stack-guard,virtio-vsock";
const MIGTD_KVM_FEATURES: &str = MIGTD_DEFAULT_FEATURES;
const DEFAULT_TDVF_IMAGE_NAME: &str = "migtd.bin";
const DEFAULT_IGVM_IMAGE_NAME: &str = "migtd.igvm";
const DEFAULT_IMAGE_FORMAT: &str = "tdvf";
const MIGTD_TD_INFO_GUID: &str = "dbbdfad7-9cba-4aae-b498-c0fd425860b4";
const MIGTD_MAX_MIGRATION_CHANNEL_COUNT: u32 = 12;
const MIGTD_MAX_VCPU_COUNT: u32 = 1;

lazy_static! {
    static ref PROJECT_ROOT: &'static Path =
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    static ref SHIM_FOLDER: PathBuf = PROJECT_ROOT.join("deps/td-shim");
    static ref DEFAULT_OUTPUT: PathBuf = PROJECT_ROOT.join("target");
    static ref DEFAULT_POLICY: PathBuf = PROJECT_ROOT.join("config/policy_production_fmspc.json");
    static ref DEFAULT_CA: PathBuf =
        PROJECT_ROOT.join("config/Intel_SGX_Provisioning_Certification_RootCA.cer");
    static ref DEFAULT_METADATA: PathBuf = PROJECT_ROOT.join("config/metadata.json");
    static ref DEFAULT_METADATA_NO_TDINFO: PathBuf =
        PROJECT_ROOT.join("config/metadata_no_tdinfo.json");
    static ref DEFAULT_SHIM_LAYOUT: PathBuf = PROJECT_ROOT.join("config/shim_layout.json");
    static ref DEFAULT_IMAGE_LAYOUT: PathBuf = PROJECT_ROOT.join("config/image_layout.json");
    static ref DEFAULT_IMAGE_LAYOUT_NO_TDINFO: PathBuf =
        PROJECT_ROOT.join("config/image_layout_no_tdinfo.json");
    static ref DEFAULT_SERVTD_INFO: PathBuf = PROJECT_ROOT.join("config/servtd_info.json");
    static ref MMIO_LAYOUT_SOURCE: PathBuf = PROJECT_ROOT.join("src/devices/pci/src/layout.rs");
}

#[derive(Clone, Args)]
pub(crate) struct BuildArgs {
    /// Build artifacts in debug mode, without optimizations and with log messages
    #[clap(long)]
    debug: bool,
    /// Disable the default features `stack-guard` and `virtio-vsock` of `migtd` crate
    #[clap(long)]
    no_default_features: bool,
    /// List of features of `migtd` crate to activate in addition to the default features,
    /// separated by comma. By default, the `stack-guard` and `virtio-vsock` features are
    /// enabled
    #[clap(long)]
    features: Option<String>,
    /// The supported platform
    #[clap(long, value_enum)]
    platform: Option<Platform>,
    /// Path of customized metadata configuration file
    #[clap(long)]
    metadata: Option<PathBuf>,
    /// Path of SGX root certificate used for remote attestation
    #[clap(long)]
    root_ca: Option<PathBuf>,
    /// Path of MigTD policy file, required if `policy_v2` is set
    #[clap(long)]
    policy: Option<PathBuf>,
    /// Path of the output MigTD image
    #[clap(short, long)]
    output: Option<PathBuf>,
    /// Image format of the MigTD file
    #[clap(long)]
    image_format: Option<String>,
    /// Path of the configuration file for td-shim memory layout
    #[clap(long)]
    shim_layout: Option<PathBuf>,
    /// Path of the configuration file for td-shim image layout
    #[clap(long)]
    image_layout: Option<PathBuf>,
    /// Log level control in migtd, default value is `off` for release and `info` for debug
    #[clap(short, long)]
    log_level: Option<LogLevel>,
    /// MMIO space layout configuration for migtd
    #[clap(long)]
    mmio_config: Option<PathBuf>,
    /// Use migration policy v2
    #[clap(long)]
    policy_v2: bool,
    /// Issuer chain of migration policy v2. Provide this OR `--signer-anchor`
    /// (at least one is required when `policy_v2` is set).
    #[clap(long)]
    policy_issuer_chain: Option<PathBuf>,
    /// Security Version Number recorded in the MigTD TD_INFO structure
    #[clap(long, default_value_t = 1)]
    td_info_svn: u32,
    /// Omit TD_INFO for compatibility with VMMs that do not support TDVF Type 7
    #[clap(long)]
    no_tdinfo: bool,
    /// Path of the 48-byte RTMR1 signer anchor to enroll (CoRIM-only form),
    /// as an alternative to `--policy-issuer-chain`. The full PEM chain is not
    /// carried in the image; the anchor is measured into RTMR1 identically.
    /// Requires `policy_v2`.
    #[clap(long)]
    signer_anchor: Option<PathBuf>,
    /// Path of the signed ServTD TCB-mapping CoRIM (`COSE_Sign1`, `.cose`).
    /// When provided, it is enrolled into the CFV and the `servtd_corim`
    /// feature is activated so the runtime resolves `hash -> SVN` through the
    /// CoRIM. Requires `policy_v2`. The CoRIM is not measured, so enrolling it
    /// does not change the image `tdinfo_hash`.
    #[clap(long)]
    servtd_corim: Option<PathBuf>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Platform {
    Kvm,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    // Log levels can be statically set at compile time via Cargo features and they are
    // configured separately for release and debug build.
    // This function is used to output feature for `migtd` crate to control its log level.
    fn debug_feature(&self) -> &str {
        match self {
            LogLevel::Off => "log/max_level_off",
            LogLevel::Error => "log/max_level_error",
            LogLevel::Warn => "log/max_level_warn",
            LogLevel::Info => "log/max_level_info",
            LogLevel::Debug => "log/max_level_debug",
            LogLevel::Trace => "log/max_level_trace",
        }
    }

    fn release_feature(&self) -> &str {
        match self {
            LogLevel::Off => "log/release_max_level_off",
            LogLevel::Error => "log/release_max_level_error",
            LogLevel::Warn => "log/release_max_level_warn",
            LogLevel::Info => "log/release_max_level_info",
            LogLevel::Debug => "log/release_max_level_debug",
            LogLevel::Trace => "log/release_max_level_trace",
        }
    }
}

impl BuildArgs {
    pub fn build(&self) -> Result<PathBuf> {
        self.check_arguments()?;
        self.create_mmio_config()?;
        let (reset_vector, shim) = self.build_shim()?;
        let migtd = self.build_migtd()?;
        let bin = self.build_final(reset_vector.as_path(), shim.as_path(), migtd.as_path())?;
        self.enroll(bin.as_path())?;
        self.patch_td_info(bin.as_path())?;

        Ok(bin)
    }

    fn patch_td_info(&self, bin: &Path) -> Result<()> {
        if self.no_tdinfo || self.image_format() != DEFAULT_IMAGE_FORMAT {
            return Ok(());
        }

        let payload_path = bin.with_extension("td-info-payload.bin");
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&MIGTD_MAX_MIGRATION_CHANNEL_COUNT.to_le_bytes());
        payload.extend_from_slice(&MIGTD_MAX_VCPU_COUNT.to_le_bytes());
        fs::write(&payload_path, payload)?;

        let sh = Shell::new()?;
        sh.change_dir(SHIM_FOLDER.as_path());
        let version = self.migtd_version()?;
        let svn = self.td_info_svn.to_string();
        let patch_result = cmd!(
            sh,
            "cargo run -p td-shim-tools --bin td-shim-patch -- td-info"
        )
        .args(["--in", bin.to_str().unwrap()])
        .args(["--out", bin.to_str().unwrap()])
        .args(["--guid", MIGTD_TD_INFO_GUID])
        .args(["--version", version.as_str()])
        .args(["--svn", svn.as_str()])
        .args(["--payload-info", payload_path.to_str().unwrap()])
        .run();

        fs::remove_file(payload_path)?;
        patch_result?;
        Ok(())
    }

    fn migtd_version(&self) -> Result<String> {
        let sh = Shell::new()?;
        sh.change_dir(*PROJECT_ROOT);
        let metadata = cmd!(sh, "cargo metadata --format-version 1 --no-deps").read()?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
        metadata["packages"]
            .as_array()
            .and_then(|packages| packages.iter().find(|package| package["name"] == "migtd"))
            .and_then(|package| package["version"].as_str())
            .map(ToOwned::to_owned)
            .context("migtd package version not found in cargo metadata")
    }

    fn check_arguments(&self) -> Result<()> {
        if !self.no_tdinfo && self.image_format() == DEFAULT_IMAGE_FORMAT && self.td_info_svn == 0 {
            return Err(anyhow::anyhow!("TD_INFO SVN must be non-zero"));
        }

        if self.no_tdinfo {
            self.ensure_td_info_absent(&self.image_layout()?)?;
            self.ensure_td_info_absent(&self.metadata()?)?;
        }

        if self.policy_v2 {
            if self.policy.is_none() {
                return Err(anyhow::anyhow!(
                    "policy_v2 is enabled but no policy file is provided"
                ));
            }
            if self.policy_issuer_chain.is_none() && self.signer_anchor.is_none() {
                return Err(anyhow::anyhow!(
                    "policy_v2 is enabled but neither --policy-issuer-chain nor --signer-anchor was provided"
                ));
            }
        } else if self.servtd_corim.is_some() {
            return Err(anyhow::anyhow!("--servtd-corim requires --policy-v2"));
        }
        Ok(())
    }

    fn ensure_td_info_absent(&self, path: &Path) -> Result<()> {
        let content = fs::read_to_string(path)?;
        let config: serde_json::Value = serde_json::from_str(&content)?;
        let contains_td_info = config.get("TdInfo").is_some_and(|value| !value.is_null())
            || config["Sections"].as_array().is_some_and(|sections| {
                sections
                    .iter()
                    .any(|section| section["Type"].as_str() == Some("TdInfo"))
            });

        if contains_td_info {
            return Err(anyhow::anyhow!(
                "{} contains TdInfo and cannot be used with --no-tdinfo",
                path.display()
            ));
        }
        Ok(())
    }

    fn build_shim(&self) -> Result<(PathBuf, PathBuf)> {
        self.build_shim_layout()?;

        let sh = Shell::new()?;
        sh.change_dir(SHIM_FOLDER.as_path());
        if self.profile() == "release" {
            cmd!(sh, "cargo build -p td-shim --target x86_64-unknown-none --features=main,tdx,log/max_level_off --no-default-features --release")
                .run()?;
        } else {
            cmd!(sh, "cargo build -p td-shim --target x86_64-unknown-none --features=main,tdx,log/max_level_info --no-default-features --release")
                .run()?;
        }

        let shim_output = SHIM_FOLDER.join("target/x86_64-unknown-none/release");

        Ok((
            shim_output.join("ResetVector.bin"),
            shim_output.join("td-shim"),
        ))
    }

    fn build_shim_layout(&self) -> Result<()> {
        let layout_config = self.shim_layout()?;
        let image_config = self.image_layout()?;

        let sh = Shell::new()?;
        sh.change_dir(SHIM_FOLDER.join("devtools/td-layout-config"));
        cmd!(sh, "cargo run -- -t memory")
            .arg(layout_config.to_str().unwrap())
            .args([
                "-o",
                SHIM_FOLDER
                    .join("td-layout/src/runtime/exec.rs")
                    .to_str()
                    .unwrap(),
            ])
            .run()?;
        let mut cmd = cmd!(sh, "cargo run -- -t image")
            .arg(image_config.to_str().unwrap())
            .args([
                "-o",
                SHIM_FOLDER
                    .join("td-layout/src/build_time.rs")
                    .to_str()
                    .unwrap(),
            ]);

        if self.image_format == Some(String::from("igvm")) {
            let metadata = self.metadata()?;
            cmd = cmd.args(["-m", metadata.to_str().unwrap()]);
        }

        cmd.run()?;
        Ok(())
    }

    fn create_mmio_config(&self) -> Result<()> {
        if let Some(json_path) = &self.mmio_config {
            config::generate_mmio_config(json_path, &MMIO_LAYOUT_SOURCE)?;
        }
        Ok(())
    }

    fn build_migtd(&self) -> Result<PathBuf> {
        let sh = Shell::new()?;
        sh.set_var("CC_x86_64_unknown_none", "clang");
        sh.set_var("AR_x86_64_unknown_none", "llvm-ar");
        sh.set_var(
            "SPDM_CONFIG",
            PROJECT_ROOT
                .join("config/spdm_config.json")
                .to_str()
                .unwrap(),
        );

        cmd!(
            sh,
            "cargo build -p migtd --target x86_64-unknown-none --no-default-features"
        )
        .args(["--features", self.features().as_str()])
        .args(["--profile", self.profile()])
        .run()?;

        Ok(PROJECT_ROOT
            .join("target/x86_64-unknown-none/")
            .join(&self.profile_path())
            .join("migtd"))
    }

    fn build_final(&self, reset_vector: &Path, shim: &Path, migtd: &Path) -> Result<PathBuf> {
        let sh = Shell::new()?;
        sh.set_var("CC", "clang");
        sh.set_var("AR", "llvm-ar");

        sh.change_dir(SHIM_FOLDER.as_path());
        cmd!(
            sh,
            "cargo run -p td-shim-tools --bin td-shim-ld --no-default-features --features=linker"
        )
        .args(&[reset_vector])
        .args(&[shim])
        .args(&["-p", migtd.to_str().unwrap()])
        .args(&["-o", self.output()?.to_str().unwrap()])
        .args(&["-i", self.image_format()])
        .args(&["-m", self.metadata()?.to_str().unwrap()])
        .run()?;

        Ok(self.output()?.to_path_buf())
    }

    fn enroll(&self, bin: &Path) -> Result<()> {
        let sh = Shell::new()?;
        sh.set_var("CC", "clang");
        sh.set_var("AR", "llvm-ar");

        sh.change_dir(SHIM_FOLDER.as_path());
        let cmd = cmd!(
            sh,
            "cargo run -p td-shim-tools --bin td-shim-enroll --features=enroller"
        )
        .args(&[bin])
        .args(&[
            "-f",
            "0BE92DC3-6221-4C98-87C1-8EEFFD70DE5A",
            self.policy()?.to_str().unwrap(),
        ]);

        let cmd = if self.policy_v2 {
            // Enroll the RTMR1 signer anchor: prefer the 48-byte anchor slot
            // (CoRIM-only form) when `--signer-anchor` is given, else the
            // legacy policy issuer chain PEM.
            if let Some(anchor) = &self.signer_anchor {
                let anchor = fs::canonicalize(anchor)?;
                cmd.args(&[
                    "2B9D5A84-6F3C-4E71-8A2D-0C7E1F4B6A93",
                    anchor.to_str().unwrap(),
                ])
            } else {
                cmd.args(&[
                    "3F2FB27A-9596-431C-A68D-D3EAB39F8AEB",
                    self.policy_issuer_chain()?.to_str().unwrap(),
                ])
            }
        } else {
            cmd.args(&[
                "CA437832-4C51-4322-B13D-A21BD0C8FFF6",
                self.root_ca()?.to_str().unwrap(),
            ])
        };

        // Enroll the optional signed CoRIM under its FFS GUID.
        let corim_path = self.servtd_corim()?;
        let cmd = if let Some(corim) = &corim_path {
            cmd.args(&[
                "7E5B9C11-2D4A-4F6E-9B3C-1A2B3C4D5E6F",
                corim.to_str().unwrap(),
            ])
        } else {
            cmd
        };

        cmd.args(&["-o", bin.to_str().unwrap()]).run()?;

        Ok(())
    }

    fn profile(&self) -> &str {
        if self.debug {
            "dev"
        } else {
            "release"
        }
    }

    fn profile_path(&self) -> &str {
        if self.debug {
            "debug"
        } else {
            "release"
        }
    }

    fn features(&self) -> String {
        let mut features = String::new();
        features.push_str("main");

        if !self.no_default_features {
            features.push_str(",");
            if let Some(platform) = self.platform {
                match platform {
                    Platform::Kvm => features.push_str(MIGTD_KVM_FEATURES),
                }
            } else {
                features.push_str(MIGTD_DEFAULT_FEATURES);
            }
        }

        if self.policy_v2 {
            features.push_str(",policy_v2");
        }

        if self.servtd_corim.is_some() {
            features.push_str(",servtd_corim");
        }

        if let Some(selected) = &self.features {
            features.push_str(",");
            features.push_str(selected);
        }

        features.push_str(",");
        if self.debug {
            println!("Building debug MigTD");
            match self.log_level {
                Some(loglevel) => match loglevel {
                    LogLevel::Off => {
                        println!("Building debug MigTD found loglevel=Off), overriding to Info");
                        features.push_str(LogLevel::Info.debug_feature());
                    }
                    LogLevel::Error => {
                        println!("Building debug MigTD found loglevel=Error");
                        features.push_str(loglevel.debug_feature());
                    }
                    LogLevel::Warn => {
                        println!("Building debug MigTD found loglevel=Warn");
                        features.push_str(loglevel.debug_feature());
                    }
                    LogLevel::Info => {
                        println!("Building debug MigTD found loglevel=Info");
                        features.push_str(loglevel.debug_feature());
                    }
                    LogLevel::Debug => {
                        println!("Building debug MigTD found loglevel=Debug");
                        features.push_str(loglevel.debug_feature());
                    }
                    LogLevel::Trace => {
                        println!("Building debug MigTD found loglevel=Trace");
                        features.push_str(loglevel.debug_feature());
                    }
                },
                _ => {
                    println!("Building debug MigTD found None(loglevel)");
                }
            }
        } else {
            println!("Building release MigTD");
            match self.log_level {
                Some(loglevel) => match loglevel {
                    LogLevel::Off => {
                        println!("Building release MigTD found loglevel=Off), overriding to Info");
                        features.push_str(LogLevel::Info.release_feature());
                    }
                    LogLevel::Error => {
                        println!("Building release MigTD found loglevel=Error");
                        features.push_str(loglevel.release_feature());
                    }
                    LogLevel::Warn => {
                        println!("Building release MigTD found loglevel=Warn");
                        features.push_str(loglevel.release_feature());
                    }
                    LogLevel::Info => {
                        println!("Building release MigTD found loglevel=Info");
                        features.push_str(loglevel.release_feature());
                    }
                    LogLevel::Debug => {
                        println!("Building release MigTD found loglevel=Debug");
                        features.push_str(loglevel.release_feature());
                    }
                    LogLevel::Trace => {
                        println!("Building release MigTD found loglevel=Trace");
                        features.push_str(loglevel.release_feature());
                    }
                },
                _ => {
                    println!("Building release MigTD found None(loglevel)");
                }
            }
        }

        features
    }

    fn metadata(&self) -> Result<PathBuf> {
        let default: &Path = if self.no_tdinfo {
            DEFAULT_METADATA_NO_TDINFO.as_path()
        } else {
            DEFAULT_METADATA.as_path()
        };
        let path = self.metadata.as_deref().unwrap_or(default);
        fs::canonicalize(path).map_err(|e| e.into())
    }

    fn output(&self) -> Result<PathBuf> {
        let default_image_name = match self.image_format.as_deref() {
            Some("igvm") => DEFAULT_IGVM_IMAGE_NAME,
            _ => DEFAULT_TDVF_IMAGE_NAME,
        };

        let path = self.output.clone().unwrap_or(
            DEFAULT_OUTPUT
                .join(self.profile_path())
                .join(default_image_name),
        );

        // Get the absolute path of the target file
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()?.join(path)
        };
        Ok(absolute)
    }

    fn image_format(&self) -> &str {
        self.image_format.as_deref().unwrap_or(DEFAULT_IMAGE_FORMAT)
    }

    fn policy(&self) -> Result<PathBuf> {
        let path = if self.policy_v2 {
            match &self.policy {
                Some(path) => path,
                None => {
                    return Err(anyhow::anyhow!(
                        "policy_v2 is enabled but no policy file is provided"
                    ))
                }
            }
        } else {
            self.policy.as_ref().unwrap_or(&DEFAULT_POLICY)
        };
        fs::canonicalize(path).map_err(|e| e.into())
    }

    fn policy_issuer_chain(&self) -> Result<PathBuf> {
        let path = self
            .policy_issuer_chain
            .as_ref()
            .ok_or(anyhow::anyhow!("No policy_issuer_chain file is provided"))?;
        fs::canonicalize(path).map_err(|e| e.into())
    }

    /// Canonicalized path of the signed ServTD TCB-mapping CoRIM, if provided.
    fn servtd_corim(&self) -> Result<Option<PathBuf>> {
        match self.servtd_corim.as_ref() {
            Some(path) => Ok(Some(fs::canonicalize(path)?)),
            None => Ok(None),
        }
    }

    fn root_ca(&self) -> Result<PathBuf> {
        let path = self.root_ca.as_ref().unwrap_or(&DEFAULT_CA);
        fs::canonicalize(path).map_err(|e| e.into())
    }

    fn shim_layout(&self) -> Result<PathBuf> {
        let path = self.shim_layout.as_ref().unwrap_or(&DEFAULT_SHIM_LAYOUT);
        fs::canonicalize(path).map_err(|e| e.into())
    }

    fn image_layout(&self) -> Result<PathBuf> {
        let default: &Path = if self.no_tdinfo {
            DEFAULT_IMAGE_LAYOUT_NO_TDINFO.as_path()
        } else {
            DEFAULT_IMAGE_LAYOUT.as_path()
        };
        let path = self.image_layout.as_deref().unwrap_or(default);
        fs::canonicalize(path).map_err(|e| e.into())
    }
}
