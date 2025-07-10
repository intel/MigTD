// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{Ok, Result};
use clap::{Args, ValueEnum};
use lazy_static::lazy_static;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use xshell::{cmd, Shell};

use crate::config;

const MIGTD_DEFAULT_FEATURES: &str = "stack-guard,virtio-vsock";
const MIGTD_KVM_FEATURES: &str = MIGTD_DEFAULT_FEATURES;
const DEFAULT_IMAGE_NAME: &str = "migtd.bin";

lazy_static! {
    static ref PROJECT_ROOT: &'static Path =
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    static ref SHIM_FOLDER: PathBuf = PROJECT_ROOT.join("deps/td-shim");
    static ref DEFAULT_OUTPUT: PathBuf = PROJECT_ROOT.join("target");
    static ref DEFAULT_POLICY: PathBuf = PROJECT_ROOT.join("config/policy_production_fmspc.json");
    static ref DEFAULT_CA: PathBuf =
        PROJECT_ROOT.join("config/Intel_SGX_Provisioning_Certification_RootCA.cer");
    static ref DEFAULT_METADATA: PathBuf = PROJECT_ROOT.join("config/metadata.json");
    static ref DEFAULT_SHIM_LAYOUT: PathBuf = PROJECT_ROOT.join("config/shim_layout.json");
    static ref DEFAULT_IMAGE_LAYOUT: PathBuf = PROJECT_ROOT.join("config/image_layout.json");
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
    /// Path of MigTD policy file
    #[clap(long)]
    policy: Option<PathBuf>,
    /// Path of engine-svn mapping file, for policy v2
    #[clap(long)]
    engine: Option<PathBuf>,
    /// Path of policy public key, for policy v2
    #[clap(long)]
    policy_pubkey: Option<PathBuf>,
    /// Path of engine public key, for policy v2
    #[clap(long)]
    engine_pubkey: Option<PathBuf>,
    /// Path of migtd collaterals, for policy v2
    #[clap(long)]
    collaterals: Option<PathBuf>,
    /// Path of the output MigTD image
    #[clap(short, long)]
    output: Option<PathBuf>,
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

    fn relase_feature(&self) -> &str {
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
        self.create_mmio_config()?;
        let (reset_vector, shim) = self.build_shim()?;
        let migtd = self.build_migtd()?;
        let bin = self.build_final(reset_vector.as_path(), shim.as_path(), migtd.as_path())?;
        self.enroll(bin.as_path())?;

        Ok(bin)
    }

    fn build_shim(&self) -> Result<(PathBuf, PathBuf)> {
        self.build_shim_layout()?;

        let sh = Shell::new()?;
        sh.change_dir(SHIM_FOLDER.as_path());
        cmd!(sh, "cargo build -p td-shim --target x86_64-unknown-none --features=main,tdx --no-default-features --release")
			.run()?;

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
        cmd!(sh, "cargo run -- -t image")
            .arg(image_config.to_str().unwrap())
            .args([
                "-o",
                SHIM_FOLDER
                    .join("td-layout/src/build_time.rs")
                    .to_str()
                    .unwrap(),
            ])
            .run()?;
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
        .args(&["-m", self.metadata()?.to_str().unwrap()])
        .run()?;

        Ok(self.output()?.to_path_buf())
    }

    fn enroll(&self, bin: &Path) -> Result<()> {
        let sh = Shell::new()?;
        sh.set_var("CC", "clang");
        sh.set_var("AR", "llvm-ar");

        sh.change_dir(SHIM_FOLDER.as_path());
        let mut cmd = cmd!(
            sh,
            "cargo run -p td-shim-tools --bin td-shim-enroll --features=enroller"
        )
        .arg(bin)
        .args(&["-o", bin.to_str().unwrap()]);

        cmd = cmd.args(&[
            "-f",
            "0BE92DC3-6221-4C98-87C1-8EEFFD70DE5A",
            self.policy()?.to_str().unwrap(),
            "CA437832-4C51-4322-B13D-A21BD0C8FFF6",
            self.root_ca()?.to_str().unwrap(),
        ]);

        if let Some(engine) = &self.engine {
            let path = fs::canonicalize(engine)?;
            cmd = cmd.args(&[
                "B1A29D14-2D12-4307-9C10-A47960838A85",
                path.to_str().unwrap(),
            ]);
        }
        if let Some(policy_pubkey) = &self.policy_pubkey {
            let path = fs::canonicalize(policy_pubkey)?;
            cmd = cmd.args(&[
                "B3C1DCFE-6BEF-449F-A183-63A84EA1E0B4",
                path.to_str().unwrap(),
            ]);
        }
        if let Some(engine_pubkey) = &self.engine_pubkey {
            let path = fs::canonicalize(engine_pubkey)?;
            cmd = cmd.args(&[
                "EDFD2B6D-7FA9-455B-9EA1-4CA0B9EC01A8",
                path.to_str().unwrap(),
            ]);
        }
        if let Some(collaterals) = &self.collaterals {
            let path = fs::canonicalize(collaterals)?;
            cmd = cmd.args(&[
                "A55107C8-5599-48F3-A2AD-8D2ECA13CD03",
                path.to_str().unwrap(),
            ]);
        }

        cmd.run()?;
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

        if let Some(selected) = &self.features {
            features.push_str(",");
            features.push_str(selected);
        }

        features.push_str(",");
        if self.debug {
            features.push_str(self.log_level.unwrap_or(LogLevel::Info).debug_feature());
        } else {
            features.push_str(self.log_level.unwrap_or(LogLevel::Off).relase_feature());
        }

        features
    }

    fn metadata(&self) -> Result<PathBuf> {
        let path = self.metadata.as_ref().unwrap_or(&DEFAULT_METADATA);
        fs::canonicalize(path).map_err(|e| e.into())
    }

    fn output(&self) -> Result<PathBuf> {
        let path = self.output.clone().unwrap_or(
            DEFAULT_OUTPUT
                .join(self.profile_path())
                .join(DEFAULT_IMAGE_NAME),
        );

        // Get the absolute path of the target file
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()?.join(path)
        };
        Ok(absolute)
    }

    fn policy(&self) -> Result<PathBuf> {
        let path = self.policy.as_ref().unwrap_or(&DEFAULT_POLICY);
        fs::canonicalize(path).map_err(|e| e.into())
    }

    // fn engine(&self) -> Result<PathBuf> {
    //     let path = self.policy.as_ref().unwrap_or(&DEFAULT_POLICY);
    //     fs::canonicalize(path).map_err(|e| e.into())
    // }

    // fn policy_pubkey(&self) -> Result<PathBuf> {
    //     let path = self.policy.as_ref().unwrap_or(&DEFAULT_POLICY);
    //     fs::canonicalize(path).map_err(|e| e.into())
    // }

    // fn engine_pubkey(&self) -> Result<PathBuf> {
    //     let path = self.policy.as_ref().unwrap_or(&DEFAULT_POLICY);
    //     fs::canonicalize(path).map_err(|e| e.into())
    // }

    fn root_ca(&self) -> Result<PathBuf> {
        let path = self.root_ca.as_ref().unwrap_or(&DEFAULT_CA);
        fs::canonicalize(path).map_err(|e| e.into())
    }

    fn shim_layout(&self) -> Result<PathBuf> {
        let path = self.shim_layout.as_ref().unwrap_or(&DEFAULT_SHIM_LAYOUT);
        fs::canonicalize(path).map_err(|e| e.into())
    }

    fn image_layout(&self) -> Result<PathBuf> {
        let path = self.image_layout.as_ref().unwrap_or(&DEFAULT_IMAGE_LAYOUT);
        fs::canonicalize(path).map_err(|e| e.into())
    }
}
