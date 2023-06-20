// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Ok, Result};
use clap::Args;
use lazy_static::lazy_static;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use xshell::{cmd, Shell};

lazy_static! {
    static ref PROJECT_ROOT: &'static Path =
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    static ref DEFAULT_OUTPUT: PathBuf = PROJECT_ROOT.join("migtd.servtd_info_hash");
    static ref DEFAULT_SERVTD_INFO: PathBuf = PROJECT_ROOT.join("config/servtd_info.json");
    static ref SHIM_FOLDER: PathBuf = PROJECT_ROOT.join("deps/td-shim");
}

#[derive(Clone, Args)]
pub(crate) struct ServtdInfoHashArgs {
    #[clap(long)]
    image: PathBuf,
    #[clap(long)]
    servtd_info: Option<PathBuf>,
    #[clap(short, long)]
    output: Option<PathBuf>,
}

impl ServtdInfoHashArgs {
    pub fn generate(&self) -> Result<()> {
        let sh = Shell::new()?;
        sh.change_dir(SHIM_FOLDER.as_path());
        let cmd = cmd!(
            sh,
            "cargo run -p td-shim-tools --bin td-shim-tee-info-hash --features tee -- "
        )
        .args(&["-l", "off"])
        .args(&["--image", self.image()?.to_str().unwrap()])
        .args(&["--manifest", self.servtd_info()?.to_str().unwrap()]);

        let cmd = if self.output.is_some() {
            cmd.args(&["--out_bin", self.output()?.to_str().unwrap()])
        } else {
            cmd
        };

        cmd.run()?;

        Ok(())
    }

    fn servtd_info(&self) -> Result<PathBuf> {
        let path = self.servtd_info.as_ref().unwrap_or(&DEFAULT_SERVTD_INFO);
        fs::canonicalize(path).map_err(|e| e.into())
    }

    fn image(&self) -> Result<PathBuf> {
        let path = &self.image;
        fs::canonicalize(path).map_err(|e| e.into())
    }

    fn output(&self) -> Result<PathBuf> {
        let path = self
            .output
            .as_ref()
            .ok_or(anyhow!("output binary is not specified"))?;

        // Get the absolute path of the target file
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()?.join(path)
        };
        Ok(absolute)
    }
}
