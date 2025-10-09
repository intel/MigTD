// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use clap::Args;
use xshell::{cmd, Shell};

const DEFAULT_LIB_CRATES: [&str; 7] = [
    "migtd",
    "crypto",
    "attestation",
    "pci",
    "virtio",
    "vsock",
    "policy",
];

#[derive(Clone, Args)]
pub(crate) struct LibraryCrates {
    #[clap(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
    crates: Option<Vec<String>>,
}

impl LibraryCrates {
    pub fn test(&self) -> Result<()> {
        let sh = Shell::new()?;
        let crates = self.crates();
        for name in crates {
            // Need to enable `test` features to skip the build script for crate `attestation`
            if name.as_str() == "attestation" {
                cmd!(sh, "cargo test")
                    .args(["-p", name.as_str(), "--features", "test"])
                    .run()?;
            } else if name.as_str() == "migtd" {
                cmd!(sh, "cargo test")
                    .args([
                        "-p",
                        name.as_str(),
                        "--features",
                        "test_disable_ra_and_accept_all",
                    ])
                    .run()?;
                cmd!(sh, "cargo test")
                    .args(["-p", name.as_str(), "--features", "policy_v2"])
                    .run()?;
            } else if name.as_str() == "policy" {
                // Run tests for policy V1 and V2
                cmd!(sh, "cargo test").args(["-p", name.as_str()]).run()?;
                cmd!(sh, "cargo test")
                    .args(["-p", name.as_str(), "--features", "policy_v2"])
                    .run()?;
            } else {
                cmd!(sh, "cargo test").args(["-p", name.as_str()]).run()?;
            }
        }
        Ok(())
    }

    pub fn build(&self) -> Result<()> {
        let sh = Shell::new()?;
        let crates = self.crates();
        for name in crates {
            cmd!(sh, "cargo build")
                .args(["-p", name.as_str()])
                .args(["--profile", "release"])
                .run()?;
        }
        Ok(())
    }

    fn crates(&self) -> Vec<String> {
        if let Some(specified) = self.crates.as_ref() {
            return specified.clone();
        } else {
            let mut crates = Vec::new();
            for name in DEFAULT_LIB_CRATES {
                crates.push(name.to_string());
            }
            crates
        }
    }
}
