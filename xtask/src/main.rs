// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod build;
mod config;
mod library;
mod servtd_info_hash;

use clap::{Parser, Subcommand};

pub(crate) fn parse_u64(value: &str) -> Result<u64, String> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));
    u64::from_str_radix(digits, radix).map_err(|error| error.to_string())
}

#[derive(Parser)]
struct Program {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Image(build::BuildArgs),
    Hash(servtd_info_hash::ServtdInfoHashArgs),
    LibTest(library::LibraryCrates),
    LibBuild(library::LibraryCrates),
}

fn main() {
    match Program::parse().command {
        Commands::Image(args) => {
            let bin = args.build().expect("Fail to build migtd binary");
            println!("Successfully generate MigTD binary: {}", bin.display());
        }
        Commands::Hash(args) => {
            args.generate().expect("Fail to calculate tdinfo hash");
        }
        Commands::LibTest(args) => args.test().expect("Library crates test failed"),
        Commands::LibBuild(args) => args.build().expect("Library crates build failed"),
    };
}

#[cfg(test)]
mod test {
    use super::parse_u64;

    #[test]
    fn test_parse_u64() {
        assert_eq!(parse_u64("1").unwrap(), 1);
        assert_eq!(parse_u64("0x100000000").unwrap(), 0x1_0000_0000);
        assert!(parse_u64("invalid").is_err());
    }
}
