// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::env;
use std::process::Command;

fn main() {
    // Skip the compilation of attestation library when the remote attestation is not enabled or
    // running unit test.
    if cfg!(any(not(feature = "remote-attestation"), feature = "test")) {
        return;
    }

    // Always use release build of attestation library.
    // Cargo will set the "DEBUG" variable to "false" if the profile is release, but it will
    // affect the behavior of the make of attestation lib. Remove the "DEBUG" variable if its
    // value is "false".
    let _ = env::var("DEBUG").ok().map(|_| env::remove_var("DEBUG"));

    // Unset the CC and AR variable
    let _ = env::var("CC").ok().map(|_| env::remove_var("CC"));
    let _ = env::var("AR").ok().map(|_| env::remove_var("AR"));

    let crate_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib_path = crate_path.display().to_string();

    let search_dir = format!("{}", &lib_path);

    println!("cargo:rustc-link-search=native={}", search_dir);
    println!("cargo:rustc-link-lib=static=servtd_attest");
}
