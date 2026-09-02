// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::env;

const SERVTD_ATTR_ENV: &str = "MIGTD_SERVTD_ATTR";

fn parse_u64(value: &str) -> Result<u64, std::num::ParseIntError> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));
    u64::from_str_radix(digits, radix)
}

fn main() {
    println!("cargo:rustc-link-arg=-defsym=__ImageBase=0");
    println!("cargo:rerun-if-env-changed={SERVTD_ATTR_ENV}");

    let servtd_attr = env::var(SERVTD_ATTR_ENV)
        .map_or(Ok(0), |value| parse_u64(&value))
        .expect("MIGTD_SERVTD_ATTR must be a decimal or hexadecimal u64");
    println!("cargo:rustc-env=MIGTD_EXPECTED_SERVTD_ATTR={servtd_attr}");

    // `test_disable_ra_and_accept_all` is test-only.
    // The release fence is enforced in `src/lib.rs` via
    // `#[cfg(all(feature = ..., not(debug_assertions)))] compile_error!`.

    // Only add attestation library linking for AzCVMEmu if not in test mode
    #[cfg(all(feature = "AzCVMEmu", not(feature = "test_disable_ra_and_accept_all")))]
    {
        // SGX 2.30 initializes servtd heap anchors in .data.rel.ro at runtime.
        // Keep them writable in the hosted emulator, as upstream servtd tests do.
        println!("cargo:rustc-link-arg=-Wl,-z,norelro");
        println!("cargo:rustc-link-arg=-lservtd_attest_app");
        println!("cargo:rustc-link-arg=-lcrypto");
    }
}
