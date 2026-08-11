// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

fn main() {
    println!("cargo:rustc-link-arg=-defsym=__ImageBase=0");

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
