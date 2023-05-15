// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_main]
use libfuzzer_sys::fuzz_target;

mod fuzzlib;
use fuzzlib::fuzz_x509;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    fuzz_x509(data);
});
