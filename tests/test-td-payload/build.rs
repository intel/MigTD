// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

fn main() {
    println!("cargo:rustc-link-arg=-defsym=__ImageBase=0");
}
