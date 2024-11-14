// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use td_payload::arch::idt::register;

#[cfg(not(feature = "fuzz"))]
pub fn register_callback(vector: u8, cb: unsafe extern "C" fn()) {
    register(vector, cb);
}
#[cfg(feature = "fuzz")]
pub fn register_callback(vector: u8, cb: unsafe extern "C" fn()) {}
