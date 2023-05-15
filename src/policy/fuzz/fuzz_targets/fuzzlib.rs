// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use serde_json;
use policy::MigPolicy;

pub fn fuzz_policy(data: &[u8]) {
    let _ = serde_json::from_slice::<MigPolicy>(data);
}
