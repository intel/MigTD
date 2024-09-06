// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crypto::x509;
use der::{Decode, Error};

pub fn fuzz_x509(data: &[u8]) -> core::result::Result<x509::Certificate, Error> {
    x509::Certificate::from_der(data)
}
