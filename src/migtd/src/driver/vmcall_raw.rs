// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "vmcall-raw")]
pub fn vmcall_raw_device_init() {
    // Initialize the transport
    vmcall_raw::transport::vmcall_raw_transport_init().expect("Failed to initialize vmcall-raw");
}
