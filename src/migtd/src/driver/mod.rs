// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod timer;
#[cfg(any(feature = "virtio-vsock", feature = "vmcall-vsock"))]
pub mod vsock;
