// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "virtio-serial")]
pub mod serial;
pub mod timer;
#[cfg(any(feature = "virtio-vsock", feature = "vmcall-vsock"))]
pub mod vsock;
