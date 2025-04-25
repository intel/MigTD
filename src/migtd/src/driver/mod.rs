// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "virtio-serial")]
pub mod serial;
pub mod ticks;
pub mod timer;
#[cfg(feature = "vmcall-raw")]
pub mod vmcall_raw;
#[cfg(any(feature = "virtio-vsock", feature = "vmcall-vsock"))]
pub mod vsock;
