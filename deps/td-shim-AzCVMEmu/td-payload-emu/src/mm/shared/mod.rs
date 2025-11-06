// Copyright (c) 2022 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;

pub struct SharedMemory {
    buf: Vec<u8>,
}

impl SharedMemory {
    pub fn new(pages: usize) -> Option<Self> {
        if pages == 0 {
            return None;
        }
        // 4KiB pages typical in TDX environment
        let size = pages.checked_mul(4096)?;
        Some(Self {
            buf: Vec::from_iter(core::iter::repeat(0u8).take(size)),
        })
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    // Add missing methods for API compatibility with real td-payload
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn copy_to_private_shadow(&mut self) -> Option<&[u8]> {
        // In emulation mode, just return the buffer directly since we're not dealing with
        // actual shared/private memory conversion like in real TDX
        Some(&self.buf)
    }
}
