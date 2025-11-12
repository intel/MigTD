// Copyright (c) 2022 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::boxed::Box;
use alloc::vec::Vec;

const PAGE_SIZE: usize = 0x1000;

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

/// Allocate shared pages in emulation mode using heap allocation
/// # Safety
/// The caller needs to explicitly call the `free_shared_pages` function after use
pub unsafe fn alloc_shared_pages(num: usize) -> Option<usize> {
    let size = PAGE_SIZE.checked_mul(num)?;
    let buf = Vec::from_iter(core::iter::repeat(0u8).take(size)).into_boxed_slice();
    let ptr = Box::into_raw(buf) as *mut u8;
    Some(ptr as usize)
}

/// Allocate a single shared page in emulation mode
/// # Safety
/// The caller needs to explicitly call the `free_shared_page` function after use
pub unsafe fn alloc_shared_page() -> Option<usize> {
    alloc_shared_pages(1)
}

/// Free shared pages allocated in emulation mode
/// # Safety
/// The caller needs to ensure the correctness of the addr and page num
pub unsafe fn free_shared_pages(addr: usize, num: usize) {
    let size = PAGE_SIZE.checked_mul(num).expect("Invalid page num");
    let ptr = addr as *mut u8;
    let _ = Box::from_raw(core::slice::from_raw_parts_mut(ptr, size));
}

/// Free a single shared page allocated in emulation mode
/// # Safety
/// The caller needs to ensure the correctness of the addr
pub unsafe fn free_shared_page(addr: usize) {
    free_shared_pages(addr, 1)
}
