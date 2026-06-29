// Copyright (c) 2022 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

const PAGE_SIZE: usize = 0x1000;

/// Records the exact byte size allocated for each shared-page address so that
/// `free_shared_pages` deallocates with the original `Layout` rather than one
/// reconstructed from a caller-supplied page count (a mismatch would cause
/// allocator UB).
static SHARED_ALLOC_SIZES: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

pub struct SharedMemory {
    buf: Vec<u8>,
    shadow: Vec<u8>,
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
            shadow: Vec::new(),
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
        // Copy into a separate shadow buffer so the returned slice is an immutable
        // snapshot, matching the real td-payload shared->private memcpy semantics.
        self.shadow.clear();
        self.shadow.extend_from_slice(&self.buf);
        Some(&self.shadow)
    }
}

/// Allocate shared pages in emulation mode using heap allocation
/// # Safety
/// The caller needs to explicitly call the `free_shared_pages` function after use
pub unsafe fn alloc_shared_pages(num: usize) -> Option<usize> {
    let size = PAGE_SIZE.checked_mul(num)?;
    let buf = Vec::from_iter(core::iter::repeat(0u8).take(size)).into_boxed_slice();
    let ptr = Box::into_raw(buf) as *mut u8;
    let addr = ptr as usize;
    SHARED_ALLOC_SIZES.lock().insert(addr, size);
    Some(addr)
}

/// Allocate a single shared page in emulation mode
/// # Safety
/// The caller needs to explicitly call the `free_shared_page` function after use
pub unsafe fn alloc_shared_page() -> Option<usize> {
    alloc_shared_pages(1)
}

/// Free shared pages allocated in emulation mode
/// # Safety
/// The caller needs to ensure the correctness of the addr. The dealloc size is
/// taken from the size recorded at allocation time, so it always matches the
/// original `Layout`; `num` is used only as a consistency check.
pub unsafe fn free_shared_pages(addr: usize, num: usize) {
    // An unknown address means a double-free or a free of an unowned pointer:
    // fail fast rather than silently masking allocator misuse.
    let size = SHARED_ALLOC_SIZES
        .lock()
        .remove(&addr)
        .unwrap_or_else(|| panic!("free_shared_pages: unknown addr {:#x}", addr));
    // `size` is always a multiple of PAGE_SIZE, so this division is exact and
    // cannot overflow. A mismatch means the caller passed a wrong page count.
    assert_eq!(
        num,
        size / PAGE_SIZE,
        "free_shared_pages: page count mismatch for {:#x}",
        addr
    );
    let ptr = addr as *mut u8;
    let _ = Box::from_raw(core::slice::from_raw_parts_mut(ptr, size));
}

/// Free a single shared page allocated in emulation mode
/// # Safety
/// The caller needs to ensure the correctness of the addr
pub unsafe fn free_shared_page(addr: usize) {
    free_shared_pages(addr, 1)
}
