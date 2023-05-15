// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use lazy_static::lazy_static;
use spin::Mutex;

use crate::{PciError, Result};

pub const MMIO32_START: u32 = 0xC000_0000;
pub const MMIO32_SIZE: u32 = 0x2000_0000;

lazy_static! {
    static ref MMIO32: Mutex<u32> = Mutex::new(0);
    static ref MMIO64: Mutex<u64> = Mutex::new(0);
}

pub fn init_mmio(end_of_ram: u64) {
    *MMIO32.lock() = MMIO32_START;

    let mmio64_start = if end_of_ram > u32::MAX as u64 {
        end_of_ram
    } else {
        u32::MAX as u64 + 1
    };

    *MMIO64.lock() = mmio64_start;
}

#[cfg(feature = "fuzz")]
pub fn alloc_mmio32(size: u32) -> Result<u32> {
    let addr = crate::get_fuzz_seed_address() + 0x10c;
    Ok(addr as u32)
}

#[cfg(not(feature = "fuzz"))]
pub fn alloc_mmio32(size: u32) -> Result<u32> {
    let addr = *MMIO32.lock();
    let addr = align_up(addr as usize, size as usize);

    if size > MMIO32_SIZE || addr > (MMIO32_START + MMIO32_SIZE - size) as usize {
        return Err(PciError::MmioOutofResource);
    }

    *MMIO32.lock() = addr as u32 + size;
    Ok(addr as u32)
}

#[cfg(feature = "fuzz")]
pub fn alloc_mmio64(size: u64) -> Result<u64> {
    let addr = crate::get_fuzz_seed_address() + 0x10c;
    Ok(addr)
}

#[cfg(not(feature = "fuzz"))]
pub fn alloc_mmio64(size: u64) -> Result<u64> {
    let addr = *MMIO64.lock();
    addr.checked_add(size).ok_or(PciError::InvalidParameter)?;

    let addr = align_up(addr as usize, size as usize) as u64;
    *MMIO64.lock() = addr + size;
    Ok(addr)
}

fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}
