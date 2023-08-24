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

#[cfg(feature = "fuzz")]
lazy_static! {
    static ref MMIO_OFFSET: Mutex<u64> = Mutex::new(0);
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
    let cur = *MMIO_OFFSET.lock();
    let addr = align_up(cur, size as u64).ok_or(PciError::InvalidParameter)?;

    let addr = u32::try_from(addr).map_err(|_| PciError::InvalidParameter)?;

    *MMIO_OFFSET.lock() = addr.checked_add(size).ok_or(PciError::InvalidParameter)? as u64;
    Ok(addr)
}

#[cfg(not(feature = "fuzz"))]
pub fn alloc_mmio32(size: u32) -> Result<u32> {
    let cur = *MMIO32.lock();
    let addr = align_up(cur as u64, size as u64).ok_or(PciError::InvalidParameter)?;

    if size > MMIO32_SIZE || addr > (MMIO32_START + MMIO32_SIZE - size) as u64 {
        return Err(PciError::MmioOutofResource);
    }

    *MMIO32.lock() = addr as u32 + size;
    Ok(addr as u32)
}

#[cfg(feature = "fuzz")]
pub fn alloc_mmio64(size: u64) -> Result<u64> {
    let cur: u64 = *MMIO_OFFSET.lock();
    let addr = align_up(cur, size).ok_or(PciError::InvalidParameter)?;

    *MMIO_OFFSET.lock() = addr.checked_add(size).ok_or(PciError::InvalidParameter)?;
    Ok(addr)
}

#[cfg(not(feature = "fuzz"))]
pub fn alloc_mmio64(size: u64) -> Result<u64> {
    let cur = *MMIO64.lock();
    let addr = align_up(cur, size).ok_or(PciError::InvalidParameter)? as u64;

    *MMIO64.lock() = addr.checked_add(size).ok_or(PciError::InvalidParameter)?;
    Ok(addr)
}

fn align_up(addr: u64, align: u64) -> Option<u64> {
    if align == 0 {
        return None;
    }
    Some((addr.checked_add(align)? - 1) & !(align - 1))
}
