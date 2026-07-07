// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use lazy_static::lazy_static;
use spin::Mutex;
use td_payload::mm::MEMORY_MAP;

use crate::{PciError, Result, MMIO32_SIZE, MMIO32_START, MMIO64_SIZE, MMIO64_START};

lazy_static! {
    static ref MMIO32: Mutex<u32> = Mutex::new(0);
    static ref MMIO64: Mutex<u64> = Mutex::new(0);
}

#[cfg(feature = "fuzz")]
lazy_static! {
    static ref MMIO_OFFSET: Mutex<u64> = Mutex::new(0);
}

pub fn init_mmio() {
    let memory_map = MEMORY_MAP.lock();

    // Iterate through each region in the memory map and check if it overlaps with the MMIO32 or MMIO64 space.
    // If an overlap is detected, panic with an error message indicating an invalid MMIO configuration.
    // This ensures that the MMIO space does not conflict with the RAM space.
    for region in memory_map.iter() {
        let region_end = region.addr.saturating_add(region.size);
        let mmio32_end = (MMIO32_START as u64).saturating_add(MMIO32_SIZE as u64);
        let mmio64_end = MMIO64_START.saturating_add(MMIO64_SIZE);

        if (region.addr < mmio32_end && region_end > MMIO32_START as u64)
            || (region.addr < mmio64_end && region_end > MMIO64_START)
        {
            panic!("Invalid MMIO configuration: MMIO space overlaps with the RAM space.");
        }
    }

    *MMIO32.lock() = MMIO32_START;
    *MMIO64.lock() = MMIO64_START;
}

/// Device MMIO is never allowed to live below 1 MiB. That range is reserved
/// for legacy low memory and is not a valid MMIO aperture.
pub const MMIO_LOW_LIMIT: u64 = 0x10_0000;

/// Returns `true` if `[base, base + length)` hits RAM or the low 1 MiB.
/// Defense in depth for host-controlled BARs.
pub fn region_overlaps_private_dram(base: u64, length: u64) -> bool {
    let end = match base.checked_add(length) {
        Some(end) => end,
        None => return true,
    };

    if base < MMIO_LOW_LIMIT {
        return true;
    }

    let memory_map = MEMORY_MAP.lock();
    for region in memory_map.iter() {
        let region_end = match region.addr.checked_add(region.size) {
            Some(region_end) => region_end,
            None => return true,
        };

        // Overlap test for the half-open intervals [base, end) and
        // [region.addr, region_end).
        if base < region_end && end > region.addr {
            return true;
        }
    }

    false
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
    use crate::MMIO32_SIZE;

    let cur = *MMIO32.lock();
    let addr = align_up(cur as u64, size as u64).ok_or(PciError::InvalidParameter)?;

    if size > MMIO32_SIZE || addr > (MMIO32_START + MMIO32_SIZE - size) as u64 {
        return Err(PciError::MmioOutofResource);
    }

    *MMIO32.lock() = (addr as u32)
        .checked_add(size)
        .ok_or(PciError::InvalidParameter)?;
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

    if size > MMIO64_SIZE || addr > MMIO64_START + MMIO64_SIZE - size {
        return Err(PciError::MmioOutofResource);
    }

    *MMIO64.lock() = addr.checked_add(size).ok_or(PciError::InvalidParameter)?;
    Ok(addr)
}

fn align_up(addr: u64, align: u64) -> Option<u64> {
    if align == 0 {
        return None;
    }
    Some((addr.checked_add(align)? - 1) & !(align - 1))
}
