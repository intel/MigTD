// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(dead_code)]

use core::{fmt::Display, mem::size_of};

#[derive(Debug, Default, Clone, Copy)]
/// Provides a checked way to access memory offsets from a range of raw memory
pub struct MemoryRegion {
    base: u64,
    length: u64,
}

#[derive(Debug)]
pub struct MemoryRegionError {
    region: MemoryRegion,
    offset: u64,
}

impl Display for MemoryRegionError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "Memory region: {:#x} - {:x}, offset: {:#x}",
            self.region.base, self.region.length, self.offset
        )
    }
}

impl MemoryRegion {
    pub fn new(base: u64, length: u64) -> Option<MemoryRegion> {
        let _ = base.checked_add(length)?;

        Some(MemoryRegion { base, length })
    }

    /// Take a slice and turn it into a region of memory
    pub fn from_bytes(data: &[u8]) -> MemoryRegion {
        MemoryRegion {
            base: data.as_ptr() as u64,
            length: data.len() as u64,
        }
    }

    // Expose the entire region as a byte slice
    pub fn as_bytes(&mut self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.base as *const u8, self.length as usize) }
    }

    // Expose the entire region as a byte slice
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, self.length as usize) }
    }

    /// Expose a section of the memory region as a slice
    pub fn as_slice<T>(&mut self, offset: u64, length: u64) -> Result<&[T], MemoryRegionError> {
        if self.base.checked_add(offset).is_none()
            || offset
                .checked_add(length)
                .and_then(|end| if end > self.length { None } else { Some(end) })
                .is_none()
        {
            return Err(MemoryRegionError {
                region: *self,
                offset,
            });
        }

        Ok(unsafe {
            core::slice::from_raw_parts((self.base + offset) as *const T, length as usize)
        })
    }

    /// Expose a section of the memory region as a slice
    pub fn as_mut_slice<T>(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<&mut [T], MemoryRegionError> {
        if self.base.checked_add(offset).is_none()
            || offset
                .checked_add(length)
                .and_then(|end| if end > self.length { None } else { Some(end) })
                .is_none()
        {
            return Err(MemoryRegionError {
                region: *self,
                offset,
            });
        }

        Ok(unsafe {
            core::slice::from_raw_parts_mut((self.base + offset) as *mut T, length as usize)
        })
    }

    /// Read a value from a given offset
    fn read<T>(&self, offset: u64) -> Result<T, MemoryRegionError>
    where
        T: Copy,
    {
        if self.base.checked_add(offset).is_none()
            || offset
                .checked_add(size_of::<T>() as u64)
                .and_then(|end| if end > self.length { None } else { Some(end) })
                .is_none()
        {
            return Err(MemoryRegionError {
                region: *self,
                offset,
            });
        }

        Ok(unsafe { *((self.base + offset) as *const T) })
    }

    /// Read a single byte at a given offset
    pub fn read_u8(&self, offset: u64) -> Result<u8, MemoryRegionError> {
        self.read(offset)
    }

    /// Read a single word at a given offset
    pub fn read_u16(&self, offset: u64) -> Result<u16, MemoryRegionError> {
        self.read(offset)
    }

    /// Read a single dword at a given offset
    pub fn read_u32(&self, offset: u64) -> Result<u32, MemoryRegionError> {
        self.read(offset)
    }

    // Read a single qword at a given offset
    pub fn read_u64(&self, offset: u64) -> Result<u64, MemoryRegionError> {
        self.read(offset)
    }

    /// Write a value at the given offset
    pub fn write<T>(&mut self, offset: u64, value: T) -> Result<(), MemoryRegionError> {
        if self.base.checked_add(offset).is_none()
            || offset
                .checked_add(size_of::<T>() as u64)
                .and_then(|end| if end > self.length { None } else { Some(end) })
                .is_none()
        {
            return Err(MemoryRegionError {
                region: *self,
                offset,
            });
        }

        unsafe {
            *((self.base + offset) as *mut T) = value;
        }

        Ok(())
    }

    /// Write a single byte at given offset
    pub fn write_u8(&mut self, offset: u64, value: u8) -> Result<(), MemoryRegionError> {
        self.write(offset, value)
    }

    /// Write a single word at given offset
    pub fn write_u16(&mut self, offset: u64, value: u16) -> Result<(), MemoryRegionError> {
        self.write(offset, value)
    }

    /// Write a single dword at given offset
    pub fn write_u32(&mut self, offset: u64, value: u32) -> Result<(), MemoryRegionError> {
        self.write(offset, value)
    }

    /// Write a single qword at given offset
    pub fn write_u64(&mut self, offset: u64, value: u64) -> Result<(), MemoryRegionError> {
        self.write(offset, value)
    }

    #[cfg(feature = "fuzz")]
    fn mmio_read<T: Copy + Clone>(&self, offset: u64) -> Result<T, MemoryRegionError> {
        unsafe {
            Ok(core::ptr::read_volatile(
                (pci::get_fuzz_seed_address() + 0x10c + offset) as *const T,
            ))
        }
    }
    #[cfg(not(feature = "fuzz"))]
    /// Read a value at given offset with a mechanism suitable for MMIO
    fn mmio_read<T: Copy + Clone>(&self, offset: u64) -> Result<T, MemoryRegionError> {
        if self.base.checked_add(offset).is_none()
            || offset
                .checked_add(size_of::<T>() as u64)
                .and_then(|end| if end > self.length { None } else { Some(end) })
                .is_none()
        {
            return Err(MemoryRegionError {
                region: *self,
                offset,
            });
        }

        #[cfg(not(feature = "tdcall"))]
        unsafe {
            Ok(core::ptr::read_volatile((self.base + offset) as *const T))
        }
        #[cfg(feature = "tdcall")]
        {
            let addr = (self.base + offset) as usize;
            Ok(tdx_tdcall::tdx::tdvmcall_mmio_read(addr))
        }
    }

    /// Read a single byte at given offset with a mechanism suitable for MMIO
    pub fn mmio_read_u8(&self, offset: u64) -> Result<u8, MemoryRegionError> {
        self.mmio_read(offset)
    }

    /// Read a single word at given offset with a mechanism suitable for MMIO
    pub fn mmio_read_u16(&self, offset: u64) -> Result<u16, MemoryRegionError> {
        self.mmio_read(offset)
    }

    /// Read a single dword at given offset with a mechanism suitable for MMIO
    pub fn mmio_read_u32(&self, offset: u64) -> Result<u32, MemoryRegionError> {
        self.mmio_read(offset)
    }

    /// Read a single qword at given offset with a mechanism suitable for MMIO
    pub fn mmio_read_u64(&self, offset: u64) -> Result<u64, MemoryRegionError> {
        self.mmio_read(offset)
    }

    #[cfg(feature = "fuzz")]
    fn mmio_write<T>(&self, offset: u64, value: T) -> Result<(), MemoryRegionError> {
        unsafe {
            core::ptr::write_volatile(
                (pci::get_fuzz_seed_address() + 0x10c + offset) as *mut T,
                value,
            );
        }

        Ok(())
    }
    #[cfg(not(feature = "fuzz"))]
    /// Write a value at given offset using a mechanism suitable for MMIO
    fn mmio_write<T>(&self, offset: u64, value: T) -> Result<(), MemoryRegionError> {
        if self.base.checked_add(offset).is_none()
            || offset
                .checked_add(size_of::<T>() as u64)
                .and_then(|end| if end > self.length { None } else { Some(end) })
                .is_none()
        {
            return Err(MemoryRegionError {
                region: *self,
                offset,
            });
        }

        #[cfg(not(feature = "tdcall"))]
        unsafe {
            core::ptr::write_volatile((self.base + offset) as *mut T, value);
        }
        #[cfg(feature = "tdcall")]
        {
            let addr = (self.base + offset) as *mut T;
            tdx_tdcall::tdx::tdvmcall_mmio_write(addr, value)
        }

        Ok(())
    }

    /// Write a single byte at given offset with a mechanism suitable for MMIO
    pub fn mmio_write_u8(&self, offset: u64, value: u8) -> Result<(), MemoryRegionError> {
        self.mmio_write(offset, value)
    }

    /// Write a single word at given offset with a mechanism suitable for MMIO
    pub fn mmio_write_u16(&self, offset: u64, value: u16) -> Result<(), MemoryRegionError> {
        self.mmio_write(offset, value)
    }

    /// Write a single dword at given offset with a mechanism suitable for MMIO
    pub fn mmio_write_u32(&self, offset: u64, value: u32) -> Result<(), MemoryRegionError> {
        self.mmio_write(offset, value)
    }

    /// Write a single qword at given offset with a mechanism suitable for MMIO
    pub fn mmio_write_u64(&self, offset: u64, value: u64) -> Result<(), MemoryRegionError> {
        self.mmio_write(offset, value)
    }
}
