// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use bitflags::bitflags;
use core::convert::From;

use crate::mmio::{alloc_mmio32, alloc_mmio64};
use crate::{PciCommand, Result};

pub const PCI_CONFIGURATION_ADDRESS_PORT: u16 = 0xCF8;
pub const PCI_CONFIGURATION_DATA_PORT: u16 = 0xCFC;
const PCI_EX_BAR_BASE_ADDRESS: u64 = 0xE0000000u64;
const PCI_MEM32_BASE_ADDRESS_MASK: u32 = 0xFFFF_FFF0;
const PCI_MEM64_BASE_ADDRESS_MASK: u64 = 0xFFFF_FFFF_FFFF_FFF0;

pub fn pci_cf8_read32(bus: u8, device: u8, fnc: u8, reg: u8) -> u32 {
    let data = u32::from(bus) << 16;
    let data = data | u32::from(device) << 11;
    let data = data | u32::from(fnc) << 8;
    let data = data | u32::from(reg & 0xfc);
    let data = data | 1u32 << 31;

    #[cfg(feature = "iocall")]
    unsafe {
        x86::io::outl(PCI_CONFIGURATION_ADDRESS_PORT, data);
        x86::io::inl(PCI_CONFIGURATION_DATA_PORT)
    }

    #[cfg(feature = "tdcall")]
    {
        tdx_tdcall::tdx::tdvmcall_io_write_32(PCI_CONFIGURATION_ADDRESS_PORT, data);
        tdx_tdcall::tdx::tdvmcall_io_read_32(PCI_CONFIGURATION_DATA_PORT)
    }
}

pub fn pci_cf8_write32(bus: u8, device: u8, fnc: u8, reg: u8, value: u32) {
    let data = u32::from(bus) << 16;
    let data = data | u32::from(device) << 11;
    let data = data | u32::from(fnc) << 8;
    let data = data | u32::from(reg & 0xfc);
    let data = data | 1u32 << 31;

    #[cfg(feature = "iocall")]
    unsafe {
        x86::io::outl(PCI_CONFIGURATION_ADDRESS_PORT, data);
        x86::io::outl(PCI_CONFIGURATION_DATA_PORT, value);
    }
    #[cfg(feature = "tdcall")]
    {
        tdx_tdcall::tdx::tdvmcall_io_write_32(PCI_CONFIGURATION_ADDRESS_PORT, data);
        tdx_tdcall::tdx::tdvmcall_io_write_32(PCI_CONFIGURATION_DATA_PORT, value);
    }
}

pub fn pci_cf8_write8(bus: u8, device: u8, fnc: u8, reg: u8, value: u8) {
    let data = u32::from(bus) << 16;
    let data = data | u32::from(device) << 11;
    let data = data | u32::from(fnc) << 8;
    let data = data | u32::from(reg & 0xfc);
    let data = data | 1u32 << 31;

    #[cfg(feature = "iocall")]
    unsafe {
        x86::io::outl(PCI_CONFIGURATION_ADDRESS_PORT, data);
        x86::io::outb(PCI_CONFIGURATION_DATA_PORT + (data & 3) as u16, value);
    }

    #[cfg(feature = "tdcall")]
    {
        tdx_tdcall::tdx::tdvmcall_io_write_32(PCI_CONFIGURATION_ADDRESS_PORT, data);
        tdx_tdcall::tdx::tdvmcall_io_write_8(
            PCI_CONFIGURATION_DATA_PORT + (data & 3) as u16,
            value,
        );
    }
}

pub fn pci_cf8_read8(bus: u8, device: u8, fnc: u8, reg: u8) -> u8 {
    let data = u32::from(bus) << 16;
    let data = data | u32::from(device) << 11;
    let data = data | u32::from(fnc) << 8;
    let data = data | u32::from(reg & 0xfc);
    let data = data | 1u32 << 31;

    #[cfg(feature = "iocall")]
    unsafe {
        x86::io::outl(PCI_CONFIGURATION_ADDRESS_PORT, data);
        x86::io::inb(PCI_CONFIGURATION_DATA_PORT + (data & 3) as u16)
    }
    #[cfg(feature = "tdcall")]
    {
        tdx_tdcall::tdx::tdvmcall_io_write_32(PCI_CONFIGURATION_ADDRESS_PORT, data);
        tdx_tdcall::tdx::tdvmcall_io_read_8(PCI_CONFIGURATION_DATA_PORT + (data & 3) as u16)
    }
}

fn get_device_details(bus: u8, device: u8, func: u8) -> (u16, u16) {
    let config_data = ConfigSpacePciEx::read::<u32>(bus, device, func, 0);
    (
        (config_data & 0xffff) as u16,
        ((config_data & 0xffff0000) >> 0x10) as u16,
    )
}

pub fn find_device(vendor_id: u16, device_id: u16) -> Option<(u8, u8, u8)> {
    const MAX_DEVICES: u8 = 32;
    const INVALID_VENDOR_ID: u16 = 0xffff;

    for device in 0..MAX_DEVICES {
        if (vendor_id, device_id) == get_device_details(0, device, 0) {
            return Some((0, device, 0));
        }
        if vendor_id == INVALID_VENDOR_ID {
            continue;
        }
    }
    None
}

/// Configure Space Access Mechanism #1

/// 32-bit I/O locations  CONFIG_ADDRESS (0xCF8)
/// 0-7     register offset
/// 8-10    funtion number
/// 11-15   device number
/// 16-23   bus number
/// 24-30   reserved
/// 31      enable bit
pub type ConfigAddress = u32;

/// Configure Space
pub struct ConfigSpace;

impl ConfigSpace {
    pub fn read32(bus: u8, device: u8, func: u8, offset: u8) -> u32 {
        let config_address = Self::get_config_address(bus, device, func, offset);

        #[cfg(feature = "iocall")]
        unsafe {
            x86::io::outl(PCI_CONFIGURATION_ADDRESS_PORT, config_address);
            x86::io::inl(PCI_CONFIGURATION_DATA_PORT)
        }
        #[cfg(feature = "tdcall")]
        {
            tdx_tdcall::tdx::tdvmcall_io_write_32(PCI_CONFIGURATION_ADDRESS_PORT, config_address);
            tdx_tdcall::tdx::tdvmcall_io_read_32(PCI_CONFIGURATION_DATA_PORT)
        }
    }

    pub fn write32(bus: u8, device: u8, func: u8, offset: u8, config_data: u32) {
        let config_address = Self::get_config_address(bus, device, func, offset);

        #[cfg(feature = "iocall")]
        unsafe {
            x86::io::outl(PCI_CONFIGURATION_ADDRESS_PORT, config_address);
            x86::io::outl(PCI_CONFIGURATION_DATA_PORT, config_data);
        }

        #[cfg(feature = "tdcall")]
        {
            tdx_tdcall::tdx::tdvmcall_io_write_32(PCI_CONFIGURATION_ADDRESS_PORT, config_address);
            tdx_tdcall::tdx::tdvmcall_io_write_32(PCI_CONFIGURATION_DATA_PORT, config_data)
        }
    }

    pub fn read16(bus: u8, device: u8, func: u8, offset: u8) -> u16 {
        let config_data = ConfigSpace::read32(bus, device, func, offset & 0b1111_1100);
        ((config_data >> ((offset & 0b10) << 3)) & 0xFFFF) as u16
    }

    pub fn write16(bus: u8, device: u8, func: u8, offset: u8, config_data: u16) {
        let old_config_data = ConfigSpace::read32(bus, device, func, offset);
        let dest = (offset & 0b010) << 3; // 0 0x10
        let mask = 0xffffu32 << dest;
        let new_config_data = (config_data as u32) << dest | (old_config_data & !mask);
        ConfigSpace::write32(bus, device, func, offset, new_config_data)
    }

    pub fn read8(bus: u8, device: u8, func: u8, offset: u8) -> u8 {
        let config_data = ConfigSpace::read32(bus, device, func, offset & 0b1111_1100);
        ((config_data >> ((offset as usize & 0b11) << 3)) & 0xFF) as u8
    }

    pub fn write8(bus: u8, device: u8, func: u8, offset: u8, config_data: u8) {
        let old_config_data = ConfigSpace::read32(bus, device, func, offset);
        let dest = (offset & 0b011) << 3; // 0 0x8 0x10 0x18
        let mask = 0xffu32 << dest;
        let new_config_data = (config_data as u32) << dest | (old_config_data & !mask);
        ConfigSpace::write32(bus, device, func, offset, new_config_data)
    }

    /// Get vendor_id and device_id
    pub fn get_device_details(bus: u8, device: u8, func: u8) -> (u16, u16) {
        let config_data = ConfigSpacePciEx::read::<u32>(bus, device, func, 0);
        (
            (config_data & 0xffff) as u16,
            ((config_data & 0xffff0000) >> 0x10) as u16,
        )
    }

    fn get_config_address(bus: u8, device: u8, func: u8, offset: u8) -> ConfigAddress {
        let offset = offset & 0b1111_1100;
        let func = func & 0b0000_0111;
        let device = device & 0b0001_1111;

        (1 << 31)
            | ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((func as u32) << 8)
            | offset as u32
    }
}

pub struct ConfigSpacePciEx;
impl ConfigSpacePciEx {
    #[cfg(not(feature = "fuzz"))]
    pub fn read<T: Copy + Clone>(bus: u8, device: u8, func: u8, offset: u16) -> T {
        let addr = PCI_EX_BAR_BASE_ADDRESS
            + ((bus as u64) << 20)
            + ((device as u64) << 15)
            + ((func as u64) << 12)
            + offset as u64;

        #[cfg(feature = "iocall")]
        unsafe {
            core::ptr::read_volatile(addr as *const T)
        }
        #[cfg(feature = "tdcall")]
        tdx_tdcall::tdx::tdvmcall_mmio_read(addr as usize)
    }
    #[cfg(feature = "fuzz")]
    pub fn read<T: Copy + Clone>(_bus: u8, _device: u8, _func: u8, offset: u16) -> T {
        let base_address = crate::get_fuzz_seed_address();
        let address = base_address + offset as u64;
        unsafe { core::ptr::read_volatile(address as *const T) }
    }

    #[cfg(not(feature = "fuzz"))]
    pub fn write<T: Copy + Clone>(bus: u8, device: u8, func: u8, offset: u16, value: T) {
        let addr = PCI_EX_BAR_BASE_ADDRESS
            + ((bus as u64) << 20)
            + ((device as u64) << 15)
            + ((func as u64) << 12)
            + offset as u64;
        #[cfg(feature = "iocall")]
        unsafe {
            core::ptr::write_volatile(addr as *mut T, value)
        }
        #[cfg(feature = "tdcall")]
        tdx_tdcall::tdx::tdvmcall_mmio_write(addr as *mut T, value);
    }

    #[cfg(feature = "fuzz")]
    pub fn write<T: Copy + Clone>(_bus: u8, _device: u8, _func: u8, offset: u16, value: T) {
        unsafe {
            let base_address = crate::get_fuzz_seed_address();
            let address = base_address + offset as u64;
            core::ptr::write_volatile(address as *mut T, value)
        }
    }
}

/// CommonHeader to all PCI Header Type
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct PciDeviceCommonHeader {
    pub device_id: u16,
    pub vendor_id: u16,
    pub status: Status,
    pub command: Command,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision_id: u8,
    pub bist: u8,
    pub header_type: u8,
    pub latency_time: u8,
    pub cache_line_size: u8,
}

bitflags! {
    #[derive(Default)]
    pub struct HeaderType: u8 {
        const MF   = 0b10000000;
        const STANDARD = 0x0;
        const PCI2PCI_BRIDGE = 0x1;
        const PCI2CARDBUS_BRIDGE = 0x2;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct Status: u16 {
        const RESERVED_0                = 0x0001;
        const RESERVED_1                = 0x0002;
        const RESERVED_2                = 0x0004;
        const INTERRUPT_STATUS          = 0x0008;
        const CAPABILITIES_LIST         = 0x0010;
        const MHZ66_CAPABLE             = 0x0020;
        const RESERVED_6                = 0x0040;
        const FAST_BACK_TO_BACK_CAPABLE = 0x0080;
        const MASTER_DATA_PARITY_ERROR  = 0x0100;
        const DEVSEL_MEDIUM_TIMING      = 0x0200;
        const DEVSEL_SLOW_TIMING        = 0x0400;
        const SIGNALED_TARGET_ABORT     = 0x0800;
        const RECEIVED_TARGET_ABORT     = 0x1000;
        const RECEIVED_MASTER_ABORT     = 0x2000;
        const SIGNALED_SYSTEM_ERROR     = 0x4000;
        const DETECTED_PARITY_ERROR     = 0x8000;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct Command: u16 {
        const IO_SPACE                  = 0x0001;
        const MEMORY_SPACE              = 0x0002;
        const BUS_MASTER                = 0x0004;
        const SPECIAL_CYCLES            = 0x0008;
        const MWI_ENABLE                = 0x0010;
        const VGA_PALETTE_SNOOP         = 0x0020;
        const PARITY_ERROR_RESPONSE     = 0x0040;
        const STEPPING_CONTROL          = 0x0080;
        const SERR_ENABLE               = 0x0100;
        const FAST_BACK_TO_BACK_ENABLE  = 0x0200;
        const INTERRUPT_DISABLE         = 0x0400;
        const RESERVED_11               = 0x0800;
        const RESERVED_12               = 0x1000;
        const RESERVED_13               = 0x2000;
        const RESERVED_14               = 0x4000;
        const RESERVED_15               = 0x8000;
    }
}

#[derive(Default)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub func: u8,

    // Pci Device Header
    pub common_header: PciDeviceCommonHeader,
    pub bars: [PciBar; 6],
    pub cardbus_cis_pointer: u32,
    pub subsystem_id: u16,
    pub subsystem_vendor_id: u16,
    pub expansion_rom_base_address: u32,
    pub reserved1: u16,
    pub reserved2: u8,
    pub capabilities_pointer: u8,
    pub reserved3: u32,
    pub max_latency: u8,
    pub min_grant: u8,
    pub interrupt_pin: u8,
    pub interrup_line: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum PciBarType {
    Unused,
    MemorySpace32,
    MemorySpace64,
    IoSpace,
}

impl Default for PciBarType {
    fn default() -> Self {
        PciBarType::Unused
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Copy)]
pub struct PciBar {
    pub address: u64,
    pub bar_type: PciBarType,
}

impl PciDevice {
    pub fn new(bus: u8, device: u8, func: u8) -> PciDevice {
        PciDevice {
            bus,
            device,
            func,
            common_header: PciDeviceCommonHeader::default(),
            ..Default::default()
        }
    }

    pub fn init(&mut self) -> Result<()> {
        let (vendor_id, device_id) =
            ConfigSpace::get_device_details(self.bus, self.device, self.func);
        self.common_header.vendor_id = vendor_id;
        self.common_header.device_id = device_id;
        let command = self.read_u16(0x4);
        let status = self.read_u16(0x6);
        log::info!(
            "PCI Device: {}:{}.{} {:x}:{:x}\nbit  \t fedcba9876543210\nstate\t {:016b}\ncommand\t {:016b}\n",
            self.bus,
            self.device,
            self.func,
            self.common_header.vendor_id,
            self.common_header.device_id,
            status,
            command,
        );

        let mut current_bar_offset = 0x10;
        let mut current_bar = 0;

        //0x24 offset is last bar
        while current_bar_offset <= 0x24 {
            let bar = self.read_u32(current_bar_offset);

            // lsb is 1 for I/O space bars
            if bar & 1 == 1 {
                self.bars[current_bar].bar_type = PciBarType::IoSpace;
                self.bars[current_bar].address = u64::from(bar & 0xffff_fffc);
            } else {
                // bits 2-1 are the type 0 is 32-but, 2 is 64 bit
                match bar >> 1 & 3 {
                    0 => {
                        let size = self.get_bar_size(current_bar_offset);

                        let addr = if size > 0 {
                            let addr = alloc_mmio32(size)?;
                            self.set_bar_addr(current_bar_offset, addr);
                            addr
                        } else {
                            bar
                        };

                        self.bars[current_bar].bar_type = PciBarType::MemorySpace32;
                        self.bars[current_bar].address =
                            u64::from(addr & PCI_MEM32_BASE_ADDRESS_MASK);
                    }
                    2 => {
                        self.bars[current_bar].bar_type = PciBarType::MemorySpace64;

                        let mut size = self.get_bar_size(current_bar_offset) as u64;
                        if size == 0 {
                            size = (self.get_bar_size(current_bar_offset + 4) as u64) << 32;
                        }

                        let addr = if size > 0 {
                            let addr = alloc_mmio64(size)?;
                            self.set_bar_addr(current_bar_offset, addr as u32);
                            self.set_bar_addr(current_bar_offset + 4, (addr >> 32) as u32);
                            addr
                        } else {
                            bar as u64
                        };

                        self.bars[current_bar].address = addr & PCI_MEM64_BASE_ADDRESS_MASK;
                        current_bar_offset += 4;
                    }
                    _ => panic!("Unsupported BAR type"),
                }
            }

            current_bar += 1;
            current_bar_offset += 4;
        }

        // Enable the bits 0 (IO Space) and 1 (Memory Space) to activate the bar configuration
        self.write_u16(
            0x4,
            (PciCommand::IO_SPACE | PciCommand::MEMORY_SPACE | PciCommand::BUS_MASTER).bits(),
        );
        for bar in &self.bars {
            log::info!("Bar: type={:?} address={:x}\n", bar.bar_type, bar.address);
        }

        Ok(())
    }

    fn set_bar_addr(&self, offset: u8, addr: u32) {
        self.write_u32(offset, addr);
    }

    fn get_bar_size(&self, offset: u8) -> u32 {
        let restore = self.read_u32(offset);
        self.write_u32(offset, u32::MAX);
        let size = self.read_u32(offset);
        self.write_u32(offset, restore);

        if size == 0 {
            size
        } else {
            !(size & 0xFFFF_FFF0) + 1
        }
    }

    pub fn read_u64(&self, offset: u8) -> u64 {
        ConfigSpacePciEx::read::<u64>(self.bus, self.device, self.func, offset as u16)
        // let low = ConfigSpace::read32(self.bus, self.device, self.func, offset);
        // let high = ConfigSpace::read32(self.bus, self.device, self.func, offset + 8);
        // (low as u64) & ((high as u64) << 8)
    }

    pub fn read_u32(&self, offset: u8) -> u32 {
        ConfigSpacePciEx::read::<u32>(self.bus, self.device, self.func, offset as u16)
        // ConfigSpace::read32(self.bus, self.device, self.func, offset)
    }

    pub fn read_u16(&self, offset: u8) -> u16 {
        ConfigSpacePciEx::read::<u16>(self.bus, self.device, self.func, offset as u16)
        // ConfigSpace::read16(self.bus, self.device, self.func, offset)
    }

    pub fn read_u8(&self, offset: u8) -> u8 {
        ConfigSpacePciEx::read::<u8>(self.bus, self.device, self.func, offset as u16)
        // ConfigSpace::read8(self.bus, self.device, self.func, offset)
    }

    pub fn write_u32(&self, offset: u8, value: u32) {
        ConfigSpacePciEx::write::<u32>(self.bus, self.device, self.func, offset as u16, value)
        // ConfigSpace::write32(self.bus, self.device, self.func, offset, value)
    }

    pub fn write_u16(&self, offset: u8, value: u16) {
        ConfigSpacePciEx::write::<u16>(self.bus, self.device, self.func, offset as u16, value)
        // ConfigSpace::write16(self.bus, self.device, self.func, offset, value)
    }

    pub fn write_u8(&self, offset: u8, value: u8) {
        ConfigSpacePciEx::write::<u8>(self.bus, self.device, self.func, offset as u16, value)
        // ConfigSpace::write8(self.bus, self.device, self.func, offset, value)
    }
}
