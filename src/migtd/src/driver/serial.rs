// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::boxed::Box;
use core::sync::atomic::AtomicBool;
use pci::PCI_EX_BAR_BASE_ADDRESS;
use td_payload::mm::shared::{alloc_shared_pages, free_shared_pages};
use virtio_serial::*;

use crate::driver::timer;

pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
pub const VIRTIO_PCI_DEVICE_ID: u16 = 0x1043;

pub static TIMEOUT: AtomicBool = AtomicBool::new(false);

// Implement a DMA allocator for vsock device
struct Allocator;

impl DmaPageAllocator for Allocator {
    fn alloc_pages(&self, page_num: usize) -> Option<u64> {
        unsafe { alloc_shared_pages(page_num).map(|addr| addr as u64) }
    }

    fn free_pages(&self, addr: u64, page_num: usize) {
        unsafe { free_shared_pages(addr as usize, page_num) }
    }
}

struct SerailTimer;

impl Timer for SerailTimer {
    fn is_timeout(&self) -> bool {
        timer::timeout()
    }

    fn reset_timeout(&self) {
        timer::reset_timer()
    }

    fn set_timeout(&self, timeout: u64) -> Option<u64> {
        timer::schedule_timeout(timeout)?;

        // enable the interrupt to accept the timeout event
        x86_64::instructions::interrupts::enable();

        Some(timeout)
    }
}

#[cfg(feature = "virtio-serial")]
pub fn virtio_serial_device_init() {
    pci_ex_bar_initialization();

    // Initialize MMIO space
    pci::init_mmio();

    // Enumerate the virtio device
    let (_b, dev, _f) = pci::find_device(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_ID).unwrap();

    let pci_device = pci::PciDevice::new(0, dev, 0);

    // Create the transport layer of virtio with the PCI device instance
    let virtio_transport = virtio::virtio_pci::VirtioPciTransport::new(pci_device);

    let serial = VirtioSerial::new(
        Box::new(virtio_transport),
        Box::new(Allocator {}),
        Box::new(SerailTimer {}),
    )
    .expect("Failed to create vsock transport layer");

    virtio_serial::register_serial_device(serial).expect("Failed to register serial device");
}

pub fn pci_ex_bar_initialization() {
    // PcdPciExpressBaseAddress TBD
    let pci_exbar_base = PCI_EX_BAR_BASE_ADDRESS;

    //
    // Clear the PCIEXBAREN bit first, before programming the high register.
    //
    pci::pci_cf8_write32(0, 0, 0, 0x60, 0);

    //
    // Program the high register. Then program the low register, setting the
    // MMCONFIG area size and enabling decoding at once.
    //
    log::info!("pci_exbar_base {:x}\n", pci_exbar_base);
    log::info!(
        "pci_exbar_base {:x}, {:x}\n",
        (pci_exbar_base >> 32) as u32,
        (pci_exbar_base << 32 >> 32 | 0x1) as u32
    );
    pci::pci_cf8_write32(0, 0, 0, 0x64, (pci_exbar_base >> 32) as u32);
    pci::pci_cf8_write32(0, 0, 0, 0x60, (pci_exbar_base << 32 >> 32 | 0x1) as u32);
}
