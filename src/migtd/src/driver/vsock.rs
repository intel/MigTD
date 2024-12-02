// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "virtio-vsock")]
use vsock::VsockDmaPageAllocator;

pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
pub const VIRTIO_PCI_DEVICE_ID: u16 = 0x1053;

// Implement a DMA allocator for vsock device
#[cfg(feature = "virtio-vsock")]
struct Allocator;

#[cfg(feature = "virtio-vsock")]
impl VsockDmaPageAllocator for Allocator {
    fn alloc_pages(&self, page_num: usize) -> Option<u64> {
        unsafe { td_payload::mm::shared::alloc_shared_pages(page_num).map(|addr| addr as u64) }
    }

    fn free_pages(&self, addr: u64, page_num: usize) {
        unsafe { td_payload::mm::shared::free_shared_pages(addr as usize, page_num) }
    }
}

#[cfg(feature = "vmcall-vsock")]
pub fn vmcall_vsock_device_init() {
    // Initialize the vsock transport
    vsock::transport::vsock_transport_init();
}

#[cfg(feature = "virtio-vsock")]
pub fn virtio_vsock_device_init(end_of_ram: u64) {
    use alloc::boxed::Box;

    pci_ex_bar_initialization();

    // Initialize MMIO space
    pci::init_mmio(end_of_ram);

    // Enumerate the virtio device
    let (_b, dev, _f) = pci::find_device(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_ID).unwrap();

    let pci_device = pci::PciDevice::new(0, dev, 0);

    // Create the transport layer of virtio with the PCI device instance
    let virtio_transport = virtio::virtio_pci::VirtioPciTransport::new(pci_device);

    // Initialize the vsock transport
    vsock::transport::vsock_transport_init(Box::new(virtio_transport), Box::new(Allocator {}))
        .expect("Failed to initialize vsock device");
}

#[cfg(feature = "virtio-vsock")]
pub fn pci_ex_bar_initialization() {
    const PCI_EX_BAR_BASE_ADDRESS: u64 = 0xE0000000u64;

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
