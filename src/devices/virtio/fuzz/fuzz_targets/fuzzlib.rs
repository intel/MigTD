// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::fuzzlib::dma_alloc::virtio_dma_alloc;
use conquer_once::spin::OnceCell;
pub use dma_alloc::init;

pub use pci::{get_fuzz_seed_address, PciDevice, COMMON_HEADER};
pub use virtio::{
    virtio_pci::VirtioPciTransport,
    virtqueue::{VirtqueueBuf, VirtQueue, VirtQueueLayout},
    VirtioTransport,
};

pub const VIRTIO_SUBSYSTEM_VSOCK: u32 = 19;
pub const PTR_OFFSET: u64 = 0x10000;
pub const PAGE_SIZE: usize = 0x1000;
pub const BARU64_1_OFFSET: u64 = 0x10;
pub const BARU64_2_OFFSET: u64 = 0x18;
pub const BARU64_3_OFFSET: u64 = 0x20;

pub const VEC_CAPACITY: usize = 0x10000_0000;
pub const TD_PAYLOAD_DMA_SIZE: usize = 0x100_0000;
pub const PTR_ALIGN_VAR: u64 = 0xffff_ffff_ffff_0000;

pub const DATA_LEN: usize = 0x100_0000;
pub const QUEUE_SIZE: usize = 16;

pub fn fuzz_virtio(pddr: u64) {
    let pcidevice = PciDevice::new(0, 1, 0);
    let mut transport = VirtioPciTransport::new(pcidevice);
    if transport.init(VIRTIO_SUBSYSTEM_VSOCK).is_ok() {
        transport.reset();
        transport.set_status(1);
        transport.add_status(64);
        transport.get_status();
        transport.set_features(0);
        transport.get_features();
        transport.set_queue(0);
        transport.set_queue_size(4);
        transport.set_queue_enable();
        // transport.notify_queue(0);
        transport.read_device_config(0);
        // tbd check pddr
        let queue = VirtQueue::new(&transport, 0, pddr as u64, 4);
        if let Ok(mut queue) = queue {
            let test_buffer1 = [1, 2, 3, 4];
            let test_buffer2 = [1, 2, 3, 4];
            let g2h = [VirtqueueBuf::new(
                test_buffer1.as_ptr() as u64,
                test_buffer1.len() as u32,
            )];
            let h2g = [VirtqueueBuf::new(
                test_buffer2.as_ptr() as u64,
                test_buffer2.len() as u32,
            )];
            let _ = queue.add(&g2h, &h2g);
            unsafe {
                std::ptr::write_volatile((pddr + PAGE_SIZE as u64 + 2) as *mut u16, 1);
            }
            let mut g2h = Vec::new();
            let mut h2g = Vec::new();
            let _ = queue.pop_used(&mut g2h, &mut h2g);
        }
    }
}

mod dma_alloc {

    use bitmap_allocator::{BitAlloc, BitAlloc4K};
    use spin::Mutex;

    static DMA_ALLOCATOR: Mutex<DmaAlloc> = Mutex::new(DmaAlloc::empty());

    pub fn init(dma_base: usize, dma_size: usize) {
        println!("init dma - {:#x} - {:#x}\n", dma_base, dma_base + dma_size);
        init_dma(dma_base, dma_size);
    }

    fn init_dma(dma_base: usize, dma_size: usize) {
        // set page table flags TBD:
        *DMA_ALLOCATOR.lock() = DmaAlloc::new(dma_base as usize, dma_size);
    }

    #[no_mangle]
    pub extern "C" fn virtio_dma_alloc(blocks: usize) -> PhysAddr {
        let paddr = unsafe { DMA_ALLOCATOR.lock().alloc_contiguous(blocks, 0) }.unwrap_or(0);
        paddr
    }

    #[no_mangle]
    pub extern "C" fn virtio_dma_dealloc(paddr: PhysAddr, blocks: usize) -> i32 {
        let _ = unsafe { DMA_ALLOCATOR.lock().dealloc_contiguous(paddr, blocks) };
        0
    }

    #[no_mangle]
    pub extern "C" fn virtio_phys_to_virt(paddr: PhysAddr) -> VirtAddr {
        paddr
    }

    #[no_mangle]
    pub extern "C" fn virtio_virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
        vaddr
    }

    type VirtAddr = usize;
    type PhysAddr = usize;

    struct DmaAlloc {
        base: usize,
        inner: BitAlloc4K,
    }

    const BLOCK_SIZE: usize = 4096;

    impl Default for DmaAlloc {
        fn default() -> Self {
            Self {
                base: 0,
                inner: BitAlloc4K::DEFAULT,
            }
        }
    }

    impl DmaAlloc {
        pub fn new(base: usize, length: usize) -> Self {
            let mut inner = BitAlloc4K::DEFAULT;
            let blocks = length / BLOCK_SIZE;
            assert!(blocks <= BitAlloc4K::CAP);
            inner.insert(0..blocks);
            DmaAlloc { base, inner }
        }

        const fn empty() -> Self {
            Self {
                base: 0,
                inner: BitAlloc4K::DEFAULT,
            }
        }

        /// # Safety
        ///
        /// This function is unsafe because manual deallocation is needed.
        #[allow(unused)]
        pub unsafe fn alloc(&mut self) -> Option<usize> {
            let ret = self.inner.alloc().map(|idx| idx * 4096 + self.base);
            println!("Alloc DMA block: {:x?}\n", ret);
            ret
        }

        /// # Safety
        ///
        /// This function is unsafe because manual deallocation is needed.
        pub unsafe fn alloc_contiguous(
            &mut self,
            block_count: usize,
            align_log2: usize,
        ) -> Option<usize> {
            let ret = self
                .inner
                .alloc_contiguous(block_count, align_log2)
                .map(|idx| idx * BLOCK_SIZE + self.base);
            println!(
                "Allocate {} DMA blocks with alignment {}: {:x?}\n",
                block_count,
                1 << align_log2,
                ret
            );
            ret
        }

        /// # Safety
        ///
        /// This function is unsafe because the DMA must have been allocated.
        #[allow(unused)]
        pub unsafe fn dealloc(&mut self, target: usize) {
            println!("Deallocate DMA block: {:x}\n", target);
            self.inner.dealloc((target - self.base) / BLOCK_SIZE)
        }

        /// # Safety
        ///
        /// This function is unsafe because the DMA must have been allocated.
        unsafe fn dealloc_contiguous(&mut self, target: usize, block_count: usize) {
            println!("Deallocate {} DMA blocks: {:x}\n", block_count, target);
            let start_idx = (target - self.base) / BLOCK_SIZE;
            for i in start_idx..start_idx + block_count {
                self.inner.dealloc(i)
            }
        }
    }
}
