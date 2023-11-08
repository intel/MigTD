// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use conquer_once::spin::OnceCell;
pub use shared_alloc::{init, virtio_shared_alloc, virtio_shared_dealloc};

pub use pci::{get_fuzz_seed_address, PciDevice, COMMON_HEADER};
pub use virtio::{virtio_pci::VirtioPciTransport, virtqueue::VirtQueue, VirtioTransport};

pub const VIRTIO_SUBSYSTEM_VSOCK: u32 = 19;
pub const PTR_OFFSET: u64 = 0x10000;
pub const PAGE_SIZE: usize = 0x1000;
pub const BARU64_1_OFFSET: u64 = 0x10;
pub const BARU64_2_OFFSET: u64 = 0x18;
pub const BARU64_3_OFFSET: u64 = 0x20;

pub const VEC_CAPACITY: usize = 0x10000_0000;
pub const TD_PAYLOAD_SHARED_MEMORY_SIZE: usize = 0x100_0000;
pub const PTR_ALIGN_VAR: u64 = 0xffff_ffff_ffff_0000;

pub const DATA_LEN: usize = 0x100_0000;

mod shared_alloc {

    use bitmap_allocator::{BitAlloc, BitAlloc4K};
    use spin::Mutex;

    static SHARED_MEMORY_ALLOCATOR: Mutex<SharedAlloc> = Mutex::new(SharedAlloc::empty());

    pub fn init(dma_base: usize, dma_size: usize) {
        println!("init dma - {:#x} - {:#x}\n", dma_base, dma_base + dma_size);
        init_dma(dma_base, dma_size);
    }

    fn init_dma(dma_base: usize, dma_size: usize) {
        // set page table flags TBD:
        *SHARED_MEMORY_ALLOCATOR.lock() = SharedAlloc::new(dma_base as usize, dma_size);
    }

    #[no_mangle]
    pub extern "C" fn virtio_shared_alloc(blocks: usize) -> PhysAddr {
        let paddr = unsafe { SHARED_MEMORY_ALLOCATOR.lock().alloc_contiguous(blocks, 0) }.unwrap_or(0);
        paddr
    }

    #[no_mangle]
    pub extern "C" fn virtio_shared_dealloc(paddr: PhysAddr, blocks: usize) -> i32 {
        let _ = unsafe { SHARED_MEMORY_ALLOCATOR.lock().dealloc_contiguous(paddr, blocks) };
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

    struct SharedAlloc {
        base: usize,
        inner: BitAlloc4K,
    }

    const BLOCK_SIZE: usize = 4096;

    impl Default for SharedAlloc {
        fn default() -> Self {
            Self {
                base: 0,
                inner: BitAlloc4K::DEFAULT,
            }
        }
    }

    impl SharedAlloc {
        pub fn new(base: usize, length: usize) -> Self {
            let mut inner = BitAlloc4K::DEFAULT;
            let blocks = length / BLOCK_SIZE;
            assert!(blocks <= BitAlloc4K::CAP);
            inner.insert(0..blocks);
            SharedAlloc { base, inner }
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
