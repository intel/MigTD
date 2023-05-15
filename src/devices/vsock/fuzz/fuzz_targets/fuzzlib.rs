// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use conquer_once::spin::OnceCell;
pub use dma_alloc::{dma_init, DMA_ALLOCATOR};

pub use pci::{get_fuzz_seed_address, PciDevice, COMMON_HEADER};
pub use virtio::{virtio_pci::VirtioPciTransport, virtqueue::VirtQueue, VirtioTransport};

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

mod dma_alloc {

    use bitmap_allocator::{BitAlloc, BitAlloc4K};
    use spin::{once::Once, Mutex};
    const PAGE_SIZE: usize = 0x1000;

    pub static DMA_ALLOCATOR: Mutex<Once<DmaAllocator>> = Mutex::new(Once::new());

    pub fn dma_init(base: u64, size: usize, share_bit: u64) -> Option<u64> {
        let allocator = DmaAllocator::new(base, size, PAGE_SIZE, share_bit)?;
        DMA_ALLOCATOR.lock().call_once(|| allocator);
        Some(base)
    }

    pub struct DmaAllocator {
        allocator: PageAllocator,
        base: u64,
        size: usize,
        page_size: usize,
        share_bit: u64,
    }

    impl DmaAllocator {
        pub fn new(base: u64, size: usize, page_size: usize, share_bit: u64) -> Option<Self> {
            if page_size % PAGE_SIZE != 0 {
                return None;
            }
    
            let allocator = PageAllocator::new(base as usize, size, page_size)?;
    
            Some(DmaAllocator {
                allocator,
                base,
                size,
                page_size,
                share_bit,
            })
        }
    
        pub fn alloc_page(&mut self) -> Option<u64> {
            let page = self.allocator.alloc()? as u64;
            Some(page)
        }
    
        pub fn alloc_pages(&mut self, page_num: usize) -> Option<u64> {
            let page = self.allocator.alloc_contiguous(page_num)? as u64;
            Some(page)
        }
    
        pub fn free_page(&mut self, page_addr: u64) {
            self.allocator.dealloc(page_addr as usize);
        }
    
        pub fn free_pages(&mut self, page_addr: u64, page_num: usize) {
            self.allocator
                .dealloc_contiguous(page_addr as usize, page_num);
        }
    }

    pub struct PageAllocator {
        base: usize,
        block_size: usize,
        inner: BitAlloc4K,
    }

    impl PageAllocator {
        /// Caller needs to ensure:
        /// - base is page aligned
        /// - size is page aligned
        pub fn new(base: usize, length: usize, block_size: usize) -> Option<Self> {
            if base % block_size != 0 || length % block_size != 0 {
                return None;
            }
    
            let mut inner = BitAlloc4K::DEFAULT;
            let blocks = length / block_size;
            assert!(blocks <= BitAlloc4K::CAP);
            inner.insert(0..blocks);
            Some(Self {
                base,
                inner,
                block_size,
            })
        }
    
        pub fn alloc(&mut self) -> Option<usize> {
            self.inner.alloc().map(|idx| idx * 4096 + self.base)
        }
    
        pub fn alloc_contiguous(&mut self, block_num: usize) -> Option<usize> {
            let idx = self.inner.alloc_contiguous(block_num, 0)?;
            let ret = idx * self.block_size + self.base;
            Some(ret)
        }
    
        pub fn dealloc(&mut self, target: usize) {
            self.inner.dealloc((target - self.base) / self.block_size)
        }
    
        pub fn dealloc_contiguous(&mut self, target: usize, block_num: usize) {
            let start_idx = (target - self.base) / self.block_size;
            for i in start_idx..start_idx + block_num {
                self.inner.dealloc(i)
            }
        }
    }
    
}    
