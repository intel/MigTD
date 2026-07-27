// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use bitflags::bitflags;
use core::mem::size_of;
use core::slice;
use core::sync::atomic::{fence, Ordering};
use volatile::Volatile;

use crate::{Result, VirtioError, VirtioTransport, PAGE_SIZE};

const MAX_QUEUE_SIZE: usize = 32;

// The `in_use` / `is_head` bitmaps are `u32`, so they can only track 32 slots.
const _: () = assert!(
    MAX_QUEUE_SIZE <= 32,
    "in_use/is_head bitmaps are u32; widen them if MAX_QUEUE_SIZE grows"
);

#[derive(Debug)]
pub struct VirtqueueBuf {
    pub addr: u64,
    pub len: u32,
}

impl VirtqueueBuf {
    pub fn new(addr: u64, len: u32) -> Self {
        Self { addr, len }
    }
}

/// The mechanism for bulk data transport on virtio devices.
///
/// Each device can have zero or more virtqueues.
#[repr(C)]
pub struct VirtQueue {
    /// Descriptor table
    desc: &'static mut [Descriptor],
    /// Available ring
    avail: &'static mut AvailRing,
    /// Used ring
    used: &'static mut UsedRing,

    /// The index of queue
    queue_idx: u32,
    /// The size of queue
    queue_size: u16,
    /// The number of used queues.
    num_used: u16,
    /// The head desc index of the free list.
    free_head: u16,
    avail_idx: u16,
    last_used_idx: u16,
    /// Private, host-inaccessible copy of the descriptor metadata the driver
    /// programmed. The descriptor table lives in shared DMA that the host can
    /// overwrite at any time. Per the TDX Virtual Firmware security requirement
    /// ("if the data is in shared memory, copy it to private memory, then
    /// validate and use"), the driver must never trust values read back from
    /// the shared table. On recycle and free-list traversal it reads
    /// addr/len/flags/next from this private shadow instead, which neutralizes
    /// host forgery of desc.addr/len/next.
    desc_shadow: [DescriptorShadow; MAX_QUEUE_SIZE],
    /// Bitmap of outstanding descriptor slots.
    in_use: u32,
    /// Bitmap of slots that are the head of an outstanding chain.
    is_head: u32,
}

impl VirtQueue {
    /// Create a new VirtQueue.
    pub fn new(
        header: &dyn VirtioTransport,
        idx: usize,
        dma_addr: u64,
        queue_size: u16,
    ) -> Result<Self> {
        // TBD: add get_descriptors_address for VirtioTransport
        // if header.queue_used(idx as u32) {
        //     return Err(Error::AlreadyUsed);
        // }
        if !queue_size.is_power_of_two()
            || header.get_queue_max_size()? < queue_size
            || queue_size > MAX_QUEUE_SIZE as u16
        {
            return Err(VirtioError::InvalidParameter);
        }
        let layout = VirtQueueLayout::new(queue_size).ok_or(VirtioError::CreateVirtioQueue)?;

        // header.queue_set(idx as u32, size as u32, PAGE_SIZE as u32, dma.pfn());
        header.set_descriptors_address(dma_addr)?;
        header.set_avail_ring(dma_addr + layout.avail_offset as u64)?;
        header.set_used_ring(dma_addr + layout.used_offset as u64)?;

        let desc: &'static mut [Descriptor] =
            unsafe { slice::from_raw_parts_mut(dma_addr as *mut Descriptor, queue_size as usize) };
        let avail: &'static mut AvailRing =
            unsafe { &mut *((dma_addr as usize + layout.avail_offset) as *mut AvailRing) };
        let used: &'static mut UsedRing =
            unsafe { &mut *((dma_addr as usize + layout.used_offset) as *mut UsedRing) };

        // link descriptors together
        let mut desc_shadow = [DescriptorShadow::default(); MAX_QUEUE_SIZE];
        for i in 0..(queue_size - 1) {
            desc[i as usize].next.write(i + 1);
            desc_shadow[i as usize].next = i + 1;
        }

        Ok(VirtQueue {
            desc,
            avail,
            used,
            queue_size,
            queue_idx: idx as u32,
            num_used: 0,
            free_head: 0,
            avail_idx: 0,
            last_used_idx: 0,
            desc_shadow,
            in_use: 0,
            is_head: 0,
        })
    }

    /// Add DMA buffers to the virtqueue, return a token.
    pub fn add(&mut self, g2h: &[VirtqueueBuf], h2g: &[VirtqueueBuf]) -> Result<u16> {
        if g2h.is_empty() && h2g.is_empty() {
            return Err(VirtioError::InvalidParameter);
        }
        if g2h.len() + h2g.len() + self.num_used as usize > self.queue_size as usize {
            return Err(VirtioError::BufferTooSmall);
        }

        // allocate descriptors from free list
        let head = self.free_head;
        let mut last = self.free_head;

        for buf in g2h.iter() {
            last = self.add_descriptor(buf, DescFlags::NEXT)?;
        }

        for buf in h2g.iter() {
            last = self.add_descriptor(buf, DescFlags::NEXT | DescFlags::WRITE)?;
        }

        // Clear the 'NEXT' flag of the last added descriptor. Update the
        // private shadow first, then mirror it into the shared table.
        let last_idx = last as usize;
        let shadow = self
            .desc_shadow
            .get_mut(last_idx)
            .ok_or(VirtioError::InvalidDescriptorIndex)?;
        shadow.flags.remove(DescFlags::NEXT);
        let flags = shadow.flags;
        self.desc
            .get_mut(last_idx)
            .ok_or(VirtioError::InvalidDescriptorIndex)?
            .flags
            .write(flags);

        self.num_used += (g2h.len() + h2g.len()) as u16;

        // Record the chain head; only a head may later be completed.
        self.is_head |= 1u32 << head;

        let avail_slot = self.avail_idx & (self.queue_size - 1);
        self.avail
            .ring
            .get_mut(avail_slot as usize)
            .ok_or(VirtioError::InvalidDescriptorIndex)?
            .write(head);

        // write barrier
        fence(Ordering::SeqCst);

        // increase head of avail ring
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.avail.idx.write(self.avail_idx);
        self.avail.used_event.write(self.avail_idx);

        Ok(head)
    }

    /// Whether there is a used element that can pop.
    pub fn can_pop(&self) -> bool {
        self.last_used_idx != self.used.idx.read()
    }

    /// The number of free descriptors.
    pub fn available_desc(&self) -> usize {
        (self.queue_size - self.num_used) as usize
    }

    fn add_descriptor(&mut self, buf: &VirtqueueBuf, flag: DescFlags) -> Result<u16> {
        let index = self.free_head as usize;
        let desc = self
            .desc
            .get_mut(index)
            .ok_or(VirtioError::InvalidDescriptorIndex)?;
        desc.set_buf(buf);
        desc.flags.write(flag);

        // Mirror the values the driver just programmed into the private shadow.
        // The free-list link is advanced from the shadow, never from the shared
        // table, so a host-forged desc.next cannot corrupt free_head.
        let shadow = &mut self.desc_shadow[index];
        shadow.addr = buf.addr;
        shadow.len = buf.len;
        shadow.flags = flag;

        // Update the free head
        let last = self.free_head;
        self.free_head = shadow.next;

        // Mark the slot as outstanding.
        self.in_use |= 1u32 << index;

        Ok(last)
    }

    /// Recycle descriptors in the list specified by head.
    ///
    /// This will push all linked descriptors at the front of the free list.
    fn recycle_descriptors(
        &mut self,
        mut head: u16,
        g2h: &mut Vec<VirtqueueBuf>,
        h2g: &mut Vec<VirtqueueBuf>,
    ) -> Result<u32> {
        let origin_free_head = self.free_head;
        self.free_head = head;
        let mut recorded_len: u32 = 0;

        while self.num_used > 0 {
            let index = head as usize;
            // `head` is seeded from the host-controlled used-ring id, so only
            // reap slots that are in range and currently outstanding.
            if index >= self.queue_size as usize || (self.in_use & (1u32 << index)) == 0 {
                return Err(VirtioError::InvalidDescriptor);
            }

            // Read descriptor metadata from the private shadow, NOT from the
            // host-writable shared table, so a forged desc.addr/len/next cannot
            // influence which buffer is recycled or freed.
            let shadow = self.desc_shadow[index];
            let flags = shadow.flags;

            // Consume the slot so it cannot be recycled twice.
            self.in_use &= !(1u32 << index);
            self.is_head &= !(1u32 << index);
            self.num_used -= 1;
            recorded_len = recorded_len.saturating_add(shadow.len);

            if flags.contains(DescFlags::WRITE) {
                h2g.push(VirtqueueBuf::new(shadow.addr, shadow.len));
            } else {
                g2h.push(VirtqueueBuf::new(shadow.addr, shadow.len));
            }

            if flags.contains(DescFlags::NEXT) {
                if self.num_used == 0 {
                    return Err(VirtioError::InvalidDescriptor);
                }
                head = shadow.next;
            } else {
                self.desc_shadow[index].next = origin_free_head;
                self.desc
                    .get_mut(index)
                    .ok_or(VirtioError::InvalidDescriptorIndex)?
                    .next
                    .write(origin_free_head);
                break;
            }
        }

        Ok(recorded_len)
    }

    /// Get a token from device used buffers, return (token, len).
    ///
    /// Ref: linux virtio_ring.c virtqueue_get_buf_ctx
    pub fn pop_used(
        &mut self,
        g2h: &mut Vec<VirtqueueBuf>,
        h2g: &mut Vec<VirtqueueBuf>,
    ) -> Result<u32> {
        if !self.can_pop() {
            return Err(VirtioError::NotReady);
        }
        // read barrier
        fence(Ordering::SeqCst);

        let last_used_idx = self.last_used_idx & (self.queue_size - 1);
        let last_used_slot = self
            .used
            .ring
            .get(last_used_idx as usize)
            .ok_or(VirtioError::InvalidRingIndex)?;
        let index = last_used_slot.id.read() as u16;
        let len = last_used_slot.len.read();

        // Untrusted device input: only accept an in-range, outstanding chain
        // head before touching any descriptor.
        if index as usize >= self.queue_size as usize
            || (self.in_use & (1u32 << index)) == 0
            || (self.is_head & (1u32 << index)) == 0
        {
            return Err(VirtioError::InvalidDescriptor);
        }

        let recorded_len = self.recycle_descriptors(index, g2h, h2g)?;
        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // Clamp the device-reported len to the driver-recorded buffer length.
        Ok(len.min(recorded_len))
    }
}

/// The inner layout of a VirtQueue.
pub struct VirtQueueLayout {
    avail_offset: usize,
    used_offset: usize,
    size: usize,
}

/// Align `size` up to a page.
fn align_up(size: usize) -> usize {
    (size + PAGE_SIZE) & !(PAGE_SIZE - 1)
}

impl VirtQueueLayout {
    pub fn new(queue_size: u16) -> Option<Self> {
        let queue_size = queue_size as usize;
        if !queue_size.is_power_of_two() || queue_size > 32768 {
            return None;
        }

        let desc = size_of::<Descriptor>() * queue_size;
        let avail = size_of::<u16>() * (3 + queue_size);
        let used = size_of::<u16>() * 3 + size_of::<UsedElem>() * queue_size;
        Some(VirtQueueLayout {
            avail_offset: desc,
            used_offset: align_up(desc + avail),
            size: align_up(desc + avail) + align_up(used),
        })
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

#[repr(C, align(16))]
#[derive(Debug)]
struct Descriptor {
    addr: Volatile<u64>,
    len: Volatile<u32>,
    flags: Volatile<DescFlags>,
    next: Volatile<u16>,
}

impl Descriptor {
    fn set_buf(&mut self, buf: &VirtqueueBuf) {
        self.addr.write(buf.addr);
        self.len.write(buf.len);
    }
}

/// Private, host-inaccessible copy of the metadata the driver programs into a
/// descriptor. The shared descriptor table can be overwritten by the host at
/// any time, so the driver keeps this shadow and reads back addr/len/flags/next
/// from it on recycle and free-list traversal instead of trusting the shared
/// table.
#[derive(Clone, Copy)]
struct DescriptorShadow {
    addr: u64,
    len: u32,
    flags: DescFlags,
    next: u16,
}

impl Default for DescriptorShadow {
    fn default() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: DescFlags::empty(),
            next: 0,
        }
    }
}

bitflags! {
    /// Descriptor flags
    struct DescFlags: u16 {
        const NEXT = 1;
        const WRITE = 2;
        const INDIRECT = 4;
    }
}

/// The driver uses the available ring to offer buffers to the device:
/// each ring entry refers to the head of a descriptor chain.
/// It is only written by the driver and read by the device.
#[repr(C)]
#[derive(Debug)]
struct AvailRing {
    flags: Volatile<u16>,
    /// A driver MUST NOT decrement the idx.
    idx: Volatile<u16>,
    ring: [Volatile<u16>; MAX_QUEUE_SIZE], // actual size: queue_size
    used_event: Volatile<u16>,             // unused
}

/// The used ring is where the device returns buffers once it is done with them:
/// it is only written to by the device, and read by the driver.
#[repr(C)]
#[derive(Debug)]
struct UsedRing {
    flags: Volatile<u16>,
    idx: Volatile<u16>,
    ring: [UsedElem; MAX_QUEUE_SIZE], // actual size: queue_size
    avail_event: Volatile<u16>,       // unused
}

#[repr(C)]
#[derive(Debug)]
struct UsedElem {
    id: Volatile<u32>,
    len: Volatile<u32>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_struct_size() {
        assert_eq!(size_of::<Descriptor>(), 16);
        assert_eq!(size_of::<DescFlags>(), 2);
        assert_eq!(size_of::<AvailRing>(), 70);
        assert_eq!(size_of::<UsedRing>(), 264);
        assert_eq!(size_of::<UsedElem>(), 8);
    }

    /// Minimal transport stub for exercising `VirtQueue` on the host. It records
    /// nothing and simply advertises a maximum queue size; `VirtQueue::new` only
    /// calls the address/size setters and `get_queue_max_size`.
    struct MockTransport {
        max_queue: u16,
    }

    impl VirtioTransport for MockTransport {
        fn init(&mut self, _device_type: u32) -> Result<()> {
            Ok(())
        }
        fn get_status(&self) -> Result<u8> {
            Ok(0)
        }
        fn set_status(&self, _status: u8) -> Result<()> {
            Ok(())
        }
        fn add_status(&self, _status: u8) -> Result<()> {
            Ok(())
        }
        fn reset(&self) -> Result<()> {
            Ok(())
        }
        fn get_features(&self) -> Result<u64> {
            Ok(0)
        }
        fn set_features(&self, _features: u64) -> Result<()> {
            Ok(())
        }
        fn set_queue(&self, _queue: u16) -> Result<()> {
            Ok(())
        }
        fn get_queue_max_size(&self) -> Result<u16> {
            Ok(self.max_queue)
        }
        fn set_queue_size(&self, _queue_size: u16) -> Result<()> {
            Ok(())
        }
        fn set_descriptors_address(&self, _address: u64) -> Result<()> {
            Ok(())
        }
        fn set_avail_ring(&self, _address: u64) -> Result<()> {
            Ok(())
        }
        fn set_used_ring(&self, _address: u64) -> Result<()> {
            Ok(())
        }
        fn set_queue_enable(&self) -> Result<()> {
            Ok(())
        }
        fn set_interrupt_vector(&mut self, _vector: u8) -> Result<u16> {
            Ok(0)
        }
        fn set_config_notify(&mut self, _index: u16) -> Result<()> {
            Ok(())
        }
        fn set_queue_notify(&mut self, _index: u16) -> Result<()> {
            Ok(())
        }
        fn notify_queue(&self, _queue: u16) -> Result<()> {
            Ok(())
        }
        fn read_device_config(&self, _offset: u64) -> Result<u32> {
            Ok(0)
        }
    }

    /// Allocate a page-aligned, zeroed region to act as the shared DMA backing
    /// store. Intentionally leaked: the returned `VirtQueue` holds `'static`
    /// references into it and the memory must outlive the test.
    fn alloc_dma(size: usize) -> u64 {
        use std::alloc::{alloc_zeroed, Layout};
        let layout = Layout::from_size_align(size, PAGE_SIZE).unwrap();
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        ptr as u64
    }

    fn make_queue(queue_size: u16) -> VirtQueue {
        let transport = MockTransport {
            max_queue: MAX_QUEUE_SIZE as u16,
        };
        let layout = VirtQueueLayout::new(queue_size).unwrap();
        let dma = alloc_dma(layout.size());
        VirtQueue::new(&transport, 0, dma, queue_size).unwrap()
    }

    /// Simulate the untrusted device posting a completion into used ring slot
    /// `used_slot` (chain head `id`, reported byte count `len`) and bumping the
    /// used index so `can_pop` observes it.
    fn device_complete(vq: &mut VirtQueue, used_slot: usize, id: u32, len: u32) {
        vq.used.ring[used_slot].id.write(id);
        vq.used.ring[used_slot].len.write(len);
        let idx = vq.used.idx.read();
        vq.used.idx.write(idx.wrapping_add(1));
    }

    #[test]
    fn normal_completion_returns_recorded_buffers() {
        let mut vq = make_queue(8);
        let head = vq.add(&[], &[VirtqueueBuf::new(0x1000, 64)]).unwrap();
        assert_eq!(vq.in_use & (1u32 << head), 1u32 << head);
        assert_eq!(vq.num_used, 1);

        device_complete(&mut vq, 0, head as u32, 64);

        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        let len = vq.pop_used(&mut g2h, &mut h2g).unwrap();

        assert_eq!(len, 64);
        assert!(g2h.is_empty());
        assert_eq!(h2g.len(), 1);
        assert_eq!(h2g[0].addr, 0x1000);
        assert_eq!(h2g[0].len, 64);
        assert_eq!(vq.num_used, 0);
        assert_eq!(vq.in_use & (1u32 << head), 0);
    }

    #[test]
    fn rejects_out_of_range_id() {
        let mut vq = make_queue(8);
        let _head = vq.add(&[], &[VirtqueueBuf::new(0x1000, 64)]).unwrap();

        // id 40 is outside the 8-entry table.
        device_complete(&mut vq, 0, 40, 64);

        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        assert!(matches!(
            vq.pop_used(&mut g2h, &mut h2g),
            Err(VirtioError::InvalidDescriptor)
        ));
    }

    #[test]
    fn rejects_forged_not_in_use_id() {
        let mut vq = make_queue(8);
        let head = vq.add(&[], &[VirtqueueBuf::new(0x1000, 64)]).unwrap();

        // In range, but never handed to the device.
        let forged = (head + 5) % 8;
        assert_ne!(forged, head);
        device_complete(&mut vq, 0, forged as u32, 64);

        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        assert!(matches!(
            vq.pop_used(&mut g2h, &mut h2g),
            Err(VirtioError::InvalidDescriptor)
        ));
    }

    #[test]
    fn rejects_duplicate_completion() {
        let mut vq = make_queue(8);
        let head = vq.add(&[], &[VirtqueueBuf::new(0x1000, 64)]).unwrap();

        device_complete(&mut vq, 0, head as u32, 64);
        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        vq.pop_used(&mut g2h, &mut h2g).unwrap();

        // Device replays the same head in the next used slot (double-free attempt).
        device_complete(&mut vq, 1, head as u32, 64);
        let mut g2h2 = Vec::new();
        let mut h2g2 = Vec::new();
        assert!(matches!(
            vq.pop_used(&mut g2h2, &mut h2g2),
            Err(VirtioError::InvalidDescriptor)
        ));
    }

    #[test]
    fn ignores_corrupted_shared_desc_uses_shadow() {
        let mut vq = make_queue(8);
        // Two-descriptor chain: readable (g2h) followed by writable (h2g).
        let head = vq
            .add(
                &[VirtqueueBuf::new(0x2000, 32)],
                &[VirtqueueBuf::new(0x3000, 48)],
            )
            .unwrap();
        assert_eq!(vq.num_used, 2);

        // Attacker rewrites the entire shared descriptor table: forge a `next`
        // cycle and garbage addr/len/flags. The reap path must ignore all of it.
        for i in 0..8usize {
            vq.desc[i].addr.write(0xdead_beef);
            vq.desc[i].len.write(0xffff_ffff);
            vq.desc[i].flags.write(DescFlags::WRITE | DescFlags::NEXT);
            vq.desc[i].next.write(head); // self/cross cycle
        }

        device_complete(&mut vq, 0, head as u32, 32);

        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        let len = vq.pop_used(&mut g2h, &mut h2g).unwrap();

        // Values come from the private shadow, not the forged shared table.
        assert_eq!(g2h.len(), 1);
        assert_eq!(g2h[0].addr, 0x2000);
        assert_eq!(g2h[0].len, 32);
        assert_eq!(h2g.len(), 1);
        assert_eq!(h2g[0].addr, 0x3000);
        assert_eq!(h2g[0].len, 48);
        // Reported len clamped to recorded chain length (32 + 48).
        assert_eq!(len, 32);
        assert_eq!(vq.num_used, 0);
        assert_eq!(vq.in_use, 0);
    }

    #[test]
    fn clamps_oversized_device_len() {
        let mut vq = make_queue(8);
        let head = vq.add(&[], &[VirtqueueBuf::new(0x1000, 64)]).unwrap();

        // Device lies about how many bytes it wrote.
        device_complete(&mut vq, 0, head as u32, u32::MAX);

        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        let len = vq.pop_used(&mut g2h, &mut h2g).unwrap();

        // Clamped to the buffer length the driver recorded.
        assert_eq!(len, 64);
    }

    #[test]
    fn rejects_mid_chain_completion() {
        let mut vq = make_queue(8);
        // Two-descriptor chain: head (g2h) -> tail (h2g).
        let head = vq
            .add(
                &[VirtqueueBuf::new(0x2000, 32)],
                &[VirtqueueBuf::new(0x3000, 48)],
            )
            .unwrap();

        // The tail slot is in_use but is NOT a chain head.
        let tail = vq.desc_shadow[head as usize].next;
        assert_ne!(tail, head);
        assert_eq!(vq.in_use & (1u32 << tail), 1u32 << tail);

        // Device completes the mid/tail descriptor instead of the head.
        device_complete(&mut vq, 0, tail as u32, 48);

        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        assert!(matches!(
            vq.pop_used(&mut g2h, &mut h2g),
            Err(VirtioError::InvalidDescriptor)
        ));

        // Nothing was reaped; the real chain is still intact.
        assert_eq!(vq.num_used, 2);
        assert_eq!(vq.in_use & (1u32 << head), 1u32 << head);
    }
}
