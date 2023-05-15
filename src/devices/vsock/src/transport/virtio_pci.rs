// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::protocol::{field, Packet};
use crate::stream::{VsockStream, BINDING_PKT_QUEUES, CONNECTION_PKT_QUEUES};
use crate::{
    align_up, VsockAddr, VsockAddrPair, VsockDmaPageAllocator, VsockTimeout, VsockTransport,
    PAGE_SIZE,
};

use super::event::*;
use super::{Result, VsockTransportError};

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ptr::{slice_from_raw_parts, slice_from_raw_parts_mut};
use core::sync::atomic::{AtomicBool, Ordering};
use virtio::virtqueue::{VirtQueue, VirtQueueLayout, VirtqueueBuf};
use virtio::{consts::*, VirtioError, VirtioTransport};

const QUEUE_RX: u16 = 0;
const QUEUE_TX: u16 = 1;
const QUEUE_EVENT: u16 = 2;
const RX_VECTOR: u8 = 0x52;
const TX_VECTOR: u8 = 0x53;
const CONFIG_VECTOR: u8 = 0x54;
const QUEUE_SIZE: usize = 16;
const RX_QUEUE_PREFILL_NUM: usize = 16;
const VSOCK_DEFAULT_BUF_SIZE: usize = PAGE_SIZE;

pub static RX_FLAG: AtomicBool = AtomicBool::new(false);
pub static TX_FLAG: AtomicBool = AtomicBool::new(false);
pub static CONFIG_FLAG: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy)]
pub struct DmaRecord {
    pub dma_addr: u64,
    pub dma_size: usize,
}

impl DmaRecord {
    pub fn new(dma_addr: u64, dma_size: usize) -> Self {
        DmaRecord { dma_addr, dma_size }
    }
}

pub struct VirtioVsock {
    pub virtio_transport: Box<dyn VirtioTransport>,
    dma_allocator: Box<dyn VsockDmaPageAllocator>,
    timer: Box<dyn VsockTimeout>,
    rx: RefCell<VirtQueue>,
    tx: RefCell<VirtQueue>,
    #[allow(unused)]
    event: RefCell<VirtQueue>,

    /// DMA record table
    dma_record: BTreeMap<u64, DmaRecord>,

    rx_buf_num: usize,
}

impl VirtioVsock {
    pub fn new(
        mut virtio_transport: Box<dyn VirtioTransport>,
        dma_allocator: Box<dyn VsockDmaPageAllocator>,
        timer: Box<dyn VsockTimeout>,
    ) -> Result<Self> {
        let transport = virtio_transport.as_mut();
        // Initialise the transport
        transport
            .init(VIRTIO_SUBSYSTEM_VSOCK)
            .map_err(|_| VsockTransportError::Initilization)?;

        // Reset device
        transport.add_status(64)?;
        transport.set_status(VIRTIO_STATUS_RESET)?;

        // Acknowledge
        transport.add_status(VIRTIO_STATUS_ACKNOWLEDGE)?;

        // And advertise driver
        transport.add_status(VIRTIO_STATUS_DRIVER)?;

        // And device features ok
        transport.add_status(VIRTIO_STATUS_FEATURES_OK)?;
        if transport.get_status()? & VIRTIO_STATUS_FEATURES_OK != VIRTIO_STATUS_FEATURES_OK {
            transport.add_status(VIRTIO_STATUS_FAILED)?;
            return Err(VsockTransportError::Initilization);
        }

        // Hardcoded queue size to QUEUE_SIZE at the moment
        let max_queue = transport.get_queue_max_size()?;
        if max_queue < QUEUE_SIZE as u16 {
            transport.add_status(VIRTIO_STATUS_FAILED)?;
            return Err(VsockTransportError::Initilization);
        }
        transport.set_queue_size(QUEUE_SIZE as u16)?;

        let mut dma_record = BTreeMap::new();

        // Create a layout here used to calculate the DMA memory size may be used
        let queue_layout =
            VirtQueueLayout::new(QUEUE_SIZE as u16).ok_or(VirtioError::CreateVirtioQueue)?;
        // We have three queue for vsock (rx, tx and event)
        let queue_size = queue_layout.size() << 2;
        let queue_dma_pages = dma_allocator
            .alloc_pages(queue_size / PAGE_SIZE)
            .ok_or(VsockTransportError::DmaAllocation)?;
        dma_record.insert(queue_dma_pages, DmaRecord::new(queue_dma_pages, queue_size));

        // program queue rx(idx 0)
        let queue_rx_dma = queue_dma_pages;
        let queue_rx = Self::create_queue(transport, QUEUE_RX, queue_rx_dma, QUEUE_SIZE as u16)?;

        // program queues tx(idx 1)
        let queue_tx_dma = queue_rx_dma + queue_layout.size() as u64;
        let queue_tx = Self::create_queue(transport, QUEUE_TX, queue_tx_dma, QUEUE_SIZE as u16)?;

        // program queues event(idx 2)
        let queue_event_dma = queue_tx_dma + queue_layout.size() as u64;
        let queue_event =
            Self::create_queue(transport, QUEUE_EVENT, queue_event_dma, QUEUE_SIZE as u16)?;

        Self::set_queue_notify(transport, QUEUE_RX, RX_VECTOR)?;
        Self::set_queue_notify(transport, QUEUE_TX, TX_VECTOR)?;

        register_callback(RX_VECTOR, rx_callback);
        register_callback(TX_VECTOR, tx_callback);
        register_callback(CONFIG_VECTOR, config_callback);

        Ok(Self {
            virtio_transport,
            dma_allocator,
            timer,
            rx: RefCell::new(queue_rx),
            tx: RefCell::new(queue_tx),
            event: RefCell::new(queue_event),
            dma_record,
            rx_buf_num: 0,
        })
    }

    /// create and enable a virtqueue and enable it.
    fn create_queue(
        transport: &dyn VirtioTransport,
        idx: u16,
        dma_addr: u64,
        queue_size: u16,
    ) -> Result<VirtQueue> {
        transport.set_queue(idx)?;
        transport.set_queue_size(queue_size)?;
        let queue = VirtQueue::new(transport, idx as usize, dma_addr, queue_size)?;
        transport.set_queue_enable()?;
        Ok(queue)
    }

    fn set_queue_notify(transport: &mut dyn VirtioTransport, queue: u16, vector: u8) -> Result<()> {
        transport.set_queue(queue)?;
        transport.set_queue_notify(vector)?;
        transport.set_queue_enable()?;

        Ok(())
    }

    fn kick_queue(&self, queue: u16) -> Result<()> {
        self.virtio_transport.set_queue(queue)?;
        self.virtio_transport.notify_queue(queue)?;

        Ok(())
    }

    fn pop_used_rx(&mut self) -> Result<()> {
        let mut g2h = Vec::new();
        let mut h2g = Vec::new();

        let _ = self.rx.borrow_mut().pop_used(&mut g2h, &mut h2g).unwrap();
        if h2g.len() != 2 {
            self.rx_buf_num -= h2g.len();
            return Err(VsockTransportError::InvalidVsockPacket);
        }
        self.rx_buf_num -= 2;

        self.recv_pkt(&h2g)?;

        self.rx_queue_fill()
    }

    fn push_buf_into_stream_queues(addrs: &VsockAddrPair, buf: Vec<u8>) {
        if buf.is_empty() {
            return;
        }

        if let Some(stream_queue) = CONNECTION_PKT_QUEUES.lock().get_mut(addrs) {
            stream_queue.push_back(buf);
        } else if let Some(stream_queue) = BINDING_PKT_QUEUES.lock().get_mut(&addrs.local) {
            stream_queue.push_back(buf);
        }
    }

    fn pop_buf_from_stream_queues(addrs: &VsockAddrPair) -> Option<Vec<u8>> {
        if let Some(stream_queue) = CONNECTION_PKT_QUEUES.lock().get_mut(addrs) {
            stream_queue.pop_front()
        } else if let Some(stream_queue) = BINDING_PKT_QUEUES.lock().get_mut(&addrs.local) {
            stream_queue.pop_front()
        } else {
            None
        }
    }

    fn recv_pkt(&mut self, pkt: &[VirtqueueBuf]) -> Result<()> {
        let mut hdr_buf = Vec::new();
        let mut data_buf = Vec::new();

        // Read out the packet header
        if self.dma_record.contains_key(&pkt[0].addr) {
            if pkt[0].len != field::HEADER_LEN as u32 {
                return Err(VsockTransportError::InvalidVsockPacket);
            }

            let dma_buf =
                unsafe { &*slice_from_raw_parts(pkt[0].addr as *const u8, pkt[0].len as usize) };

            hdr_buf.extend_from_slice(dma_buf);
            self.free_dma_memory(pkt[0].addr)
                .ok_or(VsockTransportError::DmaAllocation)?;
        }

        let packet_hdr = Packet::new_unchecked(&hdr_buf[..]);
        let data_len = packet_hdr.data_len();
        if data_len != 0 {
            if data_len > pkt[1].len {
                return Err(VsockTransportError::InvalidVsockPacket);
            }

            if self.dma_record.contains_key(&pkt[1].addr) {
                let dma_buf = unsafe {
                    &*slice_from_raw_parts(pkt[1].addr as *const u8, pkt[1].len as usize)
                };

                data_buf.extend_from_slice(dma_buf);
            }
        }
        self.free_dma_memory(pkt[1].addr)
            .ok_or(VsockTransportError::DmaAllocation)?;

        let key = VsockAddrPair {
            local: VsockAddr::new(packet_hdr.dst_cid() as u32, packet_hdr.dst_port()),
            remote: VsockAddr::new(packet_hdr.src_cid() as u32, packet_hdr.src_port()),
        };

        Self::push_buf_into_stream_queues(&key, hdr_buf);
        Self::push_buf_into_stream_queues(&key, data_buf);

        Ok(())
    }

    fn rx_queue_fill(&mut self) -> Result<()> {
        if self.rx_buf_num > RX_QUEUE_PREFILL_NUM / 2 {
            return Ok(());
        }

        while self.rx_buf_num < RX_QUEUE_PREFILL_NUM {
            // pkt header
            // to do: allocate packet header with small granularity
            let pkt_header = self
                .allocate_dma_memory(field::HEADER_LEN)
                .ok_or(VsockTransportError::DmaAllocation)?;

            let data_buf = self
                .allocate_dma_memory(VSOCK_DEFAULT_BUF_SIZE)
                .ok_or(VsockTransportError::DmaAllocation)?;

            let h2g = [
                VirtqueueBuf::new(pkt_header.dma_addr, field::HEADER_LEN as u32),
                VirtqueueBuf::new(data_buf.dma_addr, VSOCK_DEFAULT_BUF_SIZE as u32),
            ];

            // A buffer chain contains a packet header buffer and a data buffer
            self.rx.get_mut().add(&[], &h2g).unwrap();

            self.rx_buf_num += 2;
        }

        self.kick_queue(QUEUE_RX)
    }

    fn allocate_dma_memory(&mut self, size: usize) -> Option<DmaRecord> {
        let dma_size = align_up(size);
        let dma_addr = self.dma_allocator.alloc_pages(dma_size / PAGE_SIZE)?;

        let record = DmaRecord::new(dma_addr, dma_size);
        self.dma_record.insert(dma_addr, record);

        Some(record)
    }

    fn free_dma_memory(&mut self, dma_addr: u64) -> Option<u64> {
        let record = self.dma_record.get(&dma_addr)?;

        self.dma_allocator
            .free_pages(record.dma_addr, record.dma_size / PAGE_SIZE);

        self.dma_record.remove(&dma_addr);
        Some(dma_addr)
    }
}

impl VsockTransport for VirtioVsock {
    fn init(&mut self) -> core::result::Result<(), VsockTransportError> {
        // Report driver ready
        self.virtio_transport.add_status(VIRTIO_STATUS_DRIVER_OK)?;

        if self.virtio_transport.get_status()? & VIRTIO_STATUS_DRIVER_OK != VIRTIO_STATUS_DRIVER_OK
        {
            self.virtio_transport.add_status(VIRTIO_STATUS_FAILED)?;
            return Err(VsockTransportError::Initilization);
        }

        self.rx_queue_fill()?;

        Ok(())
    }

    // Get current device CID
    fn get_cid(&self) -> core::result::Result<u64, VsockTransportError> {
        Ok(u64::from(self.virtio_transport.read_device_config(0)?)
            | u64::from(self.virtio_transport.read_device_config(4)?) << 32)
    }

    fn enqueue(
        &mut self,
        _stream: &VsockStream,
        hdr: &[u8],
        buf: &[u8],
        timeout: u64,
    ) -> core::result::Result<usize, VsockTransportError> {
        if hdr.len() != field::HEADER_LEN || buf.len() > u32::MAX as usize {
            return Err(VsockTransportError::InvalidParameter);
        }

        let mut g2h = Vec::new();

        let dma = self
            .allocate_dma_memory(hdr.len())
            .ok_or(VsockTransportError::DmaAllocation)?;

        let dma_buf =
            unsafe { &mut *slice_from_raw_parts_mut(dma.dma_addr as *mut u8, dma.dma_size) };
        dma_buf[0..hdr.len()].copy_from_slice(hdr);
        g2h.push(VirtqueueBuf::new(dma.dma_addr, hdr.len() as u32));

        if !buf.is_empty() {
            let dma = self
                .allocate_dma_memory(buf.len())
                .ok_or(VsockTransportError::DmaAllocation)?;

            let dma_buf =
                unsafe { &mut *slice_from_raw_parts_mut(dma.dma_addr as *mut u8, dma.dma_size) };
            dma_buf[0..buf.len()].copy_from_slice(buf);
            g2h.push(VirtqueueBuf::new(dma.dma_addr, buf.len() as u32));
        }

        self.tx.borrow_mut().add(g2h.as_slice(), &[])?;

        self.kick_queue(QUEUE_TX)?;

        self.timer
            .set_timeout(timeout)
            .ok_or(VsockTransportError::InvalidParameter)?;

        while !self.tx.borrow_mut().can_pop() {
            if !wait_for_event(&TX_FLAG, self.timer.as_ref()) && !self.tx.borrow_mut().can_pop() {
                return Err(VsockTransportError::Timeout);
            }
        }
        self.timer.reset_timeout();

        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        let _ = self.tx.borrow_mut().pop_used(&mut g2h, &mut h2g).unwrap();

        for vq_buf in &g2h {
            self.free_dma_memory(vq_buf.addr)
                .ok_or(VsockTransportError::DmaAllocation)?;
        }

        Ok(buf.len())
    }

    fn dequeue(
        &mut self,
        stream: &VsockStream,
        timeout: u64,
    ) -> core::result::Result<Vec<u8>, VsockTransportError> {
        if let Some(data) = Self::pop_buf_from_stream_queues(&stream.addr()) {
            return Ok(data);
        }

        self.timer
            .set_timeout(timeout)
            .ok_or(VsockTransportError::InvalidParameter)?;

        loop {
            while !self.rx.borrow_mut().can_pop() {
                if !wait_for_event(&RX_FLAG, self.timer.as_ref()) && !self.rx.borrow_mut().can_pop()
                {
                    return Err(VsockTransportError::Timeout);
                }
            }

            self.pop_used_rx()?;
            if let Some(data) = Self::pop_buf_from_stream_queues(&stream.addr()) {
                self.timer.reset_timeout();
                return Ok(data);
            }
        }
    }

    /// Whether can send packet.
    fn can_send(&self) -> bool {
        let tx = self.tx.borrow();
        tx.available_desc() >= 1
    }

    /// Whether can receive packet.
    fn can_recv(&self) -> bool {
        let rx = self.rx.borrow();
        rx.can_pop()
    }
}

impl Drop for VirtioVsock {
    fn drop(&mut self) {
        for record in &self.dma_record {
            self.dma_allocator
                .free_pages(record.1.dma_addr, record.1.dma_size / PAGE_SIZE)
        }
    }
}

interrupt_handler_template!(rx_callback, _stack, {
    RX_FLAG.store(true, Ordering::SeqCst);
});

interrupt_handler_template!(tx_callback, _stack, {
    TX_FLAG.store(true, Ordering::SeqCst);
});

interrupt_handler_template!(config_callback, _stack, {
    CONFIG_FLAG.store(true, Ordering::SeqCst);
});
