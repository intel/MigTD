// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::protocol::{field, Packet};
use crate::stream::{VsockStream, BINDING_PKT_QUEUES, CONNECTION_PKT_QUEUES};
use crate::{align_up, VsockAddr, VsockAddrPair, VsockDmaPageAllocator, PAGE_SIZE};

use super::event::*;
use super::{Result, VsockTransportError};

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::poll_fn;
use core::ptr::{slice_from_raw_parts, slice_from_raw_parts_mut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Poll;
use lazy_static::lazy_static;
use spin::{Mutex, Once};
use td_payload::arch::idt::InterruptStack;
use td_payload::mm::shared::{alloc_shared_pages, free_shared_pages};
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
pub(crate) const MAX_VSOCK_PKT_DATA_LEN: usize = 0x1000 * 16;

pub static RX_FLAG: AtomicBool = AtomicBool::new(false);
pub static TX_FLAG: AtomicBool = AtomicBool::new(false);
pub static CONFIG_FLAG: AtomicBool = AtomicBool::new(false);

lazy_static! {
    static ref VSOCK_DEVICE: Mutex<Once<VirtioVsock>> = Mutex::new(Once::new());
}

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
    rx: VirtQueue,
    tx: VirtQueue,
    #[allow(unused)]
    event: VirtQueue,
    /// DMA record table
    dma_record: BTreeMap<u64, DmaRecord>,
    rx_buf_num: usize,
}

unsafe impl Send for VirtioVsock {}
unsafe impl Sync for VirtioVsock {}

impl VirtioVsock {
    pub fn new(
        mut virtio_transport: Box<dyn VirtioTransport>,
        dma_allocator: Box<dyn VsockDmaPageAllocator>,
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
        let queue_dma_pages = unsafe { alloc_shared_pages(queue_size / PAGE_SIZE) }
            .ok_or(VsockTransportError::DmaAllocation)? as u64;
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

        let irq_index_rx = transport.set_interrupt_vector(RX_VECTOR)?;
        Self::set_queue_notify(transport, QUEUE_RX, irq_index_rx)?;
        let irq_index_tx = transport.set_interrupt_vector(TX_VECTOR)?;
        Self::set_queue_notify(transport, QUEUE_TX, irq_index_tx)?;

        register_callback(RX_VECTOR, rx_callback)?;
        register_callback(TX_VECTOR, tx_callback)?;
        register_callback(CONFIG_VECTOR, config_callback)?;

        Ok(Self {
            virtio_transport,
            dma_allocator,
            rx: queue_rx,
            tx: queue_tx,
            event: queue_event,
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

    fn set_queue_notify(transport: &mut dyn VirtioTransport, queue: u16, index: u16) -> Result<()> {
        transport.set_queue(queue)?;
        transport.set_queue_notify(index)?;
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

        let _ = self.rx.pop_used(&mut g2h, &mut h2g)?;
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

        let packet_hdr = Packet::new_checked(&hdr_buf[..])
            .map_err(|_| VsockTransportError::InvalidVsockPacket)?;
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
            self.rx.add(&[], &h2g)?;

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

pub fn vsock_transport_init(
    virtio: Box<dyn VirtioTransport>,
    dma_allocator: Box<dyn VsockDmaPageAllocator>,
) -> Result<()> {
    let virtio_vsock = VirtioVsock::new(virtio, dma_allocator)?;
    let mut lock = VSOCK_DEVICE.lock();
    lock.call_once(|| virtio_vsock);

    let device = lock.get_mut().ok_or(VsockTransportError::Initilization)?;
    // Report driver ready
    device
        .virtio_transport
        .add_status(VIRTIO_STATUS_DRIVER_OK)?;

    if device.virtio_transport.get_status()? & VIRTIO_STATUS_DRIVER_OK != VIRTIO_STATUS_DRIVER_OK {
        device.virtio_transport.add_status(VIRTIO_STATUS_FAILED)?;
        return Err(VsockTransportError::Initilization);
    }
    device.rx_queue_fill()?;

    Ok(())
}

// Get current device CID
pub fn vsock_transport_get_cid() -> Result<u64> {
    let mut lock = VSOCK_DEVICE.lock();
    let device = lock.get_mut().ok_or(VsockTransportError::Initilization)?;

    Ok(u64::from(device.virtio_transport.read_device_config(0)?)
        | u64::from(device.virtio_transport.read_device_config(4)?) << 32)
}

pub async fn vsock_transport_enqueue(
    _stream: &VsockStream,
    hdr: &[u8],
    buf: &[u8],
    _timeout: u32,
) -> Result<usize> {
    if hdr.len() != field::HEADER_LEN || buf.len() > MAX_VSOCK_PKT_DATA_LEN {
        return Err(VsockTransportError::InvalidParameter);
    }

    // Acquire the lock to access the vsock device.
    let mut lock = VSOCK_DEVICE.lock();
    let device = lock.get_mut().ok_or(VsockTransportError::Initilization)?;

    let mut g2h = Vec::new();

    let dma = device
        .allocate_dma_memory(hdr.len())
        .ok_or(VsockTransportError::DmaAllocation)?;

    let dma_buf = unsafe { &mut *slice_from_raw_parts_mut(dma.dma_addr as *mut u8, dma.dma_size) };
    dma_buf[0..hdr.len()].copy_from_slice(hdr);
    g2h.push(VirtqueueBuf::new(dma.dma_addr, hdr.len() as u32));

    if !buf.is_empty() {
        let dma = device
            .allocate_dma_memory(buf.len())
            .ok_or(VsockTransportError::DmaAllocation)?;

        let dma_buf =
            unsafe { &mut *slice_from_raw_parts_mut(dma.dma_addr as *mut u8, dma.dma_size) };
        dma_buf[0..buf.len()].copy_from_slice(buf);
        g2h.push(VirtqueueBuf::new(dma.dma_addr, buf.len() as u32));
    }

    device.tx.add(g2h.as_slice(), &[])?;
    device.kick_queue(QUEUE_TX)?;

    // Release the lock to avoid deadlock in the `poll_fn`
    core::mem::drop(lock);

    // Poll if there are used buffer in tx queue
    poll_fn(|_cx| -> Poll<Result<()>> {
        let mut lock = VSOCK_DEVICE.lock();
        let device = lock.get_mut().ok_or(VsockTransportError::Initilization)?;

        if !device.tx.can_pop() {
            Poll::Pending
        } else {
            let mut g2h = Vec::new();
            let mut h2g = Vec::new();
            let _ = device.tx.pop_used(&mut g2h, &mut h2g)?;

            for vq_buf in &g2h {
                device
                    .free_dma_memory(vq_buf.addr)
                    .ok_or(VsockTransportError::DmaAllocation)?;
            }
            Poll::Ready(Ok(()))
        }
    })
    .await?;

    Ok(buf.len())
}

pub async fn vsock_transport_dequeue(stream: &VsockStream, _timeout: u32) -> Result<Vec<u8>> {
    if let Some(data) = VirtioVsock::pop_buf_from_stream_queues(&stream.addr()) {
        return Ok(data);
    }

    poll_fn(|_cx| -> Poll<Result<Vec<u8>>> {
        // Acquire the lock to pop the used buffer from rx queue.
        let mut lock = VSOCK_DEVICE.lock();
        let device = lock.get_mut().ok_or(VsockTransportError::Initilization)?;

        // Pop the used buffer in the rx queue.
        if !device.rx.can_pop() {
            Poll::Pending
        } else {
            device.pop_used_rx()?;
            if let Some(data) = VirtioVsock::pop_buf_from_stream_queues(&stream.addr()) {
                Poll::Ready(Ok(data))
            } else {
                Poll::Pending
            }
        }
    })
    .await
}

/// Whether can send packet.
pub fn vsock_transport_can_send() -> Result<bool> {
    let mut lock = VSOCK_DEVICE.lock();
    let device = lock.get_mut().ok_or(VsockTransportError::Initilization)?;

    Ok(device.tx.available_desc() >= 1)
}

/// Whether can receive packet.
pub fn vsock_transport_can_recv() -> Result<bool> {
    let mut lock = VSOCK_DEVICE.lock();
    let device = lock.get_mut().ok_or(VsockTransportError::Initilization)?;

    Ok(device.rx.can_pop())
}

impl Drop for VirtioVsock {
    fn drop(&mut self) {
        for record in &self.dma_record {
            unsafe { free_shared_pages(record.1.dma_addr as usize, record.1.dma_size / PAGE_SIZE) }
        }
    }
}

fn rx_callback(_: &mut InterruptStack) {
    RX_FLAG.store(true, Ordering::SeqCst);
}

fn tx_callback(_: &mut InterruptStack) {
    TX_FLAG.store(true, Ordering::SeqCst);
}

fn config_callback(_: &mut InterruptStack) {
    CONFIG_FLAG.store(true, Ordering::SeqCst);
}
