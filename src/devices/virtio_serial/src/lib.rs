// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;
use core::fmt::Display;
use core::mem::size_of;
use core::ops::Index;
use core::ops::IndexMut;
use core::slice::{from_raw_parts, from_raw_parts_mut};
use core::sync::atomic::{AtomicBool, Ordering};
use lazy_static::lazy_static;
use spin::{Mutex, Once};
use td_payload::arch::idt::InterruptStack;
use virtio::{consts::*, virtqueue::*, VirtioError, VirtioTransport};

use rust_std_stub::{error, io};

mod port;
pub use port::*;
mod event;
use event::*;

pub const MAX_PORT_SUPPORTED: usize = 2;

const DEFAULT_BUF_SIZE: usize = PAGE_SIZE;
const DEFAULT_TIMEOUT: u32 = 0x8000;
const PAGE_SIZE: usize = 0x1000;
const PORT0_RECEIVEQ: u16 = 0;
const PORT0_TRANSMITQ: u16 = 1;
const CONTROL_RECEIVEQ: u16 = 2;
const CONTROL_TRANSMITQ: u16 = 3;
const IRQ_VECTOR: u8 = 0x52;
const QUEUE_SIZE: usize = 16;
const RX_QUEUE_PREFILL_NUM: usize = 16;
const CONFIG_MAX_NR_PORTS_OFFSET: u64 = 4;

pub static IRQ_FLAG: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub enum VirtioSerialError {
    /// Initialization error
    Initialization,
    /// Virtio/virtqueue error
    Virtio(VirtioError),
    /// Invalid parameter
    InvalidParameter,
    /// Unable to allocate DMA memory
    OutOfResource,
    /// Got error reading/writing the device, e.g. seting up the config
    Device,
    /// Timeout
    Timeout,
    // The port is not available
    PortNotAvailable(u32),
    // The port is already occupied
    PortAlreadyUsed(u32),
    /// Configure device interrupt
    Interrupt,
    // There is no data has been sent or received
    NotReady,
}

impl Display for VirtioSerialError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VirtioSerialError::Initialization => write!(f, "Initialization"),
            VirtioSerialError::Virtio(e) => write!(f, "Virtio: {e}"),
            VirtioSerialError::InvalidParameter => write!(f, "InvalidParameter"),
            VirtioSerialError::OutOfResource => write!(f, "OutOfResource"),
            VirtioSerialError::Device => write!(f, "Device"),
            VirtioSerialError::Timeout => write!(f, "Timeout"),
            VirtioSerialError::PortNotAvailable(e) => write!(f, "PortNotAvailable: 0x{e:x}"),
            VirtioSerialError::PortAlreadyUsed(e) => write!(f, "PortAlreadyUsed: 0x{e:x}"),
            VirtioSerialError::Interrupt => write!(f, "Interrupt"),
            VirtioSerialError::NotReady => write!(f, "NotReady"),
        }
    }
}

impl error::Error for VirtioSerialError {}

impl From<VirtioSerialError> for io::Error {
    fn from(e: VirtioSerialError) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

impl From<VirtioError> for VirtioSerialError {
    fn from(e: VirtioError) -> Self {
        Self::Virtio(e)
    }
}

type Result<T> = core::result::Result<T, VirtioSerialError>;

lazy_static! {
    static ref SERIAL_DEVICE: Mutex<Once<VirtioSerial>> = Mutex::new(Once::new());
}

pub fn register_serial_device(dev: VirtioSerial) -> Result<()> {
    let mut serial_device = SERIAL_DEVICE.lock();
    serial_device.call_once(|| dev);
    serial_device
        .get_mut()
        .ok_or(VirtioSerialError::Initialization)?
        .init()?;
    Ok(())
}

lazy_static! {
    pub(crate) static ref RECEIVE_QUEUES: Mutex<BTreeMap<u32, VecDeque<Vec<u8>>>> =
        Mutex::new(BTreeMap::new());
}

#[derive(Debug, Clone, Copy)]
pub struct DmaMemoryRegion {
    pub dma_addr: u64,
    pub dma_size: usize,
}

impl DmaMemoryRegion {
    pub fn new(dma_addr: u64, dma_size: usize) -> Self {
        DmaMemoryRegion { dma_addr, dma_size }
    }
}

/// Trait to allow separation of transport from block driver
pub trait DmaPageAllocator {
    fn alloc_pages(&self, page_num: usize) -> Option<u64>;
    fn free_pages(&self, addr: u64, page_num: usize);
}

/// Trait to allow separation of transport from block driver
pub trait Timer {
    fn set_timeout(&self, timeout: u32) -> Option<u32>;
    fn is_timeout(&self) -> bool;
    fn reset_timeout(&self);
}

#[repr(C)]
#[derive(Debug)]
pub struct VirtioConsoleControl {
    id: u32,
    event: u16,
    value: u16,
}

impl VirtioConsoleControl {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[repr(u16)]
#[derive(Debug)]
pub enum ControlEvent {
    DeviceReady = 0,
    DeviceAdd = 1,
    DeviceRemove = 2,
    PortReady = 3,
    ConsolePort = 4,
    Resize = 5,
    PortOpen = 6,
    PortName = 7,
    Unknown,
}

impl From<u16> for ControlEvent {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::DeviceReady,
            1 => Self::DeviceAdd,
            2 => Self::DeviceRemove,
            3 => Self::PortReady,
            4 => Self::ConsolePort,
            5 => Self::Resize,
            6 => Self::PortOpen,
            7 => Self::PortName,
            _ => Self::Unknown,
        }
    }
}

pub struct VirtioSerial {
    virtio: Box<dyn VirtioTransport>,
    dma_allocator: Box<dyn DmaPageAllocator>,
    timer: Box<dyn Timer>,

    /// DMA allocation table
    dma_allocation: BTreeMap<u64, DmaMemoryRegion>,

    // virtio queues
    queues: Vec<RefCell<VirtQueue>>,
    // Virtio
    receive_queues_prefill: Vec<usize>,

    // Max number of ports
    max_nr_ports: u32,
    // Set of connected ports
    connected_ports: BTreeSet<u32>,
    // Set of allocated ports
    allocated_ports: BTreeSet<u32>,
}

unsafe impl Send for VirtioSerial {}
unsafe impl Sync for VirtioSerial {}

impl VirtioSerial {
    pub fn new(
        virtio: Box<dyn VirtioTransport>,
        dma_allocator: Box<dyn DmaPageAllocator>,
        timer: Box<dyn Timer>,
    ) -> Result<Self> {
        Ok(Self {
            virtio,
            dma_allocator,
            timer,
            queues: Vec::new(),
            receive_queues_prefill: Vec::new(),
            dma_allocation: BTreeMap::new(),
            max_nr_ports: 0,
            connected_ports: BTreeSet::new(),
            allocated_ports: BTreeSet::new(),
        })
    }

    pub fn allocate_port(&mut self, id: u32) -> Result<()> {
        Self::port_queue_create(id)?;
        if !self.connected_ports.contains(&id) {
            return Err(VirtioSerialError::PortNotAvailable(id));
        }

        if self.allocated_ports.contains(&id) {
            return Err(VirtioSerialError::PortAlreadyUsed(id));
        }

        self.allocated_ports.insert(id);
        Ok(())
    }

    pub fn free_port(&mut self, id: u32) -> Result<()> {
        Self::port_queue_delete(id)?;
        if !self.connected_ports.contains(&id) {
            return Err(VirtioSerialError::PortNotAvailable(id));
        }

        let _ = self.allocated_ports.remove(&id);
        Ok(())
    }

    fn init(&mut self) -> Result<()> {
        self.init_status()?;
        self.read_device_config()?;
        self.init_queues()?;
        self.init_notification()?;
        self.driver_ok()?;

        self.init_control()
    }

    fn init_status(&mut self) -> Result<()> {
        let transport = self.virtio.as_mut();
        // Initialise the transport
        transport
            .init(VIRTIO_SUBSYSTEM_CONSOLE)
            .map_err(|_| VirtioSerialError::Device)?;

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
            return Err(VirtioSerialError::Device);
        }

        // Hardcoded queue size to QUEUE_SIZE at the moment
        let max_queue = transport.get_queue_max_size()?;
        if max_queue < QUEUE_SIZE as u16 {
            transport.add_status(VIRTIO_STATUS_FAILED)?;
            return Err(VirtioSerialError::Device);
        }

        Ok(())
    }

    fn read_device_config(&mut self) -> Result<()> {
        self.max_nr_ports = self
            .virtio
            .as_ref()
            .read_device_config(CONFIG_MAX_NR_PORTS_OFFSET)?;
        Ok(())
    }

    fn init_queues(&mut self) -> Result<()> {
        // Create a layout here used to calculate the DMA memory size may be used
        let queue_layout =
            VirtQueueLayout::new(QUEUE_SIZE as u16).ok_or(VirtioError::CreateVirtioQueue)?;

        // We have two control queues and `MAX_PORT_SUPPORTED` port queues for console device
        let queue_size = queue_layout.size() * (2 + MAX_PORT_SUPPORTED * 2);
        let queue_dma_pages = self
            .allocate_dma_memory(queue_size)
            .ok_or(VirtioSerialError::OutOfResource)?;

        // program queue receive(idx 0)
        let mut queue_address = queue_dma_pages.dma_addr;
        let port0_receiveq = Self::create_queue(
            self.virtio.as_ref(),
            PORT0_RECEIVEQ,
            queue_address,
            QUEUE_SIZE as u16,
        )?;
        self.queues.push(RefCell::new(port0_receiveq));
        self.receive_queues_prefill.push(0);

        // program queues transmit(idx 1)
        queue_address += queue_layout.size() as u64;
        let port0_transmitq = Self::create_queue(
            self.virtio.as_ref(),
            PORT0_TRANSMITQ,
            queue_address,
            QUEUE_SIZE as u16,
        )?;
        self.queues.push(RefCell::new(port0_transmitq));

        // program queue control receive(idx 2)
        queue_address += queue_layout.size() as u64;
        let control_receiveq = Self::create_queue(
            self.virtio.as_ref(),
            CONTROL_RECEIVEQ,
            queue_address,
            QUEUE_SIZE as u16,
        )?;
        self.queues.push(RefCell::new(control_receiveq));
        self.receive_queues_prefill.push(0);

        // program queue control transmit(idx 3)
        queue_address += queue_layout.size() as u64;
        let control_transmitq = Self::create_queue(
            self.virtio.as_ref(),
            CONTROL_TRANSMITQ,
            queue_address,
            QUEUE_SIZE as u16,
        )?;
        self.queues.push(RefCell::new(control_transmitq));

        // Port1 .. PortN
        for port_id in 1..MAX_PORT_SUPPORTED {
            let index = 4 + (port_id - 1) as u16 * 2;

            // program receiveq for port n (index 4 + (n - 1) * 2)
            queue_address += queue_layout.size() as u64;
            let receiveq = Self::create_queue(
                self.virtio.as_ref(),
                index,
                queue_address,
                QUEUE_SIZE as u16,
            )?;
            self.queues.push(RefCell::new(receiveq));
            self.receive_queues_prefill.push(0);

            // program transmitq for port n (index 4 + (n - 1) * 2 + 1)
            queue_address += queue_layout.size() as u64;
            let transmitq = Self::create_queue(
                self.virtio.as_ref(),
                index + 1,
                queue_address,
                QUEUE_SIZE as u16,
            )?;
            self.queues.push(RefCell::new(transmitq));
        }

        Ok(())
    }

    fn init_notification(&mut self) -> Result<()> {
        register_callback(IRQ_VECTOR, serial_event_callback)?;
        let transport = self.virtio.as_mut();

        let irq_index = transport.set_interrupt_vector(IRQ_VECTOR)?;

        Self::set_queue_notify(transport, PORT0_RECEIVEQ, irq_index)?;
        Self::set_queue_notify(transport, CONTROL_RECEIVEQ, irq_index)?;
        Self::set_queue_notify(transport, PORT0_TRANSMITQ, irq_index)?;
        Self::set_queue_notify(transport, CONTROL_TRANSMITQ, irq_index)?;

        for port_id in 1..MAX_PORT_SUPPORTED {
            let index = 4 + (port_id - 1) as u16 * 2;

            Self::set_queue_notify(transport, index, irq_index)?;
            Self::set_queue_notify(transport, index + 1, irq_index)?;
        }

        Ok(())
    }

    fn driver_ok(&mut self) -> Result<()> {
        // Report driver ready
        self.virtio.add_status(VIRTIO_STATUS_DRIVER_OK)?;

        if self.virtio.get_status()? & VIRTIO_STATUS_DRIVER_OK != VIRTIO_STATUS_DRIVER_OK {
            self.virtio.add_status(VIRTIO_STATUS_FAILED)?;
            return Err(VirtioSerialError::Device);
        }

        Ok(())
    }

    fn init_control(&mut self) -> Result<()> {
        self.fill_control_queue()?;
        self.device_ready()?;
        self.recv_control()
    }

    fn device_ready(&mut self) -> Result<()> {
        let control = VirtioConsoleControl {
            id: 0,
            event: ControlEvent::DeviceReady as u16,
            value: 1,
        };
        let _ = self.send_control(control.as_bytes())?;
        Ok(())
    }

    fn port_ready(&mut self, id: u32) -> Result<()> {
        let control = VirtioConsoleControl {
            id,
            event: ControlEvent::PortReady as u16,
            value: 1,
        };
        let _ = self.send_control(control.as_bytes())?;
        Ok(())
    }

    fn open_port(&mut self, id: u32) -> Result<()> {
        let control = VirtioConsoleControl {
            id,
            event: ControlEvent::PortOpen as u16,
            value: 1,
        };
        let _ = self.send_control(control.as_bytes())?;
        Ok(())
    }

    fn recv_control(&mut self) -> Result<()> {
        let vq = self.queues.index(CONTROL_RECEIVEQ as usize);

        self.timer
            .set_timeout(DEFAULT_TIMEOUT)
            .ok_or(VirtioSerialError::InvalidParameter)?;

        while !vq.borrow_mut().can_pop() && !self.timer.is_timeout() {
            if !wait_for_event(&IRQ_FLAG, self.timer.as_ref()) && !vq.borrow_mut().can_pop() {
                return Err(VirtioSerialError::Timeout);
            }
        }

        self.timer.reset_timeout();

        if self
            .queues
            .index(CONTROL_RECEIVEQ as usize)
            .borrow_mut()
            .can_pop()
        {
            let mut g2h = Vec::new();
            let mut h2g = Vec::new();
            let _ = self
                .queues
                .index(CONTROL_RECEIVEQ as usize)
                .borrow_mut()
                .pop_used(&mut g2h, &mut h2g)?;

            for vq_buf in &h2g {
                let control_msg = unsafe {
                    core::slice::from_raw_parts(vq_buf.addr as *const u8, vq_buf.len as usize)
                };

                self.handle_control_msg(control_msg)?;

                self.free_dma_memory(vq_buf.addr)
                    .ok_or(VirtioSerialError::OutOfResource)?;
            }
        }

        Ok(())
    }

    fn handle_control_msg(&mut self, control_msg: &[u8]) -> Result<()> {
        if control_msg.len() < size_of::<VirtioConsoleControl>() {
            return Err(VirtioSerialError::InvalidParameter);
        }

        let port_id = u32::from_le_bytes(control_msg[..4].try_into().unwrap());
        let event = ControlEvent::from(u16::from_le_bytes(control_msg[4..6].try_into().unwrap()));
        let val = u16::from_le_bytes(control_msg[6..8].try_into().unwrap());

        log::info!("Control message:\n");
        log::info!("event: {:x?}\n", event);
        log::info!("port_nr: {:x?}\n", port_id);
        log::info!("val: {:x?}\n", val);

        if port_id >= self.max_nr_ports || port_id >= MAX_PORT_SUPPORTED as u32 {
            return Err(VirtioSerialError::InvalidParameter);
        }

        match event {
            ControlEvent::DeviceAdd => {
                self.fill_port_queue(port_id)?;
                self.port_ready(port_id)?;
                self.recv_control()?;
            }
            ControlEvent::DeviceRemove => {
                self.connected_ports.remove(&port_id);
            }
            ControlEvent::PortOpen => {
                if val == 1 {
                    self.connected_ports.insert(port_id);
                    self.open_port(port_id)?;
                }
            }
            ControlEvent::ConsolePort | ControlEvent::Resize | ControlEvent::PortName => {}
            _ => return Err(VirtioSerialError::InvalidParameter),
        }

        Ok(())
    }

    fn send_control(&mut self, data: &[u8]) -> Result<usize> {
        let mut g2h = Vec::new();
        let dma = self
            .allocate_dma_memory(data.len())
            .ok_or(VirtioSerialError::OutOfResource)?;

        let dma_buf = unsafe { from_raw_parts_mut(dma.dma_addr as *mut u8, dma.dma_size) };
        dma_buf[0..data.len()].copy_from_slice(data);
        g2h.push(VirtqueueBuf::new(dma.dma_addr, data.len() as u32));

        let vq = self.queues.index(CONTROL_TRANSMITQ as usize);
        vq.borrow_mut().add(g2h.as_slice(), &[])?;
        self.kick_queue(CONTROL_TRANSMITQ)?;

        self.timer
            .set_timeout(DEFAULT_TIMEOUT)
            .ok_or(VirtioSerialError::InvalidParameter)?;

        while !vq.borrow_mut().can_pop() && !self.timer.is_timeout() {
            if !wait_for_event(&IRQ_FLAG, self.timer.as_ref()) && !vq.borrow_mut().can_pop() {
                return Err(VirtioSerialError::Timeout);
            }
        }
        self.timer.reset_timeout();

        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        let _ = vq.borrow_mut().pop_used(&mut g2h, &mut h2g)?;

        for vq_buf in &g2h {
            self.free_dma_memory(vq_buf.addr)
                .ok_or(VirtioSerialError::OutOfResource)?;
        }

        Ok(data.len())
    }

    pub fn enqueue(&mut self, data: &[u8], port_id: u32, _timeout: u32) -> Result<usize> {
        if data.is_empty() || data.len() > u32::MAX as usize {
            return Err(VirtioSerialError::InvalidParameter);
        }

        let mut g2h = Vec::new();
        let dma = self
            .allocate_dma_memory(data.len())
            .ok_or(VirtioSerialError::OutOfResource)?;

        let dma_buf = unsafe { from_raw_parts_mut(dma.dma_addr as *mut u8, dma.dma_size) };
        dma_buf[0..data.len()].copy_from_slice(data);
        g2h.push(VirtqueueBuf::new(dma.dma_addr, data.len() as u32));

        let queue_idx = Self::port_queue_index(port_id) + 1;

        let vq = self.queues.index(queue_idx as usize);
        vq.borrow_mut().add(g2h.as_slice(), &[])?;
        self.kick_queue(queue_idx)?;

        while !vq.borrow_mut().can_pop() {}

        let mut g2h = Vec::new();
        let mut h2g = Vec::new();
        let _ = vq.borrow_mut().pop_used(&mut g2h, &mut h2g)?;

        for vq_buf in &g2h {
            self.free_dma_memory(vq_buf.addr)
                .ok_or(VirtioSerialError::OutOfResource)?;
        }

        Ok(data.len())
    }

    fn port_queue_index(port_id: u32) -> u16 {
        if port_id == 0 {
            0
        } else {
            2 + port_id as u16 * 2
        }
    }

    fn fill_control_queue(&mut self) -> Result<()> {
        if self.receive_queues_prefill[CONTROL_RECEIVEQ as usize / 2] > RX_QUEUE_PREFILL_NUM / 2 {
            return Ok(());
        }

        while self.receive_queues_prefill[CONTROL_RECEIVEQ as usize / 2] < RX_QUEUE_PREFILL_NUM {
            let data_buf = self
                .allocate_dma_memory(DEFAULT_BUF_SIZE)
                .ok_or(VirtioSerialError::OutOfResource)?;

            let h2g = [VirtqueueBuf::new(
                data_buf.dma_addr,
                DEFAULT_BUF_SIZE as u32,
            )];

            let vq = self.queues.index(CONTROL_RECEIVEQ as usize);
            // A buffer chain contains a packet header buffer and a data buffer
            vq.borrow_mut().add(&[], &h2g)?;

            self.receive_queues_prefill[CONTROL_RECEIVEQ as usize / 2] += 1;
        }

        self.kick_queue(CONTROL_RECEIVEQ)
    }

    fn fill_port_queue(&mut self, port_id: u32) -> Result<()> {
        let queue_idx = Self::port_queue_index(port_id);

        let mut prefill_nr = *self.receive_queues_prefill.index(queue_idx as usize / 2);
        if prefill_nr > RX_QUEUE_PREFILL_NUM / 2 {
            return Ok(());
        }

        while prefill_nr < RX_QUEUE_PREFILL_NUM {
            let data_buf = self
                .allocate_dma_memory(DEFAULT_BUF_SIZE)
                .ok_or(VirtioSerialError::OutOfResource)?;

            let h2g = [VirtqueueBuf::new(
                data_buf.dma_addr,
                DEFAULT_BUF_SIZE as u32,
            )];

            // A buffer chain contains a packet header buffer and a data buffer
            self.queues
                .index(queue_idx as usize)
                .borrow_mut()
                .add(&[], &h2g)?;

            prefill_nr += 1;
        }

        *self
            .receive_queues_prefill
            .index_mut(queue_idx as usize / 2) = prefill_nr;

        self.kick_queue(queue_idx)
    }

    fn dequeue(&mut self, port_id: u32, _timeout: u32) -> Result<Vec<u8>> {
        if let Some(data) = Self::port_queue_pop(port_id) {
            return Ok(data);
        }

        let vq = self.queues.index(Self::port_queue_index(port_id) as usize);

        if !vq.borrow_mut().can_pop() {
            return Err(VirtioSerialError::NotReady);
        }

        self.pop_used_rx(port_id)?;
        if let Some(data) = Self::port_queue_pop(port_id) {
            Ok(data)
        } else {
            Err(VirtioSerialError::NotReady)
        }
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
        self.virtio.set_queue(queue)?;
        self.virtio.notify_queue(queue)?;

        Ok(())
    }

    fn pop_used_rx(&mut self, port_id: u32) -> Result<()> {
        let mut g2h = Vec::new();
        let mut h2g = Vec::new();

        let queue_idx = Self::port_queue_index(port_id) as usize;
        let len = self
            .queues
            .index(queue_idx)
            .borrow_mut()
            .pop_used(&mut g2h, &mut h2g)?;

        let prefill_num = self.receive_queues_prefill.index_mut(queue_idx / 2);
        if *prefill_num < h2g.len() {
            return Err(VirtioSerialError::Device);
        }
        *prefill_num -= h2g.len();

        self.receive_data(port_id, &h2g, len)?;
        self.fill_port_queue(port_id)?;

        Ok(())
    }

    fn receive_data(&mut self, port_id: u32, h2g: &[VirtqueueBuf], len: u32) -> Result<()> {
        let mut remaining = len;
        for buffer in h2g {
            if remaining == 0 {
                return Err(VirtioSerialError::InvalidParameter);
            }
            if self.dma_allocation.contains_key(&buffer.addr) {
                let dma_buf =
                    unsafe { from_raw_parts(buffer.addr as *const u8, buffer.len as usize) };

                let mut data_buf = Vec::new();
                let used_len = core::cmp::min(len, buffer.len);
                data_buf.extend_from_slice(&dma_buf[..used_len as usize]);
                remaining = remaining
                    .checked_sub(used_len)
                    .ok_or(VirtioSerialError::InvalidParameter)?;
                Self::port_queue_push(port_id, data_buf)?;

                self.free_dma_memory(buffer.addr)
                    .ok_or(VirtioSerialError::OutOfResource)?;
            }
        }

        Ok(())
    }

    fn allocate_dma_memory(&mut self, size: usize) -> Option<DmaMemoryRegion> {
        let dma_size = align_up(size);
        let dma_addr = self.dma_allocator.alloc_pages(dma_size / PAGE_SIZE)?;

        let record = DmaMemoryRegion::new(dma_addr, dma_size);
        self.dma_allocation.insert(dma_addr, record);

        Some(record)
    }

    fn free_dma_memory(&mut self, dma_addr: u64) -> Option<u64> {
        let record = self.dma_allocation.get(&dma_addr)?;

        self.dma_allocator
            .free_pages(record.dma_addr, record.dma_size / PAGE_SIZE);

        self.dma_allocation.remove(&dma_addr);
        Some(dma_addr)
    }

    fn port_queue_create(port_id: u32) -> Result<()> {
        if port_id as usize > MAX_PORT_SUPPORTED {
            return Err(VirtioSerialError::InvalidParameter);
        }

        RECEIVE_QUEUES.lock().insert(port_id, VecDeque::new());
        Ok(())
    }

    fn port_queue_delete(port_id: u32) -> Result<()> {
        if port_id as usize > MAX_PORT_SUPPORTED {
            return Err(VirtioSerialError::InvalidParameter);
        }

        RECEIVE_QUEUES.lock().remove(&port_id);
        Ok(())
    }

    fn port_queue_push(port_id: u32, buf: Vec<u8>) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        RECEIVE_QUEUES
            .lock()
            .get_mut(&port_id)
            .ok_or(VirtioSerialError::InvalidParameter)?
            .push_back(buf);
        Ok(())
    }

    fn port_queue_pop(port_id: u32) -> Option<Vec<u8>> {
        RECEIVE_QUEUES.lock().get_mut(&port_id)?.pop_front()
    }

    fn can_recv(&self, port_id: u32) -> bool {
        RECEIVE_QUEUES
            .lock()
            .get(&port_id)
            .is_some_and(|q| !q.is_empty())
            || self
                .queues
                .index(Self::port_queue_index(port_id) as usize)
                .borrow_mut()
                .can_pop()
    }
}

/// Align `size` up to a page.
pub(crate) fn align_up(size: usize) -> usize {
    (size & !(PAGE_SIZE - 1)) + if size % PAGE_SIZE != 0 { PAGE_SIZE } else { 0 }
}

fn serial_event_callback(_: &mut InterruptStack) {
    IRQ_FLAG.store(true, Ordering::SeqCst);
}
