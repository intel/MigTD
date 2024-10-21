// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::protocol::field::{FLAG_SHUTDOWN_READ, FLAG_SHUTDOWN_WRITE, HEADER_LEN};
use crate::protocol::{field, Packet};
use crate::{VsockAddr, VsockAddrPair, VsockError, VsockTransport, VSOCK_BUF_ALLOC};

use alloc::{
    boxed::Box, collections::BTreeMap, collections::BTreeSet, collections::VecDeque, vec::Vec,
};
use lazy_static::lazy_static;
use rust_std_stub::io::{self, Read, Write};
use spin::{Mutex, Once};

type Result<T = ()> = core::result::Result<T, VsockError>;

// Timeouts in millisecond
const DEFAULT_TIMEOUT: u64 = 8000;

lazy_static! {
    static ref VSOCK_DEVICE: Mutex<Once<VsockDevice>> = Mutex::new(Once::new());
    pub(crate) static ref CONNECTION_PKT_QUEUES: Mutex<BTreeMap<VsockAddrPair, VecDeque<Vec<u8>>>> =
        Mutex::new(BTreeMap::new());
    pub(crate) static ref BINDING_PKT_QUEUES: Mutex<BTreeMap<VsockAddr, VecDeque<Vec<u8>>>> =
        Mutex::new(BTreeMap::new());
}

fn add_stream_to_connection_map(stream: &VsockStream) {
    CONNECTION_PKT_QUEUES
        .lock()
        .insert(stream.addr, VecDeque::new());
}

fn remove_stream_from_connection_map(stream: &VsockStream) {
    CONNECTION_PKT_QUEUES.lock().remove(&stream.addr);
}

fn add_stream_to_binding_map(stream: &VsockStream) {
    BINDING_PKT_QUEUES
        .lock()
        .insert(stream.addr.local, VecDeque::new());
}

fn remove_stream_from_binding_map(stream: &VsockStream) {
    BINDING_PKT_QUEUES.lock().remove(&stream.addr.local);
}

pub fn register_vsock_device(dev: VsockDevice) -> Result {
    let mut vsock_device = VSOCK_DEVICE.lock();
    vsock_device.call_once(|| dev);
    vsock_device
        .get_mut()
        .ok_or(VsockError::Initialization)?
        .transport
        .init()?;
    Ok(())
}

pub struct VsockDevice {
    pub transport: Box<dyn VsockTransport>,
}

// Safety: We are in a single thread context for now
unsafe impl Send for VsockDevice {}
unsafe impl Sync for VsockDevice {}

impl VsockDevice {
    pub fn new(transport: Box<dyn VsockTransport>) -> Self {
        Self { transport }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum State {
    #[default]
    Closed,
    Listening,
    RequestSend,
    Establised,
    Closing,
}

pub struct VsockStream {
    state: State,
    listen_backlog: u32,
    addr: VsockAddrPair,
    data_queue: VecDeque<Vec<u8>>,
    rx_cnt: u32,
    tx_cnt: u32,
    peer_fwd_cnt: u32,
    peer_buf_alloc: u32,
}

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf, 0).map_err(|e| e.into())
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf, 0).map(|_| buf.len()).map_err(|e| e.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl VsockStream {
    pub fn new() -> Result<Self> {
        Ok(VsockStream {
            state: State::default(),
            listen_backlog: 0,
            addr: VsockAddrPair {
                local: VsockAddr {
                    cid: VSOCK_DEVICE
                        .lock()
                        .get_mut()
                        .ok_or(VsockError::DeviceNotAvailable)?
                        .transport
                        .get_cid()?,
                    port: get_unused_port().ok_or(VsockError::NoAvailablePort)?,
                },
                remote: VsockAddr::default(),
            },
            data_queue: VecDeque::new(),
            rx_cnt: 0,
            tx_cnt: 0,
            peer_fwd_cnt: 0,
            peer_buf_alloc: 0,
        })
    }

    pub fn bind(&mut self, addr: &VsockAddr) -> Result {
        if USED_PORT.lock().contains(&addr.port()) {
            return Err(VsockError::AddressAlreadyUsed);
        }

        USED_PORT.lock().insert(addr.port());
        self.addr.local.set_port(addr.port);
        Ok(())
    }

    pub fn listen(&mut self, backlog: u32) -> Result {
        if self.state == State::Closed {
            self.listen_backlog = backlog;
            self.state = State::Listening;

            add_stream_to_binding_map(self);

            Ok(())
        } else {
            Err(VsockError::Illegal)
        }
    }

    pub fn accept(&self) -> Result<VsockStream> {
        if self.state != State::Listening {
            return Err(VsockError::Illegal);
        }

        let recv = VSOCK_DEVICE
            .lock()
            .get_mut()
            .ok_or(VsockError::DeviceNotAvailable)?
            .transport
            .dequeue(self, DEFAULT_TIMEOUT)?;

        let packet = Packet::new_checked(recv.as_slice())?;
        if packet.op() != field::OP_REQUEST {
            return Err(VsockError::Illegal);
        }

        let request = Packet::new_checked(&recv[..field::HEADER_LEN])?;

        // Response the connect request
        let mut packet_buf = [0u8; field::HEADER_LEN];
        let mut packet = Packet::new_unchecked(&mut packet_buf[..]);
        packet.set_src_cid(self.addr.local.cid() as u64);
        packet.set_dst_cid(request.src_cid());
        packet.set_src_port(self.addr.local.port());
        packet.set_dst_port(request.src_port());
        packet.set_type(field::TYPE_STREAM);
        packet.set_op(field::OP_RESPONSE);
        packet.set_data_len(0);
        packet.set_flags(0);
        packet.set_fwd_cnt(0);
        packet.set_buf_alloc(VSOCK_BUF_ALLOC);

        let _ = VSOCK_DEVICE
            .lock()
            .get_mut()
            .ok_or(VsockError::DeviceNotAvailable)?
            .transport
            .enqueue(self, packet.as_ref(), &[], DEFAULT_TIMEOUT)?;

        let peer_addr = VsockAddr::new(request.src_cid() as u32, request.src_port());

        let new_stream = VsockStream {
            state: State::Establised,
            listen_backlog: 0,
            addr: VsockAddrPair {
                local: self.addr.local,
                remote: peer_addr,
            },
            data_queue: VecDeque::new(),
            rx_cnt: 0,
            tx_cnt: 0,
            peer_fwd_cnt: packet.fwd_cnt(),
            peer_buf_alloc: packet.buf_alloc(),
        };

        add_stream_to_connection_map(&new_stream);

        Ok(new_stream)
    }

    pub fn connect(&mut self, addr: &VsockAddr) -> Result {
        if self.state != State::Closed {
            return Err(VsockError::Illegal);
        }
        self.addr.remote = *addr;

        add_stream_to_connection_map(self);

        let mut buf = [0; HEADER_LEN];
        let mut packet = Packet::new_unchecked(&mut buf[..]);
        packet.set_src_cid(self.addr.local.cid() as u64);
        packet.set_dst_cid(self.addr.remote.cid() as u64);
        packet.set_src_port(self.addr.local.port());
        packet.set_dst_port(self.addr.remote.port());
        packet.set_type(field::TYPE_STREAM);
        packet.set_op(field::OP_REQUEST);
        packet.set_data_len(0);
        packet.set_flags(0);
        packet.set_fwd_cnt(0);
        packet.set_buf_alloc(VSOCK_BUF_ALLOC);

        let _ = VSOCK_DEVICE
            .lock()
            .get_mut()
            .ok_or(VsockError::DeviceNotAvailable)?
            .transport
            .enqueue(self, packet.as_ref(), &[], DEFAULT_TIMEOUT)?;

        self.state = State::RequestSend;
        let recv = VSOCK_DEVICE
            .lock()
            .get_mut()
            .ok_or(VsockError::DeviceNotAvailable)?
            .transport
            .dequeue(self, DEFAULT_TIMEOUT)?;

        let packet = Packet::new_checked(recv.as_slice())?;

        if packet.r#type() == field::TYPE_STREAM
            && packet.dst_cid() == self.addr.local.cid() as u64
            && packet.dst_port() == self.addr.local.port()
            && packet.op() == field::OP_RESPONSE
            && packet.src_port() == self.addr.remote.port()
            && packet.src_cid() == self.addr.remote.cid() as u64
        {
            self.state = State::Establised;
            self.peer_buf_alloc = packet.buf_alloc();
            self.peer_fwd_cnt = packet.fwd_cnt();
            Ok(())
        } else {
            Err(VsockError::REFUSED)
        }
    }

    pub fn shutdown(&mut self) -> Result {
        if self.state == State::Listening {
            self.state = State::Closed;
            remove_stream_from_binding_map(self);
            Ok(())
        } else if self.state == State::Establised {
            let mut buf = [0; HEADER_LEN];
            let mut packet = Packet::new_unchecked(&mut buf[..]);
            packet.set_src_cid(self.addr.local.cid() as u64);
            packet.set_dst_cid(self.addr.remote.cid() as u64);
            packet.set_src_port(self.addr.local.port());
            packet.set_dst_port(self.addr.remote.port());
            packet.set_type(field::TYPE_STREAM);
            packet.set_op(field::OP_SHUTDOWN);
            packet.set_data_len(0);
            packet.set_flags(FLAG_SHUTDOWN_READ | FLAG_SHUTDOWN_WRITE);
            packet.set_fwd_cnt(self.rx_cnt);
            packet.set_buf_alloc(VSOCK_BUF_ALLOC);
            let _ = VSOCK_DEVICE
                .lock()
                .get_mut()
                .ok_or(VsockError::DeviceNotAvailable)?
                .transport
                .enqueue(self, packet.as_ref(), &[], DEFAULT_TIMEOUT)?;

            self.state = State::Closing;
            self.reset()
        } else {
            Err(VsockError::Illegal)
        }
    }

    pub fn send(&mut self, buf: &[u8], _flags: u32) -> Result<usize> {
        let state = self.state;
        if state != State::Establised {
            return Err(VsockError::Illegal);
        }

        while self.has_free_space() == 0 {
            self.recv_packet_connected()?;
        }

        let mut header_buf = [0u8; HEADER_LEN];
        let mut packet = Packet::new_unchecked(&mut header_buf[..]);
        packet.set_src_cid(self.addr.local.cid() as u64);
        packet.set_dst_cid(self.addr.remote.cid() as u64);
        packet.set_src_port(self.addr.local.port());
        packet.set_dst_port(self.addr.remote.port());
        packet.set_type(field::TYPE_STREAM);
        packet.set_op(field::OP_RW);
        packet.set_data_len(buf.len() as u32);
        packet.set_flags(0);
        packet.set_fwd_cnt(self.rx_cnt);
        packet.set_buf_alloc(VSOCK_BUF_ALLOC);
        let _ = VSOCK_DEVICE
            .lock()
            .get_mut()
            .ok_or(VsockError::DeviceNotAvailable)?
            .transport
            .enqueue(self, packet.as_ref(), buf, DEFAULT_TIMEOUT)?;
        self.tx_cnt += buf.len() as u32;

        Ok(buf.len())
    }

    pub fn recv(&mut self, buf: &mut [u8], _flags: u32) -> Result<usize> {
        let state = self.state;
        if state != State::Establised {
            return Err(VsockError::Illegal);
        }

        if self.data_queue.is_empty() {
            loop {
                self.recv_packet_connected()?;

                // If there are received vsock packets, continue to pop them out and insert to the
                // `data_queue`. If there is no vsock packet left in the device, break the loop.
                if !VSOCK_DEVICE
                    .lock()
                    .get_mut()
                    .ok_or(VsockError::DeviceNotAvailable)?
                    .transport
                    .can_recv()
                {
                    break;
                }
            }
        }

        let mut used = 0;
        while !self.data_queue.is_empty() && used < buf.len() {
            let head = self.data_queue.front_mut().unwrap();
            let free = buf.len() - used;
            if head.len() <= free {
                buf[used..used + head.len()].copy_from_slice(head);
                used += head.len();
                self.data_queue.pop_front();
            } else {
                buf[used..].copy_from_slice(&head[..free]);
                used += free;
                head.drain(..free);
            }
        }

        Ok(used)
    }

    fn reset(&mut self) -> Result {
        if self.state == State::Closing {
            let recv = VSOCK_DEVICE
                .lock()
                .get_mut()
                .ok_or(VsockError::DeviceNotAvailable)?
                .transport
                .dequeue(self, DEFAULT_TIMEOUT)?;
            let packet = Packet::new_checked(recv.as_slice())?;
            if packet.op() == field::OP_RST {
                let mut buf = [0; HEADER_LEN];
                let mut packet = Packet::new_unchecked(&mut buf[..]);
                packet.set_src_cid(self.addr.local.cid() as u64);
                packet.set_dst_cid(self.addr.remote.cid() as u64);
                packet.set_src_port(self.addr.local.port());
                packet.set_dst_port(self.addr.remote.port());
                packet.set_type(field::TYPE_STREAM);
                packet.set_op(field::OP_RST);
                packet.set_data_len(0);
                packet.set_flags(0);
                packet.set_fwd_cnt(self.rx_cnt);
                packet.set_buf_alloc(VSOCK_BUF_ALLOC);

                let _ = VSOCK_DEVICE
                    .lock()
                    .get_mut()
                    .ok_or(VsockError::DeviceNotAvailable)?
                    .transport
                    .enqueue(self, packet.as_ref(), &[], DEFAULT_TIMEOUT)?;
                self.state = State::Closed;

                remove_stream_from_connection_map(self);
                Ok(())
            } else {
                self.state = State::Closing;
                Ok(())
            }
        } else {
            Err(VsockError::Illegal)
        }
    }

    fn recv_packet_connected(&mut self) -> Result<()> {
        let recv = VSOCK_DEVICE
            .lock()
            .get_mut()
            .ok_or(VsockError::DeviceNotAvailable)?
            .transport
            .dequeue(self, DEFAULT_TIMEOUT)?;
        let packet = Packet::new_checked(recv.as_slice())?;

        self.peer_buf_alloc = packet.buf_alloc();
        self.peer_fwd_cnt = packet.fwd_cnt();
        match packet.op() {
            field::OP_SHUTDOWN => {
                self.shutdown()?;
            }
            field::OP_RST => {
                self.reset()?;
                return Err(VsockError::Illegal);
            }
            field::OP_RW => {
                if packet.data_len() > 0 {
                    let mut recv = VSOCK_DEVICE
                        .lock()
                        .get_mut()
                        .ok_or(VsockError::DeviceNotAvailable)?
                        .transport
                        .dequeue(self, DEFAULT_TIMEOUT)?;

                    self.rx_cnt += packet.data_len();
                    if packet.data_len() as usize <= recv.len() {
                        recv.truncate(packet.data_len() as usize);
                    } else {
                        return Err(VsockError::Illegal);
                    }

                    self.data_queue.push_back(recv);
                }
            }
            field::OP_CREDIT_UPDATE => {
                self.peer_fwd_cnt = packet.fwd_cnt();
                self.peer_buf_alloc = packet.buf_alloc();
            }
            field::OP_CREDIT_REQUEST => {
                self.send_credit_update()?;
            }
            _ => return Err(VsockError::Illegal),
        }
        Ok(())
    }

    fn send_credit_update(&self) -> Result<()> {
        let mut header_buf = [0u8; HEADER_LEN];
        let mut packet = Packet::new_unchecked(&mut header_buf[..]);
        packet.set_src_cid(self.addr.local.cid() as u64);
        packet.set_dst_cid(self.addr.remote.cid() as u64);
        packet.set_src_port(self.addr.local.port());
        packet.set_dst_port(self.addr.remote.port());
        packet.set_type(field::TYPE_STREAM);
        packet.set_op(field::OP_CREDIT_UPDATE);
        packet.set_data_len(0);
        packet.set_flags(0);
        packet.set_fwd_cnt(self.rx_cnt);
        packet.set_buf_alloc(VSOCK_BUF_ALLOC);
        let _ = VSOCK_DEVICE
            .lock()
            .get_mut()
            .ok_or(VsockError::DeviceNotAvailable)?
            .transport
            .enqueue(self, packet.as_ref(), &[], DEFAULT_TIMEOUT)?;
        Ok(())
    }

    fn has_free_space(&self) -> u32 {
        self.peer_buf_alloc
            .saturating_sub(self.tx_cnt.saturating_sub(self.peer_fwd_cnt))
    }

    pub(crate) fn addr(&self) -> VsockAddrPair {
        self.addr
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

lazy_static! {
    static ref UNUSED_PORT_COUNTER: Mutex<u32> = Mutex::new(40000);
    static ref USED_PORT: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());
}

pub fn get_unused_port() -> Option<u32> {
    let mut port = UNUSED_PORT_COUNTER.lock().checked_add(1)?;

    while USED_PORT.lock().contains(&port) {
        port = port.checked_add(1)?;
    }

    USED_PORT.lock().insert(port);
    *UNUSED_PORT_COUNTER.lock() = port;

    Some(port)
}
