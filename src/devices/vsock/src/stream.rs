// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::protocol::field::{FLAG_SHUTDOWN_READ, FLAG_SHUTDOWN_WRITE, HEADER_LEN};
use crate::protocol::{field, Packet};
use crate::{
    vsock_transport_can_recv, vsock_transport_dequeue, vsock_transport_enqueue,
    vsock_transport_get_cid, VsockAddr, VsockAddrPair, VsockError, MAX_VSOCK_PKT_DATA_LEN,
    VSOCK_BUF_ALLOC,
};

use alloc::{collections::BTreeMap, collections::BTreeSet, collections::VecDeque, vec::Vec};
use async_io::{AsyncRead, AsyncWrite};
use lazy_static::lazy_static;
use rust_std_stub::io;
use spin::Mutex;

type Result<T = ()> = core::result::Result<T, VsockError>;

// Timeouts in millisecond
const DEFAULT_TIMEOUT: u32 = 8000;

lazy_static! {
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
    transport_context: u64,
    listen_backlog: u32,
    addr: VsockAddrPair,
    data_queue: VecDeque<Vec<u8>>,
    rx_cnt: u32,
    tx_cnt: u32,
    last_fwd_cnt: u32,
    peer_fwd_cnt: u32,
    peer_buf_alloc: u32,
}

impl AsyncRead for VsockStream {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf, 0).await.map_err(|e| e.into())
    }
}

impl AsyncWrite for VsockStream {
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf, 0).await.map_err(|e| e.into())
    }
}

impl VsockStream {
    pub fn new() -> Result<Self> {
        VsockStream::new_with_cid(vsock_transport_get_cid()?, 0)
    }

    pub fn new_with_cid(cid: u64, transport_context: u64) -> Result<Self> {
        Ok(VsockStream {
            state: State::default(),
            listen_backlog: 0,
            addr: VsockAddrPair {
                local: VsockAddr {
                    cid,
                    port: get_unused_port().ok_or(VsockError::NoAvailablePort)?,
                },
                remote: VsockAddr::default(),
            },
            data_queue: VecDeque::new(),
            rx_cnt: 0,
            tx_cnt: 0,
            last_fwd_cnt: 0,
            peer_fwd_cnt: 0,
            peer_buf_alloc: 0,
            transport_context,
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

    pub async fn accept(&mut self) -> Result<VsockStream> {
        if self.state != State::Listening {
            return Err(VsockError::Illegal);
        }

        let recv = vsock_transport_dequeue(self, DEFAULT_TIMEOUT).await?;

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

        let _ = self.send_vsock_pkt(packet.as_ref(), &[]).await?;

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
            last_fwd_cnt: 0,
            peer_fwd_cnt: packet.fwd_cnt(),
            peer_buf_alloc: packet.buf_alloc(),
            transport_context: 0,
        };

        add_stream_to_connection_map(&new_stream);

        Ok(new_stream)
    }

    pub async fn connect(&mut self, addr: &VsockAddr) -> Result {
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

        let _ = self.send_vsock_pkt(packet.as_ref(), &[]).await?;

        self.state = State::RequestSend;
        let recv = vsock_transport_dequeue(self, DEFAULT_TIMEOUT).await?;

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

    pub async fn shutdown(&mut self) -> Result {
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
            let _ = self.send_vsock_pkt(packet.as_ref(), &[]).await?;

            self.state = State::Closing;
            self.reset().await
        } else {
            Err(VsockError::Illegal)
        }
    }

    pub async fn send(&mut self, buf: &[u8], _flags: u32) -> Result<usize> {
        let state = self.state;
        if state != State::Establised {
            return Err(VsockError::Illegal);
        }

        let total_len = buf.len();
        let mut bytes_sent = 0;

        // If the buffer size is larger than the max packet size or the free space size,
        // truncate it into multiple packets.
        while bytes_sent < total_len {
            // Wait for available send buffer space
            while self.peer_free_space() == 0 {
                self.recv_packet_connected().await?;
            }

            // Determine how much data to send in this packet
            let remaining = total_len - bytes_sent;
            let available_space = self.peer_free_space() as usize;
            let chunk_size = remaining.min(MAX_VSOCK_PKT_DATA_LEN).min(available_space);

            let mut header_buf = [0u8; HEADER_LEN];
            let mut packet = Packet::new_unchecked(&mut header_buf[..]);
            packet.set_src_cid(self.addr.local.cid() as u64);
            packet.set_dst_cid(self.addr.remote.cid() as u64);
            packet.set_src_port(self.addr.local.port());
            packet.set_dst_port(self.addr.remote.port());
            packet.set_type(field::TYPE_STREAM);
            packet.set_op(field::OP_RW);
            packet.set_data_len(chunk_size as u32);
            packet.set_flags(0);
            packet.set_fwd_cnt(self.rx_cnt);
            packet.set_buf_alloc(VSOCK_BUF_ALLOC);

            let n = self
                .send_vsock_pkt(packet.as_ref(), &buf[bytes_sent..bytes_sent + chunk_size])
                .await?;
            self.tx_cnt += n as u32;
            bytes_sent += n;
        }

        Ok(total_len)
    }

    pub async fn recv(&mut self, buf: &mut [u8], _flags: u32) -> Result<usize> {
        let state = self.state;
        if state != State::Establised {
            return Err(VsockError::Illegal);
        }

        while self.data_queue.is_empty() {
            loop {
                self.recv_packet_connected().await?;

                // If there are received vsock packets, continue to pop them out and insert to the
                // `data_queue`. If there is no vsock packet left in the device, break the loop.
                if !vsock_transport_can_recv()? {
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

    pub fn transport_context(&self) -> u64 {
        self.transport_context
    }

    pub fn set_transport_context(&mut self, context: u64) {
        self.transport_context = context
    }

    async fn reset(&mut self) -> Result {
        if self.state == State::Closing {
            let recv = vsock_transport_dequeue(self, DEFAULT_TIMEOUT).await?;
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

                let _ = self.send_vsock_pkt(packet.as_ref(), &[]).await?;
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

    async fn recv_packet_connected(&mut self) -> Result<()> {
        let recv = vsock_transport_dequeue(self, DEFAULT_TIMEOUT).await?;
        let packet = Packet::new_checked(recv.as_slice())?;

        self.peer_buf_alloc = packet.buf_alloc();
        self.peer_fwd_cnt = packet.fwd_cnt();
        match packet.op() {
            field::OP_SHUTDOWN => {
                self.shutdown().await?;
            }
            field::OP_RST => {
                self.reset().await?;
                return Err(VsockError::Illegal);
            }
            field::OP_RW => {
                if packet.data_len() > 0 {
                    let mut recv = vsock_transport_dequeue(self, DEFAULT_TIMEOUT).await?;

                    self.rx_cnt += packet.data_len();
                    if packet.data_len() as usize <= recv.len() {
                        recv.truncate(packet.data_len() as usize);
                    } else {
                        return Err(VsockError::Illegal);
                    }

                    // Send credit update if the free space is less than a max packet size
                    if self.free_space() < MAX_VSOCK_PKT_DATA_LEN as u32 {
                        self.send_credit_update().await?;
                    }

                    self.data_queue.push_back(recv);
                }
            }
            field::OP_CREDIT_UPDATE => {
                self.peer_fwd_cnt = packet.fwd_cnt();
                self.peer_buf_alloc = packet.buf_alloc();
            }
            field::OP_CREDIT_REQUEST => {
                self.send_credit_update().await?;
            }
            _ => return Err(VsockError::Illegal),
        }
        Ok(())
    }

    async fn send_credit_update(&mut self) -> Result<()> {
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
        let _ = self.send_vsock_pkt(packet.as_ref(), &[]).await?;
        Ok(())
    }

    async fn send_vsock_pkt(&mut self, packet_header: &[u8], data: &[u8]) -> Result<usize> {
        self.last_fwd_cnt = self.rx_cnt;
        vsock_transport_enqueue(self, packet_header, data, DEFAULT_TIMEOUT)
            .await
            .map_err(|e| e.into())
    }

    fn peer_free_space(&self) -> u32 {
        self.peer_buf_alloc
            .saturating_sub(self.tx_cnt.saturating_sub(self.peer_fwd_cnt))
    }

    fn free_space(&self) -> u32 {
        VSOCK_BUF_ALLOC.saturating_sub(self.rx_cnt.saturating_sub(self.last_fwd_cnt))
    }

    pub(crate) fn addr(&self) -> VsockAddrPair {
        self.addr
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
