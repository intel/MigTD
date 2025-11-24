// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]

extern crate alloc;
use alloc::vec::Vec;
use core::fmt::{self, Display};
use rust_std_stub::{error, io};
use stream::VsockStream;

pub mod protocol;
pub mod stream;
pub mod transport;
#[allow(dead_code)]
pub(crate) mod virtio_dump;

use transport::*;

const PAGE_SIZE: usize = 0x1000;
const VSOCK_BUF_ALLOC: u32 = 0x40000;

#[derive(Debug)]
pub enum VsockError {
    /// Initialization error
    Initialization,
    /// Device not available
    DeviceNotAvailable,
    /// Cannot allocate unused port
    NoAvailablePort,
    /// Port has been already used
    AddressAlreadyUsed,
    /// Tranport: device io error
    Transport(VsockTransportError),
    /// Packet buffer is too short.
    Truncated,
    /// Packet header can not be recognized.
    Malformed,
    /// VsockStream
    /// An operation is not permitted in the current state.
    Illegal,
    /// There is no listen socket on remote
    REFUSED,
    /// There is no data has been sent or received
    NotReady,
}

impl Display for VsockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VsockError::Initialization => write!(f, "Initialization"),
            VsockError::DeviceNotAvailable => write!(f, "DeviceNotAvailable"),
            VsockError::Transport(e) => write!(f, "Transport: {e}"),
            VsockError::Truncated => write!(f, "Truncated"),
            VsockError::Malformed => write!(f, "Malformed"),
            VsockError::Illegal => write!(f, "Illegal"),
            VsockError::REFUSED => write!(f, "REFUSED"),
            VsockError::NoAvailablePort => write!(f, "NoAvailablePort"),
            VsockError::AddressAlreadyUsed => write!(f, "AddressAlreadyUsed"),
            VsockError::NotReady => write!(f, "NotReady"),
        }
    }
}

impl error::Error for VsockError {}

impl From<VsockError> for io::Error {
    fn from(e: VsockError) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

impl From<VsockTransportError> for VsockError {
    fn from(e: VsockTransportError) -> Self {
        match e {
            VsockTransportError::NotReady => VsockError::NotReady,
            _ => Self::Transport(e),
        }
    }
}

/// Trait to allow separation of transport from block driver
pub trait VsockTransport {
    fn get_cid(&self) -> core::result::Result<u64, VsockTransportError>;
    fn init(&mut self) -> core::result::Result<(), VsockTransportError>;
    fn enqueue(
        &mut self,
        stream: &VsockStream,
        hdr: &[u8],
        data: &[u8],
        timeout: u32,
    ) -> core::result::Result<usize, VsockTransportError>;
    fn dequeue(
        &mut self,
        stream: &VsockStream,
        timeout: u32,
    ) -> core::result::Result<Vec<u8>, VsockTransportError>;
    fn can_send(&self) -> bool;
    fn can_recv(&self) -> bool;
}

/// Trait to allow separation of transport from block driver
pub trait VsockDmaPageAllocator {
    fn alloc_pages(&self, page_num: usize) -> Option<u64>;
    fn free_pages(&self, addr: u64, page_num: usize);
}

#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct VsockAddr {
    cid: u64,
    port: u32,
}

impl VsockAddr {
    pub fn new(cid: u32, port: u32) -> Self {
        VsockAddr {
            cid: cid as u64,
            port,
        }
    }

    pub fn cid(&self) -> u32 {
        self.cid as u32
    }

    pub fn port(&self) -> u32 {
        self.port
    }

    pub fn set_cid(&mut self, cid: u32) {
        self.cid = cid as u64;
    }

    pub fn set_port(&mut self, port: u32) {
        self.port = port;
    }
}

impl fmt::Display for VsockAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cid: {} port: {}", self.cid(), self.port())
    }
}

impl fmt::Debug for VsockAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Debug)]
pub(crate) struct VsockAddrPair {
    pub local: VsockAddr,
    pub remote: VsockAddr,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    Closed,
    Listen,
    RequestSend,
    Establised,
    Closing,
}

/// Align `size` up to a page.
pub(crate) fn align_up(size: usize) -> usize {
    (size & !(PAGE_SIZE - 1)) + if size % PAGE_SIZE != 0 { PAGE_SIZE } else { 0 }
}
