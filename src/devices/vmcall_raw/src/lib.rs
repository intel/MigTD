// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]

extern crate alloc;

// Re-export TDX dependencies conditionally to avoid feature gates throughout the code
#[cfg(not(feature = "AzCVMEmu"))]
extern crate td_payload;
#[cfg(not(feature = "AzCVMEmu"))]
extern crate tdx_tdcall;

#[cfg(feature = "AzCVMEmu")]
extern crate td_payload_emu as td_payload;
#[cfg(feature = "AzCVMEmu")]
extern crate tdx_tdcall_emu as tdx_tdcall;

use core::fmt::{self, Display};
use rust_std_stub::{error, io};
use tdx_tdcall::TdVmcallError;

pub mod stream;
pub mod transport;

const PAGE_SIZE: usize = 0x1000;

#[derive(Debug)]
pub enum VmcallRawError {
    /// Initialization error
    Initialization,
    /// Device not available
    DeviceNotAvailable,
    /// Cannot allocate unused port
    NoAvailablePort,
    /// Port has been already used
    AddressAlreadyUsed,
    /// Tranport: device io error
    TransportError,
    /// Packet buffer is too short.
    Truncated,
    /// Packet header can not be recognized.
    Malformed,
    /// An operation is not permitted in the current state.
    Illegal,
    /// There is no listen socket on remote
    REFUSED,
    /// There is no data has been sent or received
    NotReady,
    /// Tdvmcall error
    TdVmcallErr,
    /// Interrupt error
    Interrupt,
}

impl Display for VmcallRawError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VmcallRawError::Initialization => write!(f, "Initialization"),
            VmcallRawError::DeviceNotAvailable => write!(f, "DeviceNotAvailable"),
            VmcallRawError::TransportError => write!(f, "TransportError"),
            VmcallRawError::Truncated => write!(f, "Truncated"),
            VmcallRawError::Malformed => write!(f, "Malformed"),
            VmcallRawError::Illegal => write!(f, "Illegal"),
            VmcallRawError::REFUSED => write!(f, "REFUSED"),
            VmcallRawError::NoAvailablePort => write!(f, "NoAvailablePort"),
            VmcallRawError::AddressAlreadyUsed => write!(f, "AddressAlreadyUsed"),
            VmcallRawError::NotReady => write!(f, "NotReady"),
            VmcallRawError::TdVmcallErr => write!(f, "TdVmcallErr"),
            VmcallRawError::Interrupt => write!(f, "Interrupt"),
        }
    }
}

impl From<()> for VmcallRawError {
    fn from(_: ()) -> Self {
        VmcallRawError::Illegal
    }
}

impl error::Error for VmcallRawError {}

impl From<VmcallRawError> for io::Error {
    fn from(e: VmcallRawError) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

impl From<TdVmcallError> for VmcallRawError {
    fn from(_err: TdVmcallError) -> VmcallRawError {
        VmcallRawError::TdVmcallErr
    }
}

/// Trait to allow separation of transport from block driver
pub trait VmcallRawDmaPageAllocator {
    fn alloc_pages(&self, page_num: usize) -> Option<u64>;
    fn free_pages(&self, addr: u64, page_num: usize);
}

#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct VmcallRawAddr {
    pub transport_context: u64,
}

impl VmcallRawAddr {
    pub fn new(mid: u64) -> Self {
        VmcallRawAddr {
            transport_context: mid as u64,
        }
    }

    pub fn transport_context(&self) -> u64 {
        self.transport_context as u64
    }

    pub fn set_transport_context(&mut self, mid: u64) {
        self.transport_context = mid as u64;
    }
}

impl fmt::Display for VmcallRawAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mid: {}", self.transport_context())
    }
}

impl fmt::Debug for VmcallRawAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
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
