// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
#![cfg_attr(not(test), no_std)]

extern crate alloc;
use core::fmt::Display;
use mem::MemoryRegionError;
use pci::PciError;

pub mod consts;
mod mem;
pub mod virtio_pci;
pub mod virtqueue;

const PAGE_SIZE: usize = 0x1000;

/// Virtio errors
#[derive(Debug)]
pub enum VirtioError {
    /// Virtio device not support.
    VirtioUnsupportedDevice,
    /// Virtio legacy device only.
    VirtioLegacyOnly,
    /// Virtio device negotiation failed.
    VirtioFeatureNegotiationFailed,
    /// VirtioQueue is too small.
    CreateVirtioQueue,
    /// The buffer is too small.
    BufferTooSmall,
    /// The device is not ready.
    NotReady,
    /// The queue is already in use.
    AlreadyUsed,
    /// Invalid parameter.
    InvalidParameter,
    /// I/O Error
    IoError,
    /// Bad Ring
    BadRing,
    /// Set device notification
    SetDeviceNotification,
    /// Invalid device MMIO offset
    InvalidOffset(MemoryRegionError),
    /// Invalid index for descriptor table
    InvalidDescriptorIndex,
    /// Invalid index for ring
    InvalidRingIndex,
    /// Invalid index for ring
    InvalidDescriptor,
    /// Pci related error
    Pci(PciError),
}

impl Display for VirtioError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            VirtioError::VirtioUnsupportedDevice => write!(f, "VirtioUnsupportedDevice"),
            VirtioError::VirtioLegacyOnly => write!(f, "VirtioLegacyOnly"),
            VirtioError::VirtioFeatureNegotiationFailed => {
                write!(f, "VirtioFeatureNegotiationFailed")
            }
            VirtioError::CreateVirtioQueue => write!(f, "CreateVirtioQueue"),
            VirtioError::BufferTooSmall => write!(f, "BufferTooSmall"),
            VirtioError::NotReady => write!(f, "NotReady"),
            VirtioError::AlreadyUsed => write!(f, "AlreadyUsed"),
            VirtioError::InvalidParameter => write!(f, "InvalidParameter"),
            VirtioError::IoError => write!(f, "IoError"),
            VirtioError::BadRing => write!(f, "BadRing"),
            VirtioError::SetDeviceNotification => write!(f, "SetDeviceNotification"),
            VirtioError::InvalidOffset(e) => write!(f, "InvalidOffset: {}", e),
            VirtioError::InvalidDescriptorIndex => write!(f, "InvalidDescriptorIndex"),
            VirtioError::InvalidRingIndex => write!(f, "InvalidRingIndex"),
            VirtioError::InvalidDescriptor => write!(f, "InvalidDescriptor"),
            VirtioError::Pci(_) => write!(f, "Pci"),
        }
    }
}

impl From<mem::MemoryRegionError> for VirtioError {
    fn from(e: mem::MemoryRegionError) -> Self {
        VirtioError::InvalidOffset(e)
    }
}

impl From<PciError> for VirtioError {
    fn from(e: PciError) -> Self {
        VirtioError::Pci(e)
    }
}

pub type Result<T = ()> = core::result::Result<T, VirtioError>;

/// Trait to allow separation of transport from block driver
pub trait VirtioTransport {
    fn init(&mut self, device_type: u32) -> Result<()>;
    fn get_status(&self) -> Result<u8>;
    fn set_status(&self, status: u8) -> Result<()>;
    fn add_status(&self, status: u8) -> Result<()>;
    fn reset(&self) -> Result<()>;
    fn get_features(&self) -> Result<u64>;
    fn set_features(&self, features: u64) -> Result<()>;
    fn set_queue(&self, queue: u16) -> Result<()>;
    fn get_queue_max_size(&self) -> Result<u16>;
    fn set_queue_size(&self, queue_size: u16) -> Result<()>;
    fn set_descriptors_address(&self, address: u64) -> Result<()>;
    fn set_avail_ring(&self, address: u64) -> Result<()>;
    fn set_used_ring(&self, address: u64) -> Result<()>;
    fn set_queue_enable(&self) -> Result<()>;
    fn set_interrupt_vector(&mut self, vector: u8) -> Result<u16>;
    fn set_config_notify(&mut self, index: u16) -> Result<()>;
    fn set_queue_notify(&mut self, index: u16) -> Result<()>;
    fn notify_queue(&self, queue: u16) -> Result<()>;
    fn read_device_config(&self, offset: u64) -> Result<u32>;
}
