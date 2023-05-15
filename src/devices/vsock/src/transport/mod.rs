// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use cfg_if::cfg_if;
use core::fmt::{self, Display};
use rust_std_stub::error;
#[cfg(feature = "vmcall-vsock")]
use tdx_tdcall::TdVmcallError;
#[cfg(feature = "virtio-vsock")]
use virtio::VirtioError;

mod event;
cfg_if! {
    if #[cfg(feature = "vmcall-vsock")] {
        mod vmcall;
        pub use vmcall::*;
    } else if #[cfg(feature = "virtio-vsock")] {
        mod virtio_pci;
        pub use virtio_pci::*;
    }
}

type Result<T> = core::result::Result<T, VsockTransportError>;

#[derive(Debug)]
pub enum VsockTransportError {
    #[cfg(feature = "virtio-vsock")]
    Virtio(VirtioError),
    #[cfg(feature = "vmcall-vsock")]
    Vmcall(TdVmcallError),
    CreateVirtQueue,
    Initilization,
    DmaAllocation,
    Timeout,
    InvalidParameter,
    InvalidVsockPacket,
}

impl Display for VsockTransportError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VsockTransportError::InvalidParameter => write!(f, "InvalidParameter"),
            VsockTransportError::InvalidVsockPacket => write!(f, "InvalidVsockPacket"),
            VsockTransportError::CreateVirtQueue => write!(f, "CreateVirtQueue"),
            VsockTransportError::Initilization => write!(f, "Initilization"),
            VsockTransportError::DmaAllocation => write!(f, "DmaAllocation"),
            VsockTransportError::Timeout => write!(f, "Timeout"),
            #[cfg(feature = "virtio-vsock")]
            VsockTransportError::Virtio(e) => write!(f, "Virtio: {}", e),
            #[cfg(feature = "vmcall-vsock")]
            VsockTransportError::Vmcall(_) => write!(f, "Vmcall"),
        }
    }
}

impl error::Error for VsockTransportError {}

#[cfg(feature = "virtio-vsock")]
impl From<VirtioError> for VsockTransportError {
    fn from(e: VirtioError) -> Self {
        VsockTransportError::Virtio(e)
    }
}
