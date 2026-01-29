// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::MigrationResult;
use alloc::vec::Vec;

type Result<T> = core::result::Result<T, MigrationResult>;

#[cfg(feature = "vmcall-raw")]
pub(super) type TransportType = vmcall_raw::stream::VmcallRaw;

#[cfg(all(feature = "virtio-serial", not(feature = "vmcall-raw")))]
pub(super) type TransportType = virtio_serial::VirtioSerialPort;

#[cfg(all(not(feature = "virtio-serial"), not(feature = "vmcall-raw")))]
pub(super) type TransportType = vsock::stream::VsockStream;

pub(super) async fn setup_transport(
    mig_request_id: u64,
    #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))] migtd_cid: u64,
    #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))] mig_channel_port: u32,
    data: &mut Vec<u8>,
) -> Result<TransportType> {
    #[cfg(not(feature = "vmcall-raw"))]
    let _ = data;

    #[cfg(feature = "vmcall-raw")]
    {
        use vmcall_raw::stream::VmcallRaw;
        let mut vmcall_raw_instance = VmcallRaw::new_with_mid(mig_request_id)
            .map_err(|e| {
                data.extend_from_slice(&format!("Error: exchange_msk(): Failed to create vmcall_raw_instance with Migration ID: {:x} errorcode: {}\n", mig_request_id, e).into_bytes());
                log::error!("exchange_msk: Failed to create vmcall_raw_instance with Migration ID: {} errorcode: {:?}\n", mig_request_id, e);
                MigrationResult::InvalidParameter
        })?;

        vmcall_raw_instance
            .connect()
            .await
            .map_err(|e| {
                data.extend_from_slice(&format!("Error: exchange_msk(): Failed to connect vmcall_raw_instance with Migration ID: {:x} errorcode: {}\n", mig_request_id, e).into_bytes());
                log::error!("exchange_msk: Failed to connect vmcall_raw_instance with Migration ID: {} errorcode: {:?}\n", mig_request_id, e);
                MigrationResult::InvalidParameter
            })?;
        return Ok(vmcall_raw_instance);
    }

    #[cfg(all(feature = "virtio-serial", not(feature = "vmcall-raw")))]
    {
        use virtio_serial::VirtioSerialPort;
        const VIRTIO_SERIAL_PORT_ID: u32 = 1;

        let port = VirtioSerialPort::new(VIRTIO_SERIAL_PORT_ID);
        port.open()?;
        return Ok(port);
    }

    #[cfg(all(not(feature = "virtio-serial"), not(feature = "vmcall-raw")))]
    {
        use vsock::{stream::VsockStream, VsockAddr};

        #[cfg(feature = "virtio-vsock")]
        let mut vsock = VsockStream::new()?;

        #[cfg(feature = "vmcall-vsock")]
        let mut vsock = VsockStream::new_with_cid(migtd_cid, mig_request_id)?;

        // Establish the vsock connection with host
        vsock
            .connect(&VsockAddr::new(migtd_cid as u32, mig_channel_port))
            .await?;
        return Ok(vsock);
    }
}

pub(super) async fn shutdown_transport(
    transport: &mut TransportType,
    mig_request_id: u64,
    data: &mut Vec<u8>,
) -> Result<()> {
    #[cfg(not(feature = "vmcall-raw"))]
    let _ = data;

    #[cfg(feature = "vmcall-raw")]
    transport.shutdown().await.map_err(|e| {
        data.extend_from_slice(
            &format!(
                "Error: shutdown_transport(): Failed to transport in vmcall_raw_instance with Migration ID: {:x} errorcode: {}\n",
                mig_request_id,
                e
            )
            .into_bytes(),
        );
        log::error!(
            "shutdown_transport: Failed to transport in vmcall_raw_instance with Migration ID: {} errorcode: {}",
            mig_request_id,
            e
        );
        MigrationResult::InvalidParameter
    })?;

    #[cfg(all(feature = "virtio-serial", not(feature = "vmcall-raw")))]
    transport.close().map_err(|e| {
        log::error!("shutdown_transport: virtio_serial close error: {:?}\n", e);
        MigrationResult::InvalidParameter
    })?;

    #[cfg(all(not(feature = "virtio-serial"), not(feature = "vmcall-raw")))]
    transport.shutdown().await.map_err(|e| {
        log::error!("shutdown_transport: vsock shutdown error: {:?}\n", e);
        MigrationResult::InvalidParameter
    })?;

    Ok(())
}
