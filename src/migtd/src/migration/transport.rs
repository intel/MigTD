// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::MigrationResult;
use crate::migration::data::MigrationInformation;

type Result<T> = core::result::Result<T, MigrationResult>;

#[cfg(feature = "vmcall-raw")]
pub(super) type TransportType = vmcall_raw::stream::VmcallRaw;

#[cfg(all(feature = "virtio-serial", not(feature = "vmcall-raw")))]
pub(super) type TransportType = virtio_serial::VirtioSerialPort;

#[cfg(all(not(feature = "virtio-serial"), not(feature = "vmcall-raw")))]
pub(super) type TransportType = vsock::stream::VsockStream;

pub(super) async fn setup_transport(info: &MigrationInformation) -> Result<TransportType> {
    #[cfg(feature = "vmcall-raw")]
    {
        use vmcall_raw::stream::VmcallRaw;
        let mut vmcall_raw_instance = VmcallRaw::new_with_mid(info.mig_info.mig_request_id)
            .map_err(|e| {
                log::error!(migration_request_id = info.mig_info.mig_request_id;
                    "exchange_msk: Failed to create vmcall_raw_instance errorcode: {:?}\n", e);
                MigrationResult::InvalidParameter
            })?;

        vmcall_raw_instance.connect().await.map_err(|e| {
            log::error!(migration_request_id = info.mig_info.mig_request_id;
                    "exchange_msk: Failed to connect vmcall_raw_instance errorcode: {:?}\n", e);
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
        let mut vsock = VsockStream::new_with_cid(
            info.mig_socket_info.mig_td_cid,
            info.mig_info.mig_request_id,
        )?;

        // Establish the vsock connection with host
        vsock
            .connect(&VsockAddr::new(
                info.mig_socket_info.mig_td_cid as u32,
                info.mig_socket_info.mig_channel_port,
            ))
            .await?;
        return Ok(vsock);
    }
}

pub(super) async fn shutdown_transport(
    transport: &mut TransportType,
    info: &MigrationInformation,
) -> Result<()> {
    #[cfg(feature = "vmcall-raw")]
    transport.shutdown().await.map_err(|e| {
        log::error!(migration_request_id = info.mig_info.mig_request_id;
            "shutdown_transport: Failed to shutdown vmcall_raw_instance errorcode: {:?}\n", e);
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
