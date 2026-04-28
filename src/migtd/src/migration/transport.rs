// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::MigrationResult;

type Result<T> = core::result::Result<T, MigrationResult>;

#[cfg(feature = "vmcall-raw")]
pub(super) type TransportType = vmcall_raw::stream::VmcallRaw;

#[cfg(all(feature = "virtio-serial", not(feature = "vmcall-raw")))]
pub(super) type TransportType = virtio_serial::VirtioSerialPort;

#[cfg(all(not(feature = "virtio-serial"), not(feature = "vmcall-raw")))]
pub(super) type TransportType = vsock::stream::VsockStream;

pub(super) async fn setup_transport(
    _mig_request_id: u64,
    #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))] migtd_cid: u64,
    #[cfg(any(feature = "vmcall-vsock", feature = "virtio-vsock"))] mig_channel_port: u32,
) -> Result<TransportType> {
    #[cfg(feature = "vmcall-raw")]
    {
        use vmcall_raw::stream::VmcallRaw;
        let mut vmcall_raw_instance = VmcallRaw::new_with_mid(_mig_request_id).map_err(|e| {
            log::error!(migration_request_id = _mig_request_id;
                    "exchange_msk: Failed to create vmcall_raw_instance errorcode: {:?}\n", e);
            MigrationResult::InvalidParameter
        })?;

        vmcall_raw_instance.connect().await.map_err(|e| {
            log::error!(migration_request_id = _mig_request_id;
                    "exchange_msk: Failed to connect vmcall_raw_instance errorcode: {:?}\n", e);
            MigrationResult::InvalidParameter
        })?;
        return Ok(vmcall_raw_instance);
    }

    #[cfg(all(feature = "virtio-serial", not(feature = "vmcall-raw")))]
    {
        use crate::driver::ticks::Timer;
        use core::time::Duration;
        use virtio_serial::{VirtioSerial, VirtioSerialError, VirtioSerialPort};
        const VIRTIO_SERIAL_PORT_ID: u32 = 1;
        const VIRTIO_SERIAL_OPEN_RETRY_TIMES: usize = 100;
        const VIRTIO_SERIAL_OPEN_RETRY_DELAY: Duration = Duration::from_millis(10);

        let port = VirtioSerialPort::new(VIRTIO_SERIAL_PORT_ID);
        let mut opened = false;
        for _ in 0..VIRTIO_SERIAL_OPEN_RETRY_TIMES {
            match port.open() {
                Ok(()) => {
                    opened = true;
                    break;
                }
                Err(VirtioSerialError::PortNotAvailable(_)) => {
                    // `PORT_OPEN` can arrive after init_control; pump control queue during retry.
                    // If we drained pending control msgs, try open again immediately to avoid
                    // waiting for the next retry tick.
                    Timer::after(VIRTIO_SERIAL_OPEN_RETRY_DELAY).await;
                    VirtioSerial::try_poll_control()?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        if !opened {
            log::error!(
                "virtio-serial port {} not available after {} retries ({}ms total)\n",
                VIRTIO_SERIAL_PORT_ID,
                VIRTIO_SERIAL_OPEN_RETRY_TIMES,
                VIRTIO_SERIAL_OPEN_RETRY_TIMES
                    * VIRTIO_SERIAL_OPEN_RETRY_DELAY.as_millis() as usize,
            );
            return Err(VirtioSerialError::PortNotAvailable(VIRTIO_SERIAL_PORT_ID).into());
        }
        return Ok(port);
    }

    #[cfg(all(not(feature = "virtio-serial"), not(feature = "vmcall-raw")))]
    {
        use vsock::{stream::VsockStream, VsockAddr};

        #[cfg(feature = "virtio-vsock")]
        let mut vsock = VsockStream::new()?;

        #[cfg(feature = "vmcall-vsock")]
        let mut vsock = VsockStream::new_with_cid(migtd_cid, _mig_request_id)?;

        // Establish the vsock connection with host
        vsock
            .connect(&VsockAddr::new(migtd_cid as u32, mig_channel_port))
            .await?;
        return Ok(vsock);
    }
}

pub(super) async fn shutdown_transport(
    transport: &mut TransportType,
    _mig_request_id: u64,
) -> Result<()> {
    #[cfg(feature = "vmcall-raw")]
    transport.shutdown().await.map_err(|e| {
        log::error!(migration_request_id = _mig_request_id;
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
