// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::mem::size_of;

use migtd::{
    migration::{data::*, session::*, *},
    ratls,
};

struct ExchangeInformation {
    min_ver: u16,
    max_ver: u16,
    key: MigrationSessionKey,
}

impl Default for ExchangeInformation {
    fn default() -> Self {
        Self {
            key: MigrationSessionKey::new(),
            min_ver: 0,
            max_ver: 0,
        }
    }
}

impl ExchangeInformation {
    fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, size_of::<Self>()) }
    }
}

pub fn exchange_msk(info: &MigrationInformation) -> Result<()> {
    let mut msk = MigrationSessionKey::new();

    read_msk(&info.mig_info, &mut msk)?;

    let transport;
    #[cfg(feature = "virtio-serial")]
    {
        use virtio_serial::VirtioSerialPort;
        const VIRTIO_SERIAL_PORT_ID: u32 = 1;

        let port = VirtioSerialPort::new(VIRTIO_SERIAL_PORT_ID);
        port.open()?;
        transport = port;
    };

    #[cfg(not(feature = "virtio-serial"))]
    {
        use vsock::{stream::VsockStream, VsockAddr};
        // Establish the vsock connection with host
        let mut vsock = VsockStream::new()?;
        vsock.connect(&VsockAddr::new(
            info.mig_socket_info.mig_td_cid as u32,
            info.mig_socket_info.mig_channel_port,
        ))?;

        transport = vsock;
    };

    let mut remote_information = ExchangeInformation::default();
    let mut exchange_information = ExchangeInformation {
        key: msk,
        ..Default::default()
    };

    // Establish TLS layer connection and negotiate the MSK
    if info.is_src() {
        let min_export_version = tdcall_sys_rd(GSM_FIELD_MIN_EXPORT_VERSION)?.1;
        let max_export_version = tdcall_sys_rd(GSM_FIELD_MAX_EXPORT_VERSION)?.1;
        if min_export_version > u16::MAX as u64 || max_export_version > u16::MAX as u64 {
            return Err(MigrationResult::InvalidParameter);
        }
        exchange_information.min_ver = min_export_version as u16;
        exchange_information.max_ver = max_export_version as u16;

        // TLS client
        let mut ratls_client =
            ratls::client(transport).map_err(|_| MigrationResult::SecureSessionError)?;

        // MigTD-S send Migration Session Forward key to peer
        ratls_client.write(exchange_information.as_bytes())?;
        let size = ratls_client.read(remote_information.as_bytes_mut())?;
        if size < size_of::<ExchangeInformation>() {
            return Err(MigrationResult::NetworkError);
        }
    } else {
        let min_import_version = tdcall_sys_rd(GSM_FIELD_MIN_IMPORT_VERSION)?.1;
        let max_import_version = tdcall_sys_rd(GSM_FIELD_MAX_IMPORT_VERSION)?.1;
        if min_import_version > u16::MAX as u64 || max_import_version > u16::MAX as u64 {
            return Err(MigrationResult::InvalidParameter);
        }
        exchange_information.min_ver = min_import_version as u16;
        exchange_information.max_ver = max_import_version as u16;

        // TLS server
        let mut ratls_server =
            ratls::server(transport).map_err(|_| MigrationResult::SecureSessionError)?;

        ratls_server.write(exchange_information.as_bytes())?;
        let size = ratls_server.read(remote_information.as_bytes_mut())?;
        if size < size_of::<ExchangeInformation>() {
            return Err(MigrationResult::NetworkError);
        }
    }

    let mig_ver = cal_mig_version(
        info.is_src(),
        exchange_information.min_ver,
        exchange_information.max_ver,
        remote_information.min_ver,
        remote_information.max_ver,
    )?;
    set_mig_version(info, mig_ver)?;

    write_msk(&info.mig_info, &remote_information.key)?;
    log::info!("Set MSK and report status\n");
    exchange_information.key.clear();
    remote_information.key.clear();

    Ok(())
}
