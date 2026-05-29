// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{boxed::Box, vec::Vec};
use core::mem::MaybeUninit;
use core::time::Duration;
use crypto::{
    tls::SecureChannel,
    x509::{Certificate, Decode},
};
use ring::rand::{SecureRandom, SystemRandom};
use tdx_tdcall::tdx::{tdcall_servtd_rebind_approve, tdcall_vm_write};

use crate::migration::servtd_ext::read_servtd_ext;
use crate::migration::transport::*;
#[cfg(feature = "spdm_attestation")]
use crate::spdm;

use crate::{config, migration::pre_session_data::pre_session_data_exchange};

use crate::{
    driver::ticks::with_timeout,
    migration::{
        servtd_ext::{write_approved_servtd_ext_hash, ServtdExt},
        MigrationResult, MigtdMigrationInformation, TD_INFO_SIZE,
    },
    ratls::{self, find_extension, EXTNID_MIGTD_SERVTD_EXT},
};
pub use tdx_tdcall::tdx::TargetTdUuid;

/// Rebind session token held by the Service TD. This field is written by the ServiceTD
/// executing TDG.VM.WR.
pub const TDCS_FIELD_SERVTD_REBIND_ACCEPT_TOKEN: u64 = 0x191000030000021E;
/// The intended SERVTD_ATTR for the Service TD about to be bound to the TD.
pub const TDCS_FIELD_SERVTD_REBIND_ATTR: u64 = 0x1910000300000222;
const TDCS_FIELD_WRITE_MASK: u64 = u64::MAX;

const TLS_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
                                                       // FIXME: Need VMM provide socket information

#[repr(C)]
pub struct RebindingToken {
    token: [u8; 32],
}

impl RebindingToken {
    pub fn read_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }

        let mut uinit: MaybeUninit<Self> = MaybeUninit::uninit();
        // Safety: MaybeUninit<RebindingToken> has same layout with RebindingToken
        Some(unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                uinit.as_mut_ptr() as *mut u8,
                size_of::<Self>(),
            );
            uinit.assume_init()
        })
    }

    pub fn token(&self) -> &[u8] {
        &self.token
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }
}

pub async fn start_rebinding(
    info: &MigtdMigrationInformation,
    data: &mut Vec<u8>,
) -> Result<(), MigrationResult> {
    let mut transport = setup_transport(info.mig_request_id).await?;

    let policy = config::get_policy()
        .ok_or(MigrationResult::InvalidParameter)
        .map_err(|e| {
            log::error!("pre_session_data_exchange: get_policy error: {:?}\n", e);
            e
        })?;

    // Exchange policy firstly because of the message size limitation of TLS protocol
    const PRE_SESSION_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds

    if info.migration_source == 1 {
        let remote_policy = Box::pin(with_timeout(
            PRE_SESSION_TIMEOUT,
            pre_session_data_exchange(&mut transport, policy),
        ))
        .await
        .map_err(|e| {
            log::error!(
                "start_rebinding: pre_session_data_exchange timeout error: {:?}\n",
                e
            );
            e
        })?
        .map_err(|e| {
            log::error!(
                "start_rebinding: pre_session_data_exchange error: {:?}\n",
                e
            );
            e
        })?;

        #[cfg(not(feature = "spdm_attestation"))]
        rebinding_old_prepare(transport, info, data, remote_policy).await?;

        #[cfg(feature = "spdm_attestation")]
        rebinding_old_prepare(
            transport,
            info,
            data,
            #[cfg(feature = "policy_v2")]
            remote_policy,
        )
        .await?;
    } else {
        let remote_policy = Box::pin(with_timeout(
            PRE_SESSION_TIMEOUT,
            pre_session_data_exchange(&mut transport, policy),
        ))
        .await
        .map_err(|e| {
            log::error!(
                "start_rebinding: pre_session_data_exchange timeout error: {:?}\n",
                e
            );
            e
        })?
        .map_err(|e| {
            log::error!(
                "start_rebinding: pre_session_data_exchange error: {:?}\n",
                e
            );
            e
        })?;

        // Wrap remote_policy with length prefix for downstream TLS verify callback
        let mut pre_session_data = Vec::new();
        pre_session_data.extend_from_slice(&(remote_policy.len() as u32).to_le_bytes());
        pre_session_data.extend_from_slice(&remote_policy);

        #[cfg(not(feature = "spdm_attestation"))]
        rebinding_new_prepare(transport, info, data, pre_session_data).await?;

        #[cfg(feature = "spdm_attestation")]
        rebinding_new_prepare(
            transport,
            info,
            data,
            #[cfg(feature = "policy_v2")]
            pre_session_data,
        )
        .await?;
    }
    #[cfg(feature = "vmcall-raw")]
    {
        use crate::migration::logging::entrylog;

        entrylog(
            &format!("Complete rebinding and report status\n").into_bytes(),
            log::Level::Info,
            info.mig_request_id,
        );
        log::info!("Complete rebinding and report status\n");
    }
    Ok(())
}

#[cfg(feature = "spdm_attestation")]
pub async fn rebinding_old_prepare(
    transport: TransportType,
    info: &MigtdMigrationInformation,
    _data: &mut Vec<u8>,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<(), MigrationResult> {
    use core::ops::DerefMut;

    const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    let (mut spdm_requester, device_io_ref) = spdm::spdm_requester(transport).map_err(|_e| {
        log::error!(
            "rebinding: Failed in spdm_requester transport. Migration ID: {}\n",
            info.mig_request_id
        );
        MigrationResult::SecureSessionError
    })?;
    with_timeout(
        SPDM_TIMEOUT,
        spdm::spdm_requester_rebind_old(
            &mut spdm_requester,
            info,
            #[cfg(feature = "policy_v2")]
            remote_policy,
        ),
    )
    .await
    .map_err(|e| {
        log::error!(
            "rebinding: spdm_requester_rebind_old timeout error: {:?}\n",
            e
        );
        e
    })?
    .map_err(|e| {
        log::error!("rebinding: spdm_requester_rebind_old error: {:?}\n", e);
        e
    })?;
    log::info!("Rebind completed\n");

    let mut transport_lock = device_io_ref.lock();
    let transport = transport_lock.deref_mut();
    shutdown_transport(&mut transport.transport, info.mig_request_id).await?;
    Ok(())
}

#[cfg(feature = "spdm_attestation")]
pub async fn rebinding_new_prepare(
    transport: TransportType,
    info: &MigtdMigrationInformation,
    _data: &mut Vec<u8>,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<(), MigrationResult> {
    use core::ops::DerefMut;

    const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    let (mut spdm_responder, device_io_ref) = spdm::spdm_responder(transport).map_err(|_e| {
        log::error!(
            "rebinding: Failed in spdm_responder transport. Migration ID: {}\n",
            info.mig_request_id
        );
        MigrationResult::SecureSessionError
    })?;

    with_timeout(
        SPDM_TIMEOUT,
        spdm::spdm_responder_rebind_new(
            &mut spdm_responder,
            info,
            #[cfg(feature = "policy_v2")]
            remote_policy,
        ),
    )
    .await
    .map_err(|e| {
        log::error!(
            "rebinding: spdm_responder_rebind_new timeout error: {:?}\n",
            e
        );
        e
    })?
    .map_err(|e| {
        log::error!("rebinding: spdm_responder_rebind_new error: {:?}\n", e);
        e
    })?;
    log::info!("Rebind completed\n");

    let mut transport_lock = device_io_ref.lock();
    let transport = transport_lock.deref_mut();
    shutdown_transport(&mut transport.transport, info.mig_request_id).await?;
    Ok(())
}

#[cfg(not(feature = "spdm_attestation"))]
async fn rebinding_old_prepare(
    transport: TransportType,
    info: &MigtdMigrationInformation,
    data: &mut Vec<u8>,
    remote_policy: Vec<u8>,
) -> Result<(), MigrationResult> {
    let servtd_ext = read_servtd_ext(info.binding_handle, &info.target_td_uuid)?;

    // Resolve the initial TDINFO_STRUCT: use VMM-provided bytes when present,
    // otherwise fall back to the local MigTD's self-report.
    let local;
    let init_td_info: &[u8; TD_INFO_SIZE] = match info.init_td_info_if_present() {
        Some(t) => t,
        None => {
            local = crate::migration::local_init_td_info()?;
            &local
        }
    };

    // Per GHCI 1.5: init policy key hash is in tdinfo.mrowner.
    // Use mrowner directly as the init_policy_hash equivalent.
    let init_policy_hash = crate::migration::td_info_mrowner(init_td_info).to_vec();

    // Per GHCI 1.5: init_tdinfo replaces the old init_report (full TDREPORT).
    // The TDINFO_STRUCT contains all the measurement fields needed for verification.
    let init_tdinfo: &[u8] = init_td_info;

    // TLS client
    let mut ratls_client = ratls::client_rebinding(
        transport,
        remote_policy,
        &init_policy_hash,
        init_tdinfo,
        &servtd_ext,
    )
    .map_err(|_| {
        #[cfg(feature = "vmcall-raw")]
        data.extend_from_slice(
            &format!(
                "Error: rebinding_old(): Failed in ratls transport. Migration ID: {:x}\n",
                info.mig_request_id,
            )
            .into_bytes(),
        );
        log::error!(
            "rebinding_old(): Failed in ratls transport. Migration ID: {}\n",
            info.mig_request_id
        );
        MigrationResult::SecureSessionError
    })?;

    let rebind_token = create_rebind_token()?;
    tls_send_rebind_token(&mut ratls_client, &rebind_token).await?;

    approve_rebinding(info, &rebind_token)?;

    shutdown_transport(ratls_client.transport_mut(), info.mig_request_id).await?;
    Ok(())
}

#[cfg(not(feature = "spdm_attestation"))]
async fn rebinding_new_prepare(
    transport: TransportType,
    info: &MigtdMigrationInformation,
    data: &mut Vec<u8>,
    pre_session_data: Vec<u8>,
) -> Result<(), MigrationResult> {
    // TLS server
    let mut ratls_server = ratls::server_rebinding(transport, pre_session_data).map_err(|e| {
        #[cfg(feature = "vmcall-raw")]
        data.extend_from_slice(
            &format!(
                "Error: rebinding_new(): Failed in ratls transport. Migration ID: {:x}\n",
                info.mig_request_id
            )
            .into_bytes(),
        );
        log::error!(
            "rebinding_new(): Failed in ratls transport. Migration ID: {} Error: {:?}\n",
            info.mig_request_id,
            e
        );
        e
    })?;

    let rebind_token = tls_receive_rebind_token(&mut ratls_server).await?;

    // The TLS session is established; we can now extract servtd_ext from the peer certificates.
    let mut servtd_ext = get_servtd_ext_from_cert(&ratls_server.peer_certs())?;
    write_rebinding_session_token(&rebind_token.token)?;
    write_servtd_rebind_attr(&servtd_ext.cur_servtd_attr)?;
    servtd_ext.cur_servtd_info_hash.fill(0);
    servtd_ext.cur_servtd_attr.fill(0);
    write_approved_servtd_ext_hash(&servtd_ext.calculate_approved_servtd_ext_hash()?)?;

    shutdown_transport(ratls_server.transport_mut(), info.mig_request_id).await?;
    Ok(())
}

pub fn write_rebinding_session_token(rebind_token: &[u8]) -> Result<(), MigrationResult> {
    if rebind_token.len() != 32 {
        return Err(MigrationResult::InvalidParameter);
    }

    for (idx, chunk) in rebind_token.chunks_exact(size_of::<u64>()).enumerate() {
        let elem = u64::from_le_bytes(chunk.try_into().unwrap());
        tdcall_vm_write(
            TDCS_FIELD_SERVTD_REBIND_ACCEPT_TOKEN + idx as u64,
            elem,
            TDCS_FIELD_WRITE_MASK,
        )?;
    }

    Ok(())
}

pub fn write_servtd_rebind_attr(servtd_attr: &[u8]) -> Result<(), MigrationResult> {
    if servtd_attr.len() != 8 {
        return Err(MigrationResult::InvalidParameter);
    }

    let elem = u64::from_le_bytes(servtd_attr.try_into().unwrap());
    tdcall_vm_write(TDCS_FIELD_SERVTD_REBIND_ATTR, elem, TDCS_FIELD_WRITE_MASK)?;

    Ok(())
}

pub fn approve_rebinding(
    info: &MigtdMigrationInformation,
    rebind_token: &RebindingToken,
) -> Result<(), MigrationResult> {
    tdcall_servtd_rebind_approve(
        info.binding_handle,
        &rebind_token.token,
        &info.target_td_uuid,
    )?;
    Ok(())
}

fn get_servtd_ext_from_cert(certs: &Option<Vec<&[u8]>>) -> Result<ServtdExt, MigrationResult> {
    if let Some(cert_chain) = certs {
        if cert_chain.is_empty() {
            return Err(MigrationResult::SecureSessionError);
        }

        let cert = Certificate::from_der(cert_chain[0])
            .map_err(|_| MigrationResult::SecureSessionError)?;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(MigrationResult::SecureSessionError)?;

        let servtd_ext = find_extension(extensions, &EXTNID_MIGTD_SERVTD_EXT)
            .ok_or(MigrationResult::SecureSessionError)?;

        ServtdExt::read_from_bytes(servtd_ext).ok_or(MigrationResult::InvalidParameter)
    } else {
        Err(MigrationResult::SecureSessionError)
    }
}

pub fn create_rebind_token() -> Result<RebindingToken, MigrationResult> {
    let mut token = [0u8; 32];
    let rng = SystemRandom::new();
    rng.fill(&mut token)
        .map_err(|_| MigrationResult::InvalidParameter)?;

    Ok(RebindingToken { token })
}

async fn tls_send_rebind_token(
    tls_session: &mut SecureChannel<TransportType>,
    rebind_token: &RebindingToken,
) -> Result<(), MigrationResult> {
    // MigTD old send rebinding session token to peer
    with_timeout(
        TLS_TIMEOUT,
        tls_session_write_all(tls_session, rebind_token.as_bytes()),
    )
    .await
    .map_err(|e| {
        log::error!(
            "tls_send_rebind_token: tls_session_write_all timeout error: {:?}\n",
            e
        );
        e
    })?
    .map_err(|e| {
        log::error!(
            "tls_send_rebind_token: tls_session_write_all error: {:?}\n",
            e
        );
        e
    })?;
    Ok(())
}

async fn tls_receive_rebind_token(
    tls_session: &mut SecureChannel<TransportType>,
) -> Result<RebindingToken, MigrationResult> {
    let mut data = [0u8; size_of::<RebindingToken>()];
    // MigTD old send rebinding session token to peer
    with_timeout(TLS_TIMEOUT, tls_session_read_exact(tls_session, &mut data))
        .await
        .map_err(|e| {
            log::error!(
                "tls_receive_rebind_token: tls_session_read_exact timeout error: {:?}\n",
                e
            );
            e
        })?
        .map_err(|e| {
            log::error!(
                "tls_receive_rebind_token: tls_session_read_exact error: {:?}\n",
                e
            );
            e
        })?;

    let rebind_token =
        RebindingToken::read_from_bytes(&data).ok_or(MigrationResult::InvalidParameter)?;
    Ok(rebind_token)
}

async fn tls_session_write_all(
    tls_session: &mut SecureChannel<TransportType>,
    data: &[u8],
) -> Result<(), MigrationResult> {
    let mut sent = 0;
    while sent < data.len() {
        let n = tls_session
            .write(&data[sent..])
            .await
            .map_err(|_| MigrationResult::SecureSessionError)?;
        sent += n;
    }
    Ok(())
}

async fn tls_session_read_exact(
    tls_session: &mut SecureChannel<TransportType>,
    data: &mut [u8],
) -> Result<(), MigrationResult> {
    let mut recvd = 0;
    while recvd < data.len() {
        let n = tls_session
            .read(&mut data[recvd..])
            .await
            .map_err(|_| MigrationResult::NetworkError)?;
        recvd += n;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::migration::{td_info_mrowner, td_info_mrownerconfig};
    use alloc::vec;

    /// Create a 512-byte TDINFO_STRUCT with known mrowner and mrownerconfig.
    fn make_tdinfo(mrowner: &[u8; 48], mrownerconfig: &[u8; 48]) -> [u8; TD_INFO_SIZE] {
        let mut tdinfo = [0u8; TD_INFO_SIZE];
        // mrowner at offset 112..160
        tdinfo[112..160].copy_from_slice(mrowner);
        // mrownerconfig at offset 160..208
        tdinfo[160..208].copy_from_slice(mrownerconfig);
        tdinfo
    }

    /// Build a MigtdMigrationInformation byte buffer. When `init_tdinfo` is `Some`, the
    /// raw TDINFO bytes are appended directly (no envelope, per the new wire
    /// contract).
    fn build_mig_info(
        mig_request_id: u64,
        migration_source: u8,
        has_init_data: u8,
        uuid: [u64; 4],
        binding_handle: u64,
        init_tdinfo: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&mig_request_id.to_le_bytes()); // 0..8
        buf.push(migration_source); // 8
        buf.push(has_init_data); // 9
        buf.extend_from_slice(&[0u8; 6]); // 10..16 reserved
        for u in &uuid {
            buf.extend_from_slice(&u.to_le_bytes()); // 16..48
        }
        buf.extend_from_slice(&binding_handle.to_le_bytes()); // 48..56
        if let Some(data) = init_tdinfo {
            buf.extend_from_slice(data); // 56..56+512
        }
        buf
    }

    #[test]
    fn test_mig_info_no_init_data() {
        let buf = build_mig_info(42, 1, 0, [1, 2, 3, 4], 99, None);
        let info = MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf)
            .expect("should parse");
        assert_eq!(info.mig_request_id, 42);
        assert_eq!(info.migration_source, 1);
        assert_eq!(info.has_init_data, 0);
        assert_eq!(info.target_td_uuid, [1, 2, 3, 4]);
        assert_eq!(info.binding_handle, 99);
        assert!(info.init_td_info_if_present().is_none());
        // Padded tail is zero.
        assert_eq!(info.init_td_info, [0u8; TD_INFO_SIZE]);
    }

    #[test]
    fn test_mig_info_with_init_data() {
        let tdinfo = make_tdinfo(&[0xCAu8; 48], &[0xFEu8; 48]);
        let buf = build_mig_info(7, 0, 1, [10, 20, 30, 40], 55, Some(&tdinfo));
        let info = MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf)
            .expect("should parse with init data");
        assert_eq!(info.mig_request_id, 7);
        assert_eq!(info.has_init_data, 1);
        let init = info.init_td_info_if_present().expect("should be present");
        assert_eq!(init, &tdinfo);
        assert_eq!(td_info_mrowner(init), &[0xCAu8; 48]);
        assert_eq!(td_info_mrownerconfig(init), &[0xFEu8; 48]);
    }

    #[test]
    fn test_mig_info_rejects_short_buffer() {
        assert!(MigtdMigrationInformation::read_from_bytes(10, &[0u8; 10]).is_err());
        assert!(MigtdMigrationInformation::read_from_bytes(55, &[0u8; 55]).is_err());
        // 55 < 56
    }

    #[test]
    fn test_mig_info_rejects_nonzero_reserved() {
        let mut buf = build_mig_info(1, 0, 0, [0; 4], 0, None);
        buf[10] = 0xFF; // reserved byte not zero
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
    }

    #[test]
    fn test_mig_info_rejects_has_init_data_without_tail() {
        // has_init_data=1 but no tail bytes following → flag/length mismatch
        let buf = build_mig_info(1, 0, 1, [0; 4], 0, None);
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
    }

    #[test]
    fn test_mig_info_rejects_full_form_without_flag() {
        // has_init_data=0 but full 568-byte buffer → flag/length mismatch
        let tdinfo = [0u8; TD_INFO_SIZE];
        let buf = build_mig_info(1, 0, 0, [0; 4], 0, Some(&tdinfo));
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
    }

    #[test]
    fn test_mig_info_rejects_invalid_has_init_data() {
        // has_init_data must be 0 or 1
        let mut buf = build_mig_info(1, 0, 0, [0; 4], 0, None);
        buf[9] = 2;
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
        buf[9] = 0xFF;
        assert!(MigtdMigrationInformation::read_from_bytes(buf.len() as u32, &buf).is_err());
    }

    #[test]
    fn test_mig_info_rejects_unexpected_length() {
        // Only short (56) or full (568) lengths are accepted.
        let mid_buf = vec![0u8; 100];
        assert!(
            MigtdMigrationInformation::read_from_bytes(mid_buf.len() as u32, &mid_buf).is_err()
        );
    }
}
