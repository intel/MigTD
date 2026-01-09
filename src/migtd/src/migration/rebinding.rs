// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};
use core::mem::MaybeUninit;
use core::time::Duration;
use crypto::{
    tls::SecureChannel,
    x509::{Certificate, Decode},
};
use ring::rand::{SecureRandom, SystemRandom};
use tdx_tdcall::tdx::{tdcall_servtd_rebind_approve, tdcall_vm_write};

use crate::mig_policy::get_init_policy;
use crypto::hash::digest_sha384;

use crate::{
    config,
    migration::session::{
        exchange_hello_packet, receive_pre_session_data_packet, receive_start_session_packet,
        send_pre_session_data_packet, send_start_session_packet,
    },
};

use crate::{
    driver::ticks::with_timeout,
    migration::{
        servtd_ext::{write_approved_servtd_ext_hash, ServtdExt},
        session::{setup_transport, shutdown_transport, TransportType},
        MigrationResult,
    },
    ratls::{self, find_extension, EXTNID_MIGTD_SERVTD_EXT},
};
pub use tdx_tdcall::tdx::TargetTdUuid;

/// Rebind session token held by the Service TD. This field is written by the ServiceTD
/// executing TDG.VM.WR.
pub const TDCS_FIELD_SERVTD_REBIND_ACCEPT_TOKEN: u64 = 0x191000030000021E;
/// The intended SERVTD_ATTR for the Service TD about to be bound to the TD.
pub const TDCS_FIELD_SERVTD_REBIND_ATTR: u64 = 0x1910000300000222;

const TLS_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
                                                       // FIXME: Need VMM provide socket information
const STUB_MIGTD_CID: u32 = 20;
const STUB_CHANNEL_PORT_SRC: u32 = 1234;
const STUB_CHANNEL_PORT_DST: u32 = 1235;

#[repr(C)]
pub struct RebindingToken {
    pub token: [u8; 32],
    pub binding_handle: u64,
    pub target_td_uuid: TargetTdUuid,
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

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }
}

pub struct RebindingInfo {
    pub mig_request_id: u64,
    pub rebinding_src: u8,
    pub _reserved: [u8; 7],
    pub num_binding_handle: u32,
    _reserved2: [u8; 4],
    pub binding_handle_list: Vec<u64>,
    pub target_td_uuid_list: Vec<[u64; 4]>,
}

impl RebindingInfo {
    pub fn read_from_bytes(b: &[u8]) -> Option<Self> {
        // Check the length of input and the reserved fields
        if b.len() < 24 || b[9..16] != [0; 7] || b[20..24] != [0; 4] {
            return None;
        }
        let mig_request_id = u64::from_le_bytes(b[..8].try_into().unwrap());
        let rebinding_src = b[8];
        let num_binding_handle = u32::from_le_bytes(b[16..20].try_into().unwrap());
        let total_len = 24 + (8 + 32) * num_binding_handle as usize;

        // The number of BindingHandle must be non-0 for MigTD-old and it must be 0 for MigTD-new.
        if rebinding_src == 1 && num_binding_handle == 0 {
            return None;
        } else if rebinding_src == 0 && num_binding_handle != 0 {
            return None;
        }

        if b.len() != total_len {
            return None;
        }
        let uuid_offset = 24 + 8 * num_binding_handle as usize;
        let binding_handle_list = b[24..uuid_offset]
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        let target_td_uuid_list = b[uuid_offset..total_len]
            .chunks_exact(32)
            .map(|chunk| {
                let mut uuid = [0u64; 4];
                uuid[0] = u64::from_le_bytes(chunk[..8].try_into().unwrap());
                uuid[1] = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
                uuid[2] = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
                uuid[3] = u64::from_le_bytes(chunk[24..32].try_into().unwrap());
                uuid
            })
            .collect();

        Some(Self {
            mig_request_id,
            rebinding_src,
            _reserved: [0; 7],
            num_binding_handle,
            _reserved2: [0; 4],
            binding_handle_list,
            target_td_uuid_list,
        })
    }
}

pub(super) async fn rebinding_old_pre_session_data_exchange(
    transport: &mut TransportType,
    binding_handle: u64,
) -> Result<Vec<u8>, MigrationResult> {
    let version = exchange_hello_packet(transport).await.map_err(|e| {
        log::error!(
            "pre_session_data_exchange: exchange_hello_packet error: {:?}\n",
            e
        );
        e
    })?;
    log::info!("Pre-Session-Message Version: 0x{:04x}\n", version);

    let policy = config::get_policy()
        .ok_or(MigrationResult::InvalidParameter)
        .map_err(|e| {
            log::error!("pre_session_data_exchange: get_policy error: {:?}\n", e);
            e
        })?;
    send_pre_session_data_packet(policy, transport)
        .await
        .map_err(|e| {
            log::error!(
                "pre_session_data_exchange: send_pre_session_data_packet error: {:?}\n",
                e
            );
            e
        })?;
    let remote_policy = receive_pre_session_data_packet(transport)
        .await
        .map_err(|e| {
            log::error!(
                "pre_session_data_exchange: receive_pre_session_data_packet error: {:?}\n",
                e
            );
            e
        })?;

    let init_policy_stored = get_init_policy(binding_handle);
    let init_policy = init_policy_stored.as_deref().unwrap_or(policy);
    send_pre_session_data_packet(init_policy, transport)
        .await
        .map_err(|e| {
            log::error!(
                "pre_session_data_exchange: send_pre_session_data_packet error: {:?}\n",
                e
            );
            e
        })?;

    send_start_session_packet(transport).await.map_err(|e| {
        log::error!(
            "pre_session_data_exchange: send_start_session_packet error: {:?}\n",
            e
        );
        e
    })?;
    receive_start_session_packet(transport).await.map_err(|e| {
        log::error!(
            "pre_session_data_exchange: receive_start_session_packet error: {:?}\n",
            e
        );
        e
    })?;

    Ok(remote_policy)
}

pub(super) async fn rebinding_new_pre_session_data_exchange(
    transport: &mut TransportType,
) -> Result<Vec<u8>, MigrationResult> {
    let version = exchange_hello_packet(transport).await.map_err(|e| {
        log::error!(
            "pre_session_data_exchange: exchange_hello_packet error: {:?}\n",
            e
        );
        e
    })?;
    log::info!("Pre-Session-Message Version: 0x{:04x}\n", version);

    let policy = config::get_policy()
        .ok_or(MigrationResult::InvalidParameter)
        .map_err(|e| {
            log::error!("pre_session_data_exchange: get_policy error: {:?}\n", e);
            e
        })?;
    send_pre_session_data_packet(policy, transport)
        .await
        .map_err(|e| {
            log::error!(
                "pre_session_data_exchange: send_pre_session_data_packet error: {:?}\n",
                e
            );
            e
        })?;
    let remote_policy = receive_pre_session_data_packet(transport)
        .await
        .map_err(|e| {
            log::error!(
                "pre_session_data_exchange: receive_pre_session_data_packet error: {:?}\n",
                e
            );
            e
        })?;

    let init_policy = receive_pre_session_data_packet(transport)
        .await
        .map_err(|e| {
            log::error!(
                "pre_session_data_exchange: send_pre_session_data_packet error: {:?}\n",
                e
            );
            e
        })?;

    send_start_session_packet(transport).await.map_err(|e| {
        log::error!(
            "pre_session_data_exchange: send_start_session_packet error: {:?}\n",
            e
        );
        e
    })?;
    receive_start_session_packet(transport).await.map_err(|e| {
        log::error!(
            "pre_session_data_exchange: receive_start_session_packet error: {:?}\n",
            e
        );
        e
    })?;

    // FIXME: Refactor the TLS verification callback to enable easier access to pre-session data.
    let mut policy_buffer = Vec::new();
    policy_buffer.extend_from_slice(&(remote_policy.len() as u32).to_le_bytes());
    policy_buffer.extend_from_slice(&remote_policy);
    policy_buffer.extend_from_slice(&(init_policy.len() as u32).to_le_bytes());
    policy_buffer.extend_from_slice(&init_policy);

    Ok(policy_buffer)
}

pub async fn start_rebinding(
    info: &RebindingInfo,
    data: &mut Vec<u8>,
) -> Result<(), MigrationResult> {
    let mut transport = setup_transport(
        info.mig_request_id,
        #[cfg(any(feature = "virtio-vsock", feature = "vmcall-vsock"))]
        STUB_MIGTD_CID,
        #[cfg(any(feature = "virtio-vsock", feature = "vmcall-vsock"))]
        if info.rebinding_src == 1 {
            STUB_CHANNEL_PORT_SRC
        } else {
            STUB_CHANNEL_PORT_DST
        },
        #[cfg(any(feature = "virtio-vsock", feature = "vmcall-vsock"))]
        data,
    )
    .await?;

    // Exchange policy firstly because of the message size limitation of TLS protocol
    const PRE_SESSION_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    if info.rebinding_src == 1 {
        let remote_policy = Box::pin(with_timeout(
            PRE_SESSION_TIMEOUT,
            rebinding_old_pre_session_data_exchange(&mut transport, info.binding_handle_list[0]),
        ))
        .await
        .map_err(|e| {
            log::error!(
                "start_rebinding: rebinding_old_pre_session_data_exchange timeout error: {:?}\n",
                e
            );
            e
        })?
        .map_err(|e| {
            log::error!(
                "start_rebinding: rebinding_old_pre_session_data_exchange error: {:?}\n",
                e
            );
            e
        })?;
        #[cfg(not(feature = "spdm_attestation"))]
        rebinding_old(
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
            rebinding_new_pre_session_data_exchange(&mut transport),
        ))
        .await
        .map_err(|e| {
            log::error!(
                "start_rebinding: rebinding_new_pre_session_data_exchange timeout error: {:?}\n",
                e
            );
            e
        })?
        .map_err(|e| {
            log::error!(
                "start_rebinding: rebinding_new_pre_session_data_exchange error: {:?}\n",
                e
            );
            e
        })?;

        #[cfg(not(feature = "spdm_attestation"))]
        rebinding_new(
            transport,
            info,
            data,
            #[cfg(feature = "policy_v2")]
            remote_policy,
        )
        .await?;
    }

    #[cfg(feature = "vmcall-raw")]
    {
        entrylog(
            &format!("Complete rebinding and report status\n").into_bytes(),
            Level::Info,
            info.mig_request_id,
        );
        log::info!("Complete rebinding and report status\n");
    }
    Ok(())
}

pub async fn rebinding_old(
    transport: TransportType,
    info: &RebindingInfo,
    data: &mut Vec<u8>,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<(), MigrationResult> {
    // TLS client
    let mut ratls_client = ratls::client_rebinding(
        transport,
        #[cfg(feature = "policy_v2")]
        remote_policy,
        info.binding_handle_list[0],
        &info.target_td_uuid_list[0],
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

    let tokens = create_token_list(info)?;
    tls_send_rebind_tokens(&mut ratls_client, &tokens).await?;

    approve_rebinding(&tokens)?;

    shutdown_transport(ratls_client.transport_mut(), info.mig_request_id, data).await?;
    Ok(())
}

pub async fn rebinding_new(
    transport: TransportType,
    info: &RebindingInfo,
    data: &mut Vec<u8>,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<(), MigrationResult> {
    // TLS server
    let mut ratls_server = ratls::server_rebinding(
        transport,
        #[cfg(feature = "policy_v2")]
        remote_policy,
    )
    .map_err(|_| {
        #[cfg(feature = "vmcall-raw")]
        data.extend_from_slice(
            &format!(
                "Error: rebinding_new(): Failed in ratls transport. Migration ID: {:x}\n",
                info.mig_request_id
            )
            .into_bytes(),
        );
        log::error!(
            "rebinding_new(): Failed in ratls transport. Migration ID: {}\n",
            info.mig_request_id
        );
        MigrationResult::SecureSessionError
    })?;

    let servtd_ext = get_servtd_ext_from_cert(&ratls_server.peer_certs())?;
    let received_tokens = tls_receive_rebind_tokens(&mut ratls_server).await?;

    check_remote_handle_list(info, &received_tokens)?;

    write_rebinding_session_token(&received_tokens[0].token)?;
    write_servtd_rebind_attr(&servtd_ext.cur_servtd_attr)?;
    write_approved_servtd_ext_hash(&servtd_ext.calculate_approved_servtd_ext_hash()?)?;

    shutdown_transport(ratls_server.transport_mut(), info.mig_request_id, data).await?;
    Ok(())
}

pub fn write_rebinding_session_token(rebind_token: &[u8]) -> Result<(), MigrationResult> {
    if rebind_token.len() != 32 {
        return Err(MigrationResult::InvalidParameter);
    }

    for (idx, chunk) in rebind_token.chunks_exact(size_of::<u64>()).enumerate() {
        let elem = u64::from_le_bytes(chunk.try_into().unwrap());
        tdcall_vm_write(TDCS_FIELD_SERVTD_REBIND_ACCEPT_TOKEN + idx as u64, elem, 0)?;
    }

    Ok(())
}

pub fn write_servtd_rebind_attr(servtd_attr: &[u8]) -> Result<(), MigrationResult> {
    if servtd_attr.len() != 8 {
        return Err(MigrationResult::InvalidParameter);
    }

    let elem = u64::from_le_bytes(servtd_attr.try_into().unwrap());
    tdcall_vm_write(TDCS_FIELD_SERVTD_REBIND_ATTR, elem, 0)?;

    Ok(())
}

pub fn approve_rebinding(token_list: &[RebindingToken]) -> Result<(), MigrationResult> {
    for token in token_list {
        tdcall_servtd_rebind_approve(token.binding_handle, &token.token, &token.target_td_uuid)?;
    }

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

fn create_token_list(info: &RebindingInfo) -> Result<Vec<RebindingToken>, MigrationResult> {
    let mut tokens = Vec::new();

    for (handle, uuid) in info
        .binding_handle_list
        .iter()
        .zip(info.target_td_uuid_list.iter())
    {
        let mut token = [0u8; 32];
        let rng = SystemRandom::new();
        rng.fill(&mut token)
            .map_err(|_| MigrationResult::InvalidParameter)?;
        tokens.push(RebindingToken {
            token,
            binding_handle: *handle,
            target_td_uuid: *uuid,
        });
    }

    Ok(tokens)
}

fn check_remote_handle_list(
    info: &RebindingInfo,
    remote_list: &[RebindingToken],
) -> Result<(), MigrationResult> {
    let set: BTreeSet<u64> = remote_list
        .iter()
        .map(|token| token.binding_handle)
        .collect();

    if set.len() != remote_list.len() || remote_list.len() != info.binding_handle_list.len() {
        return Err(MigrationResult::InvalidParameter);
    }

    for (handle, uuid) in info
        .binding_handle_list
        .iter()
        .zip(info.target_td_uuid_list.iter())
    {
        if remote_list
            .iter()
            .find(|t| t.binding_handle == *handle && &t.target_td_uuid == uuid)
            .is_none()
        {
            return Err(MigrationResult::InvalidParameter);
        }
    }

    Ok(())
}

async fn tls_send_rebind_tokens(
    tls_session: &mut SecureChannel<TransportType>,
    tokens: &[RebindingToken],
) -> Result<(), MigrationResult> {
    let msg = setup_rebind_tokens_message(tokens)?;
    // MigTD old send rebinding session token to peer
    with_timeout(
        TLS_TIMEOUT,
        tls_session_write_all(tls_session, msg.as_slice()),
    )
    .await
    .map_err(|e| {
        log::error!(
            "tls_send_rebind_tokens: tls_session_write_all timeout error: {:?}\n",
            e
        );
        e
    })?
    .map_err(|e| {
        log::error!(
            "tls_send_rebind_tokens: tls_session_write_all error: {:?}\n",
            e
        );
        e
    })?;
    Ok(())
}

async fn tls_receive_rebind_tokens(
    tls_session: &mut SecureChannel<TransportType>,
) -> Result<Vec<RebindingToken>, MigrationResult> {
    let mut header = [0u8; 8];
    // MigTD old send rebinding session token to peer
    with_timeout(
        TLS_TIMEOUT,
        tls_session_read_exact(tls_session, &mut header),
    )
    .await
    .map_err(|e| {
        log::error!(
            "tls_receive_rebind_tokens: tls_session_read_exact timeout error: {:?}\n",
            e
        );
        e
    })?
    .map_err(|e| {
        log::error!(
            "tls_receive_rebind_tokens: tls_session_read_exact error: {:?}\n",
            e
        );
        e
    })?;

    let msg_type = header[0];
    if msg_type != 1 {
        return Err(MigrationResult::InvalidParameter);
    }

    let msg_size = u32::from_le_bytes(header[4..8].try_into().unwrap());
    let data_size = msg_size as usize - header.len();
    if data_size % size_of::<RebindingToken>() != 0 {
        return Err(MigrationResult::InvalidParameter);
    }

    let mut data = vec![0u8; data_size];
    // MigTD old send rebinding session token to peer
    with_timeout(TLS_TIMEOUT, tls_session_read_exact(tls_session, &mut data))
        .await
        .map_err(|e| {
            log::error!(
                "tls_receive_rebind_tokens: tls_session_read_exact timeout error: {:?}\n",
                e
            );
            e
        })?
        .map_err(|e| {
            log::error!(
                "tls_receive_rebind_tokens: tls_session_read_exact error: {:?}\n",
                e
            );
            e
        })?;

    let token_nums = data_size / size_of::<RebindingToken>();
    let mut tokens = Vec::new();
    for i in 0..token_nums {
        let offset = i * size_of::<RebindingToken>();
        tokens.push(
            RebindingToken::read_from_bytes(&data[offset..offset + size_of::<RebindingToken>()])
                .ok_or(MigrationResult::InvalidParameter)?,
        );
    }

    Ok(tokens)
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

fn setup_rebind_tokens_message(tokens: &[RebindingToken]) -> Result<Vec<u8>, MigrationResult> {
    let mut msg_buf = Vec::new();

    let token_nums = tokens.len();
    let msg_size = 8 + (token_nums * size_of::<RebindingToken>()) as u32;

    // Message type: rebind tokens
    msg_buf.extend_from_slice(&[1]);
    // Reserved
    msg_buf.extend_from_slice(&[0u8; 3]);
    // Message size
    msg_buf.extend_from_slice(&msg_size.to_le_bytes());

    for token in tokens {
        msg_buf.extend_from_slice(token.as_bytes());
    }

    Ok(msg_buf)
}
