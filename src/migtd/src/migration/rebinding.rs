// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{boxed::Box, vec::Vec};
use core::mem::MaybeUninit;
use core::time::Duration;
use crypto::{
    tls::SecureChannel,
    x509::{Certificate, Decode},
    SHA384_DIGEST_SIZE,
};
use ring::rand::{SecureRandom, SystemRandom};
use tdx_tdcall::tdx::{tdcall_servtd_rebind_approve, tdcall_vm_write};

use crate::migration::servtd_ext::read_servtd_ext;
#[cfg(feature = "spdm_attestation")]
use crate::spdm;
use crate::{event_log, migration::transport::*};
use crypto::hash::digest_sha384;

use crate::{
    config,
    migration::pre_session_data::{
        exchange_hello_packet, receive_pre_session_data_packet, receive_start_session_packet,
        send_pre_session_data_packet, send_start_session_packet,
    },
};

use crate::{
    driver::ticks::with_timeout,
    migration::{
        servtd_ext::{write_approved_servtd_ext_hash, ServtdExt},
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
const MIGTD_DATA_SIGNATURE: &[u8] = b"MIGTDATA";
const MIGTD_DATA_TYPE_INIT_MIG_POLICY: u32 = 0;
const MIGTD_DATA_TYPE_INIT_TD_REPORT: u32 = 1;
const MIGTD_DATA_TYPE_INIT_EVENT_LOG: u32 = 2;

const MIGTD_REBIND_OP_PREPARE: u8 = 0;
const MIGTD_REBIND_OP_FINALIZE: u8 = 1;

#[repr(C)]
pub struct RebindingToken {
    pub token: [u8; 32],
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

pub struct RebindingInfo<'a> {
    pub mig_request_id: u64,
    pub rebinding_src: u8,
    pub has_init_data: u8,
    pub operation: u8,
    pub target_td_uuid: [u64; 4],
    pub binding_handle: u64,
    pub init_migtd_data: Option<InitData<'a>>,
}

impl<'a> RebindingInfo<'a> {
    pub fn read_from_bytes(b: &'a [u8]) -> Option<Self> {
        // Check the length of input and the reserved fields
        if b.len() < 56 || b[9..16] != [0; 7] || b[11..16] != [0; 4] {
            return None;
        }
        let mig_request_id = u64::from_le_bytes(b[..8].try_into().unwrap());
        let rebinding_src = b[8];
        let has_init_data = b[9];
        let operation = b[10];

        let target_td_uuid: [u64; 4] = core::array::from_fn(|i| {
            let offset = 16 + i * 8;
            u64::from_le_bytes(b[offset..offset + 8].try_into().unwrap())
        });
        let binding_handle = u64::from_le_bytes(b[48..56].try_into().unwrap());

        let mut init_migtd_data = None;
        if has_init_data == 1 {
            // Returns None if `has_init_data` is set but reading initialization data from the input buffer fails.
            init_migtd_data = Some(InitData::read_from_bytes(&b[56..])?);
        }

        Some(Self {
            mig_request_id,
            rebinding_src,
            has_init_data,
            operation,
            target_td_uuid,
            binding_handle,
            init_migtd_data,
        })
    }
}

pub struct InitData<'a> {
    pub init_report: Vec<u8>,
    pub init_policy: &'a [u8],
    pub init_event_log: &'a [u8],
}

impl<'a> InitData<'a> {
    pub fn read_from_bytes(b: &'a [u8]) -> Option<Self> {
        if b.len() < 20 || &b[..8] != MIGTD_DATA_SIGNATURE {
            return None;
        }

        let version = u32::from_le_bytes(b[8..12].try_into().unwrap());
        let length = u32::from_le_bytes(b[12..16].try_into().unwrap());
        let num_entries = u32::from_le_bytes(b[16..20].try_into().unwrap());

        if version != 0x00010000 || b.len() < length as usize {
            return None;
        }

        let mut offset = 20;
        let mut init_report = None;
        let mut init_policy = None;
        let mut init_event_log = None;
        for _ in 0..num_entries {
            let entry = MigtdDateEntry::read_from_bytes(&b[offset..])?;
            match entry.r#type {
                MIGTD_DATA_TYPE_INIT_MIG_POLICY => init_policy = Some(entry.value),
                MIGTD_DATA_TYPE_INIT_TD_REPORT => {
                    if entry.value.len() > 1024 {
                        return None;
                    }
                    init_report = Some(entry.value.to_vec())
                }
                MIGTD_DATA_TYPE_INIT_EVENT_LOG => init_event_log = Some(entry.value),
                _ => return None,
            }
            offset += entry.length as usize + 8;
        }

        Some(Self {
            init_report: init_report?,
            init_policy: init_policy?,
            init_event_log: init_event_log?,
        })
    }

    pub fn get_from_local() -> Option<Self> {
        Some(Self {
            init_report: tdx_tdcall::tdreport::tdcall_report(&[0u8; 64])
                .ok()?
                .as_bytes()
                .to_vec(),
            init_policy: config::get_policy()?,
            init_event_log: event_log::get_event_log()?,
        })
    }
}

pub struct MigtdDateEntry<'a> {
    pub r#type: u32,
    pub length: u32,
    pub value: &'a [u8],
}

impl<'a> MigtdDateEntry<'a> {
    pub fn read_from_bytes(b: &'a [u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }

        let r#type = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let length = u32::from_le_bytes(b[4..8].try_into().unwrap());

        if b.len() < length as usize + 8 {
            return None;
        }

        Some(Self {
            r#type,
            length,
            value: &b[8..8 + length as usize],
        })
    }
}

pub(super) async fn rebinding_old_pre_session_data_exchange(
    transport: &mut TransportType,
    init_policy: &[u8],
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
    info: &RebindingInfo<'_>,
    data: &mut Vec<u8>,
) -> Result<(), MigrationResult> {
    let mut transport = setup_transport(info.mig_request_id, data).await?;

    // Exchange policy firstly because of the message size limitation of TLS protocol
    const PRE_SESSION_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    if info.rebinding_src == 1 {
        let local_data = InitData::get_from_local().ok_or(MigrationResult::InvalidParameter)?;
        let init_migtd_data = info
            .init_migtd_data
            .as_ref()
            .or(Some(&local_data))
            .ok_or(MigrationResult::InvalidParameter)?;
        let remote_policy = Box::pin(with_timeout(
            PRE_SESSION_TIMEOUT,
            rebinding_old_pre_session_data_exchange(&mut transport, init_migtd_data.init_policy),
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
        match info.operation {
            MIGTD_REBIND_OP_PREPARE => {
                rebinding_old_prepare(transport, info, &init_migtd_data, data, remote_policy)
                    .await?
            }
            MIGTD_REBIND_OP_FINALIZE => rebinding_old_finalize(info, data).await?,
            _ => return Err(MigrationResult::InvalidParameter),
        }

        #[cfg(feature = "spdm_attestation")]
        match info.operation {
            MIGTD_REBIND_OP_PREPARE => {
                rebinding_old_spdm(
                    transport,
                    info,
                    data,
                    #[cfg(feature = "policy_v2")]
                    remote_policy,
                )
                .await?
            }
            MIGTD_REBIND_OP_FINALIZE => rebinding_old_finalize(info, data).await?,
            _ => return Err(MigrationResult::InvalidParameter),
        }
    } else {
        let pre_session_data = Box::pin(with_timeout(
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
        match info.operation {
            MIGTD_REBIND_OP_PREPARE => {
                rebinding_new_prepare(transport, info, data, pre_session_data).await?
            }
            MIGTD_REBIND_OP_FINALIZE => rebinding_new_finalize(info, data).await?,
            _ => return Err(MigrationResult::InvalidParameter),
        }

        #[cfg(feature = "spdm_attestation")]
        match info.operation {
            MIGTD_REBIND_OP_PREPARE => {
                rebinding_new_spdm(
                    transport,
                    info,
                    data,
                    #[cfg(feature = "policy_v2")]
                    pre_session_data,
                )
                .await?
            }
            MIGTD_REBIND_OP_FINALIZE => rebinding_new_finalize(info, data).await?,
            _ => return Err(MigrationResult::InvalidParameter),
        }
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
pub async fn rebinding_old_spdm(
    transport: TransportType,
    info: &RebindingInfo<'_>,
    _data: &mut Vec<u8>,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<(), MigrationResult> {
    const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    let mut spdm_requester = spdm::spdm_requester(transport).map_err(|_e| {
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
    Ok(())
}

#[cfg(feature = "spdm_attestation")]
pub async fn rebinding_new_spdm(
    transport: TransportType,
    info: &RebindingInfo<'_>,
    _data: &mut Vec<u8>,
    #[cfg(feature = "policy_v2")] remote_policy: Vec<u8>,
) -> Result<(), MigrationResult> {
    const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    let mut spdm_responder = spdm::spdm_responder(transport).map_err(|_e| {
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
    Ok(())
}

pub async fn rebinding_old_prepare(
    transport: TransportType,
    info: &RebindingInfo<'_>,
    init_migtd_data: &InitData<'_>,
    data: &mut Vec<u8>,
    remote_policy: Vec<u8>,
) -> Result<(), MigrationResult> {
    let servtd_ext = read_servtd_ext(info.binding_handle, &info.target_td_uuid)?;
    let init_policy_hash = digest_sha384(init_migtd_data.init_policy)?;

    // TLS client
    let mut ratls_client = ratls::client_rebinding(
        transport,
        remote_policy,
        &init_policy_hash,
        &init_migtd_data.init_report,
        init_migtd_data.init_event_log,
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

    let rebind_token = create_rebind_token(info)?;
    tls_send_rebind_token(&mut ratls_client, &rebind_token).await?;

    approve_rebinding(info, &rebind_token)?;

    shutdown_transport(ratls_client.transport_mut(), info.mig_request_id, data).await?;
    Ok(())
}

pub async fn rebinding_old_finalize(
    _info: &RebindingInfo<'_>,
    _data: &mut Vec<u8>,
) -> Result<(), MigrationResult> {
    Ok(())
}

async fn rebinding_new_prepare(
    transport: TransportType,
    info: &RebindingInfo<'_>,
    data: &mut Vec<u8>,
    pre_session_data: Vec<u8>,
) -> Result<(), MigrationResult> {
    // TLS server
    let mut ratls_server = ratls::server_rebinding(transport, pre_session_data).map_err(|_| {
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
    let rebind_token = tls_receive_rebind_token(&mut ratls_server).await?;
    if rebind_token.target_td_uuid != info.target_td_uuid {
        return Err(MigrationResult::InvalidParameter);
    }

    write_rebinding_session_token(&rebind_token.token)?;
    write_servtd_rebind_attr(&servtd_ext.cur_servtd_attr)?;
    write_approved_servtd_ext_hash(&servtd_ext.calculate_approved_servtd_ext_hash()?)?;

    shutdown_transport(ratls_server.transport_mut(), info.mig_request_id, data).await?;
    Ok(())
}

async fn rebinding_new_finalize(
    _info: &RebindingInfo<'_>,
    _data: &mut Vec<u8>,
) -> Result<(), MigrationResult> {
    write_rebinding_session_token(&[0u8; 32])?;
    write_approved_servtd_ext_hash(&[0u8; SHA384_DIGEST_SIZE])?;
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

pub fn approve_rebinding(
    info: &RebindingInfo,
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

pub fn create_rebind_token(info: &RebindingInfo) -> Result<RebindingToken, MigrationResult> {
    let mut token = [0u8; 32];
    let rng = SystemRandom::new();
    rng.fill(&mut token)
        .map_err(|_| MigrationResult::InvalidParameter)?;

    Ok(RebindingToken {
        token,
        target_td_uuid: info.target_td_uuid,
    })
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
