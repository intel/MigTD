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
const TDCS_FIELD_WRITE_MASK: u64 = u64::MAX;

const TLS_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
                                                       // FIXME: Need VMM provide socket information
const MIGTD_DATA_SIGNATURE: &[u8] = b"MIGTDATA";
const MIGTD_DATA_TYPE_TDINFO: u32 = 0;

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

pub struct RebindingInfo {
    pub mig_request_id: u64,
    pub rebinding_src: u8,
    pub has_init_data: u8,
    pub target_td_uuid: [u64; 4],
    pub binding_handle: u64,
    pub init_migtd_data: Option<InitData>,
}

impl RebindingInfo {
    pub fn read_from_bytes(b: &[u8]) -> Option<Self> {
        // Check the length of input and the reserved fields (bytes 10-15 per GHCI 1.5)
        if b.len() < 56 || b[10..16] != [0; 6] {
            return None;
        }
        let mig_request_id = u64::from_le_bytes(b[..8].try_into().unwrap());
        let rebinding_src = b[8];
        let has_init_data = b[9];

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
            target_td_uuid,
            binding_handle,
            init_migtd_data,
        })
    }
}

pub struct InitData {
    /// The TDINFO_STRUCT of the initial MigTD (per GHCI 1.5, MIGTD_DATA type 0).
    pub init_tdinfo: Vec<u8>,
}

impl InitData {
    /// TDINFO_STRUCT field offsets and sizes (per TDX Module ABI).
    const TDINFO_MROWNER_OFFSET: usize = 112; // attributes(8) + xfam(8) + mrtd(48) + mrconfig_id(48)
    const TDINFO_MROWNERCONFIG_OFFSET: usize = 160; // MROWNER_OFFSET + 48
    const TDINFO_FIELD_SIZE: usize = SHA384_DIGEST_SIZE;
    const TDINFO_MIN_SIZE: usize = 512;

    /// Extract mrowner from the TDINFO_STRUCT.
    /// Per GHCI 1.5: VMM puts migpolicy.policy_key in tdinfo.mrowner.
    pub fn mrowner(&self) -> &[u8] {
        &self.init_tdinfo[Self::TDINFO_MROWNER_OFFSET..Self::TDINFO_MROWNER_OFFSET + Self::TDINFO_FIELD_SIZE]
    }

    /// Extract mrownerconfig from the TDINFO_STRUCT.
    /// Per GHCI 1.5: VMM puts migpolicy.policy_svn in tdinfo.mrownerconfig.
    pub fn mrownerconfig(&self) -> &[u8] {
        &self.init_tdinfo[Self::TDINFO_MROWNERCONFIG_OFFSET..Self::TDINFO_MROWNERCONFIG_OFFSET + Self::TDINFO_FIELD_SIZE]
    }

    pub fn read_from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 20 || &b[..8] != MIGTD_DATA_SIGNATURE {
            return None;
        }

        let version = u32::from_le_bytes(b[8..12].try_into().unwrap());
        let length = u32::from_le_bytes(b[12..16].try_into().unwrap());
        let num_entries = u32::from_le_bytes(b[16..20].try_into().unwrap());

        // Per GHCI 1.5: version must be 0x00010000, numberOfEntry must be 1 (tdinfo)
        if version != 0x00010000 || b.len() < length as usize || num_entries != 1 {
            return None;
        }

        let entry = MigtdDataEntry::read_from_bytes(&b[20..])?;
        if entry.r#type != MIGTD_DATA_TYPE_TDINFO {
            return None;
        }

        if entry.value.len() < Self::TDINFO_MIN_SIZE {
            return None;
        }

        Some(Self {
            init_tdinfo: entry.value.to_vec(),
        })
    }

    pub fn write_into_bytes(&self, buf: &mut Vec<u8>) {
        let start_len = buf.len();
        buf.extend_from_slice(MIGTD_DATA_SIGNATURE);
        buf.extend_from_slice(&0x00010000u32.to_le_bytes()); // Version

        // Placeholder for length.
        buf.extend_from_slice(&0u32.to_le_bytes());

        // Per GHCI 1.5: numberOfEntry = 1, entry type 0 = tdinfo
        buf.extend_from_slice(&1u32.to_le_bytes()); // num_entries

        buf.extend_from_slice(&MIGTD_DATA_TYPE_TDINFO.to_le_bytes());
        buf.extend_from_slice(&(self.init_tdinfo.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.init_tdinfo);

        let total_size = (buf.len() - start_len) as u32;

        // Update length field
        let length_offset = start_len + 12;
        buf[length_offset..length_offset + 4].copy_from_slice(&total_size.to_le_bytes());
    }

    pub fn get_from_local(report_data: &[u8; 64]) -> Option<Self> {
        let report = tdx_tdcall::tdreport::tdcall_report(report_data).ok()?;
        Some(Self {
            init_tdinfo: report.td_info.as_bytes().to_vec(),
        })
    }
}

pub struct MigtdDataEntry<'a> {
    pub r#type: u32,
    pub length: u32,
    pub value: &'a [u8],
}

impl<'a> MigtdDataEntry<'a> {
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
    init_tdinfo: &[u8],
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

    send_pre_session_data_packet(init_tdinfo, transport)
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

    let init_tdinfo = receive_pre_session_data_packet(transport)
        .await
        .map_err(|e| {
            log::error!(
                "pre_session_data_exchange: receive init_tdinfo error: {:?}\n",
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
    policy_buffer.extend_from_slice(&(init_tdinfo.len() as u32).to_le_bytes());
    policy_buffer.extend_from_slice(&init_tdinfo);

    Ok(policy_buffer)
}

pub async fn start_rebinding(
    info: &RebindingInfo,
    data: &mut Vec<u8>,
) -> Result<(), MigrationResult> {
    let mut transport = setup_transport(info.mig_request_id).await?;

    // Exchange policy firstly because of the message size limitation of TLS protocol
    const PRE_SESSION_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds
    if info.rebinding_src == 1 {
        let local_data =
            InitData::get_from_local(&[0u8; 64]).ok_or(MigrationResult::InvalidParameter)?;
        let init_migtd_data = info
            .init_migtd_data
            .as_ref()
            .or(Some(&local_data))
            .ok_or(MigrationResult::InvalidParameter)?;
        let remote_policy = Box::pin(with_timeout(
            PRE_SESSION_TIMEOUT,
            rebinding_old_pre_session_data_exchange(&mut transport, &init_migtd_data.init_tdinfo),
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
        rebinding_old_prepare(transport, info, &init_migtd_data, data, remote_policy).await?;

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
    info: &RebindingInfo,
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
    info: &RebindingInfo,
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
    info: &RebindingInfo,
    init_migtd_data: &InitData,
    data: &mut Vec<u8>,
    remote_policy: Vec<u8>,
) -> Result<(), MigrationResult> {
    let servtd_ext = read_servtd_ext(info.binding_handle, &info.target_td_uuid)?;

    // Per GHCI 1.5: init policy key hash is in tdinfo.mrowner.
    // Use mrowner directly as the init_policy_hash equivalent.
    let init_policy_hash = init_migtd_data.mrowner().to_vec();

    // Per GHCI 1.5: init_tdinfo replaces the old init_report (full TDREPORT).
    // The TDINFO_STRUCT contains all the measurement fields needed for verification.
    let init_tdinfo = &init_migtd_data.init_tdinfo;

    // Per GHCI 1.5: init_event_log is no longer part of MIGTD_DATA.
    // Use local event log; RATLS cert still carries init_event_log extension
    // for responder-side verification of init RTMRs.
    let init_event_log = event_log::get_event_log().unwrap_or(&[]);

    // TLS client
    let mut ratls_client = ratls::client_rebinding(
        transport,
        remote_policy,
        &init_policy_hash,
        init_tdinfo,
        init_event_log,
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
    info: &RebindingInfo,
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
    use alloc::vec;

    /// Build a minimal valid MIGTD_DATA blob containing one TDINFO_STRUCT entry.
    fn build_migtd_data(tdinfo: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MIGTD_DATA_SIGNATURE); // "MIGTDATA"
        buf.extend_from_slice(&0x00010000u32.to_le_bytes()); // version
        buf.extend_from_slice(&0u32.to_le_bytes()); // length placeholder
        buf.extend_from_slice(&1u32.to_le_bytes()); // num_entries = 1
        // Entry: type 0 (TDINFO)
        buf.extend_from_slice(&MIGTD_DATA_TYPE_TDINFO.to_le_bytes());
        buf.extend_from_slice(&(tdinfo.len() as u32).to_le_bytes());
        buf.extend_from_slice(tdinfo);
        // Patch length
        let total = buf.len() as u32;
        buf[12..16].copy_from_slice(&total.to_le_bytes());
        buf
    }

    /// Create a 512-byte TDINFO_STRUCT with known mrowner and mrownerconfig.
    fn make_tdinfo(mrowner: &[u8; 48], mrownerconfig: &[u8; 48]) -> Vec<u8> {
        let mut tdinfo = vec![0u8; 512];
        // mrowner at offset 112..160
        tdinfo[112..160].copy_from_slice(mrowner);
        // mrownerconfig at offset 160..208
        tdinfo[160..208].copy_from_slice(mrownerconfig);
        tdinfo
    }

    // --- InitData tests ---

    #[test]
    fn test_initdata_read_write_roundtrip() {
        let mrowner = [0xAAu8; 48];
        let mrownerconfig = [0xBBu8; 48];
        let tdinfo = make_tdinfo(&mrowner, &mrownerconfig);

        let data = build_migtd_data(&tdinfo);
        let init = InitData::read_from_bytes(&data).expect("should parse valid MIGTD_DATA");

        assert_eq!(init.init_tdinfo.len(), 512);
        assert_eq!(init.init_tdinfo, tdinfo);

        // Round-trip: write back and re-parse
        let mut buf = Vec::new();
        init.write_into_bytes(&mut buf);
        let init2 = InitData::read_from_bytes(&buf).expect("round-trip should parse");
        assert_eq!(init2.init_tdinfo, tdinfo);
    }

    #[test]
    fn test_initdata_mrowner_mrownerconfig() {
        let mrowner = [0x11u8; 48];
        let mrownerconfig = [0x22u8; 48];
        let tdinfo = make_tdinfo(&mrowner, &mrownerconfig);
        let data = build_migtd_data(&tdinfo);

        let init = InitData::read_from_bytes(&data).unwrap();
        assert_eq!(init.mrowner(), &mrowner);
        assert_eq!(init.mrownerconfig(), &mrownerconfig);
    }

    #[test]
    fn test_initdata_rejects_bad_signature() {
        let tdinfo = vec![0u8; 512];
        let mut data = build_migtd_data(&tdinfo);
        data[0] = b'X'; // corrupt signature
        assert!(InitData::read_from_bytes(&data).is_none());
    }

    #[test]
    fn test_initdata_rejects_bad_version() {
        let tdinfo = vec![0u8; 512];
        let mut data = build_migtd_data(&tdinfo);
        data[8..12].copy_from_slice(&0x00020000u32.to_le_bytes()); // wrong version
        assert!(InitData::read_from_bytes(&data).is_none());
    }

    #[test]
    fn test_initdata_rejects_multiple_entries() {
        let tdinfo = vec![0u8; 512];
        let mut data = build_migtd_data(&tdinfo);
        data[16..20].copy_from_slice(&2u32.to_le_bytes()); // num_entries = 2
        assert!(InitData::read_from_bytes(&data).is_none());
    }

    #[test]
    fn test_initdata_rejects_wrong_type() {
        let tdinfo = vec![0u8; 512];
        let mut data = build_migtd_data(&tdinfo);
        data[20..24].copy_from_slice(&1u32.to_le_bytes()); // type 1 instead of 0
        assert!(InitData::read_from_bytes(&data).is_none());
    }

    #[test]
    fn test_initdata_rejects_short_tdinfo() {
        let tdinfo = vec![0u8; 256]; // too small (< 512)
        let data = build_migtd_data(&tdinfo);
        assert!(InitData::read_from_bytes(&data).is_none());
    }

    #[test]
    fn test_initdata_rejects_empty() {
        assert!(InitData::read_from_bytes(&[]).is_none());
        assert!(InitData::read_from_bytes(&[0u8; 10]).is_none());
    }

    // --- RebindingInfo tests ---

    /// Build a minimal RebindingInfo byte buffer.
    fn build_rebinding_info(
        mig_request_id: u64,
        rebinding_src: u8,
        has_init_data: u8,
        uuid: [u64; 4],
        binding_handle: u64,
        init_data: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&mig_request_id.to_le_bytes()); // 0..8
        buf.push(rebinding_src); // 8
        buf.push(has_init_data); // 9
        buf.extend_from_slice(&[0u8; 6]); // 10..16 reserved
        for u in &uuid {
            buf.extend_from_slice(&u.to_le_bytes()); // 16..48
        }
        buf.extend_from_slice(&binding_handle.to_le_bytes()); // 48..56
        if let Some(data) = init_data {
            buf.extend_from_slice(data);
        }
        buf
    }

    #[test]
    fn test_rebinding_info_no_init_data() {
        let buf = build_rebinding_info(42, 1, 0, [1, 2, 3, 4], 99, None);
        let info = RebindingInfo::read_from_bytes(&buf).expect("should parse");
        assert_eq!(info.mig_request_id, 42);
        assert_eq!(info.rebinding_src, 1);
        assert_eq!(info.has_init_data, 0);
        assert_eq!(info.target_td_uuid, [1, 2, 3, 4]);
        assert_eq!(info.binding_handle, 99);
        assert!(info.init_migtd_data.is_none());
    }

    #[test]
    fn test_rebinding_info_with_init_data() {
        let tdinfo = make_tdinfo(&[0xCAu8; 48], &[0xFEu8; 48]);
        let migtd_data = build_migtd_data(&tdinfo);
        let buf = build_rebinding_info(7, 0, 1, [10, 20, 30, 40], 55, Some(&migtd_data));
        let info = RebindingInfo::read_from_bytes(&buf).expect("should parse with init data");
        assert_eq!(info.mig_request_id, 7);
        assert_eq!(info.has_init_data, 1);
        let init = info.init_migtd_data.as_ref().unwrap();
        assert_eq!(init.mrowner(), &[0xCAu8; 48]);
        assert_eq!(init.mrownerconfig(), &[0xFEu8; 48]);
    }

    #[test]
    fn test_rebinding_info_rejects_short_buffer() {
        assert!(RebindingInfo::read_from_bytes(&[0u8; 10]).is_none());
        assert!(RebindingInfo::read_from_bytes(&[0u8; 55]).is_none()); // 55 < 56
    }

    #[test]
    fn test_rebinding_info_rejects_nonzero_reserved() {
        let mut buf = build_rebinding_info(1, 0, 0, [0; 4], 0, None);
        buf[10] = 0xFF; // reserved byte not zero
        assert!(RebindingInfo::read_from_bytes(&buf).is_none());
    }

    #[test]
    fn test_rebinding_info_rejects_has_init_data_without_data() {
        // has_init_data=1 but no data bytes following → InitData::read_from_bytes fails
        let buf = build_rebinding_info(1, 0, 1, [0; 4], 0, None);
        assert!(RebindingInfo::read_from_bytes(&buf).is_none());
    }
}
