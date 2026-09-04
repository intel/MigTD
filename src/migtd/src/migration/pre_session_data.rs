// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::MigrationResult;
use alloc::{vec, vec::Vec};
use async_io::{AsyncRead, AsyncWrite};

type Result<T> = core::result::Result<T, MigrationResult>;

/// Extension trait that logs an error (with the supplied context) before
/// propagating it. Intended for use with `?` to keep call sites concise.
pub(crate) trait LogErr<T, E> {
    fn log_err(self, ctx: &str) -> core::result::Result<T, E>;
}

impl<T, E: core::fmt::Debug> LogErr<T, E> for core::result::Result<T, E> {
    fn log_err(self, ctx: &str) -> core::result::Result<T, E> {
        self.map_err(|e| {
            log::error!("{} error: {:?}\n", ctx, e);
            e
        })
    }
}

#[repr(C)]
struct PreSessionMessage {
    pub r#type: u8,
    pub reserved: [u8; 3],
    pub length: u32, // Length in bytes of the message payload
}

impl PreSessionMessage {
    const PRE_SESSION_DATA_TYPE: u8 = 1;
    const START_SESSION_TYPE: u8 = 2;
    const HELLO_PACKET_TYPE: u8 = 0xff;

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    pub fn read_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            log::error!(
                "PreSessionMessage: Insufficient bytes to read header bytes.len() = {}\n",
                bytes.len()
            );
            return None;
        }
        let header = PreSessionMessage {
            r#type: bytes[0],
            reserved: bytes[1..4].try_into().unwrap(),
            length: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        };
        Some(header)
    }
}

#[repr(C)]
pub(super) struct HelloPacketPayload {
    magic_word: [u8; 4],
    lowest_supported_version: u16,
    highest_supported_version: u16,
}

impl HelloPacketPayload {
    const HELLO_PACKET_PAYLOAD_SIZE: usize = 8;
    const HELLO_PACKET_MAGIC_WORD: [u8; 4] = [b'M', b'G', b'T', b'D'];
    const LOWEST_VERSION: u16 = 0x0100;
    const HIGHEST_VERSION: u16 = 0x0100;

    pub const fn new() -> Self {
        Self {
            magic_word: Self::HELLO_PACKET_MAGIC_WORD,
            lowest_supported_version: Self::LOWEST_VERSION,
            highest_supported_version: Self::HIGHEST_VERSION,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    pub fn read_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            log::error!(
                "HelloPacketPayload: Insufficient bytes to read header bytes.len() = {}\n",
                bytes.len()
            );
            return None;
        }
        let payload = HelloPacketPayload {
            magic_word: bytes[..4].try_into().unwrap(),
            lowest_supported_version: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            highest_supported_version: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        };

        if payload.magic_word != HelloPacketPayload::HELLO_PACKET_MAGIC_WORD {
            log::error!("HelloPacketPayload: Invalid magic word in hello packet\n");
            return None;
        }
        Some(payload)
    }

    fn negotiate_supported_version(&self) -> Option<u16> {
        let low = core::cmp::max(Self::LOWEST_VERSION, self.lowest_supported_version);
        let high = core::cmp::min(Self::HIGHEST_VERSION, self.highest_supported_version);
        if low > high {
            None
        } else {
            Some(high)
        }
    }
}

pub(super) async fn send_pre_session_data<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
    data: &[u8],
) -> Result<()> {
    let mut sent = 0;
    while sent < data.len() {
        let n = transport.write(&data[sent..]).await.map_err(|e| {
            log::error!("send_pre_session_data: Network error: {:?}\n", e);
            MigrationResult::NetworkError
        })?;
        // Fail closed if the transport reports success without progress.
        if n == 0 {
            log::error!("send_pre_session_data: zero-length transport write\n");
            return Err(MigrationResult::NetworkError);
        }
        sent += n;
    }
    Ok(())
}

pub(super) async fn receive_pre_session_data<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
    data: &mut [u8],
) -> Result<()> {
    // The underlying transport (vsock/vmcall_raw/virtio_serial) is VMM-mediated
    // and blocks until data is available or returns an error — it does not
    // return 0 (EOF) like a POSIX socket would.
    let mut recvd = 0;
    while recvd < data.len() {
        let n = transport.read(&mut data[recvd..]).await.map_err(|e| {
            log::error!("receive_pre_session_data: Network error: {:?}\n", e);
            MigrationResult::NetworkError
        })?;
        if n == 0 {
            log::error!("receive_pre_session_data: EOF (peer closed connection)\n");
            return Err(MigrationResult::NetworkError);
        }
        recvd += n;
    }
    Ok(())
}

pub(super) async fn send_pre_session_data_packet<T: AsyncRead + AsyncWrite + Unpin>(
    pre_session_data: &[u8],
    transport: &mut T,
) -> Result<()> {
    let header = PreSessionMessage {
        r#type: PreSessionMessage::PRE_SESSION_DATA_TYPE,
        reserved: [0u8; 3],
        length: pre_session_data.len() as u32,
    };

    send_pre_session_data(transport, header.as_bytes())
        .await
        .map_err(|e| {
            log::error!("send_pre_session_data header: Network error: {:?}\n", e);
            e
        })?;
    send_pre_session_data(transport, pre_session_data)
        .await
        .map_err(|e| {
            log::error!(
                "send_pre_session_data pre_session_data: Network error: {:?}\n",
                e
            );
            e
        })
}

pub(super) async fn receive_pre_session_data_packet<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
) -> Result<Vec<u8>> {
    let mut header_buffer = [0u8; size_of::<PreSessionMessage>()];
    receive_pre_session_data(transport, &mut header_buffer)
        .await
        .map_err(|e| {
            log::error!("receive_pre_session_data header: Network error: {:?}\n", e);
            e
        })?;

    let header = PreSessionMessage::read_from_bytes(&header_buffer).ok_or_else(|| {
        log::error!("receive_pre_session_data_packet: Failed to read PreSessionMessage header\n");
        MigrationResult::InvalidParameter
    })?;
    if header.r#type != PreSessionMessage::PRE_SESSION_DATA_TYPE {
        log::error!("PreSessionMessage: Invalid type in pre-session data packet\n");
        return Err(MigrationResult::InvalidParameter);
    }

    let pre_session_data_payload_size = header.length as usize;

    // Bound the VMM-supplied payload length before allocating. Without this
    // check, the untrusted u32 length could request a roughly 4 GiB heap
    // allocation and abort MigTD. 1 MiB is well above expected policy and
    // issuer-chain sizes.
    const MAX_PRE_SESSION_PAYLOAD_SIZE: usize = 1 * 1024 * 1024;
    if pre_session_data_payload_size > MAX_PRE_SESSION_PAYLOAD_SIZE {
        log::error!(
            "receive_pre_session_data_packet: payload length {} exceeds max {}\n",
            pre_session_data_payload_size,
            MAX_PRE_SESSION_PAYLOAD_SIZE
        );
        return Err(MigrationResult::InvalidParameter);
    }

    let mut pre_session_data_payload = vec![0u8; pre_session_data_payload_size];
    receive_pre_session_data(transport, &mut pre_session_data_payload)
        .await
        .map_err(|e| {
            log::error!("receive_pre_session_data payload: Network error: {:?}\n", e);
            e
        })?;

    Ok(pre_session_data_payload)
}

pub(super) async fn send_start_session_packet<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
) -> Result<()> {
    let header = PreSessionMessage {
        r#type: PreSessionMessage::START_SESSION_TYPE,
        reserved: [0u8; 3],
        length: 0,
    };

    send_pre_session_data(transport, header.as_bytes())
        .await
        .map_err(|e| {
            log::error!("send_start_session_packet: Network error: {:?}\n", e);
            e
        })
}

pub(super) async fn receive_start_session_packet<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
) -> Result<()> {
    let mut header_buffer = [0u8; size_of::<PreSessionMessage>()];
    receive_pre_session_data(transport, &mut header_buffer)
        .await
        .map_err(|e| {
            log::error!("receive_start_session_packet: Network error: {:?}\n", e);
            e
        })?;

    let packet = PreSessionMessage::read_from_bytes(&header_buffer).ok_or_else(|| {
        log::error!("receive_start_session_packet: Failed to read PreSessionMessage header\n");
        MigrationResult::InvalidParameter
    })?;

    // Sanity checks
    if packet.r#type != PreSessionMessage::START_SESSION_TYPE {
        log::error!("PreSessionMessage: Invalid type in start session packet\n");
        return Err(MigrationResult::InvalidParameter);
    }
    if packet.length != 0 {
        log::error!("PreSessionMessage: Invalid length in start session packet\n");
        return Err(MigrationResult::InvalidParameter);
    }

    Ok(())
}

async fn send_hello_packet<T: AsyncRead + AsyncWrite + Unpin>(transport: &mut T) -> Result<()> {
    let header = PreSessionMessage {
        r#type: PreSessionMessage::HELLO_PACKET_TYPE,
        reserved: [0u8; 3],
        length: 8,
    };
    send_pre_session_data(transport, header.as_bytes())
        .await
        .map_err(|e| {
            log::error!("send_hello_packet: Network error: {:?}\n", e);
            e
        })?;

    let payload = HelloPacketPayload::new();
    send_pre_session_data(transport, payload.as_bytes())
        .await
        .map_err(|e| {
            log::error!("send_hello_packet: Network error: {:?}\n", e);
            e
        })
}

async fn receive_hello_packet<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
) -> Result<HelloPacketPayload> {
    let mut header_buffer = [0u8; size_of::<PreSessionMessage>()];
    receive_pre_session_data(transport, &mut header_buffer)
        .await
        .map_err(|e| {
            log::error!("receive_hello_packet: Network error: {:?}\n", e);
            e
        })?;

    let header = PreSessionMessage::read_from_bytes(&header_buffer).ok_or_else(|| {
        log::error!("receive_hello_packet: Failed to read PreSessionMessage header\n");
        MigrationResult::InvalidParameter
    })?;

    // Sanity checks
    if header.r#type != PreSessionMessage::HELLO_PACKET_TYPE {
        log::error!("PreSessionMessage: Invalid type in hello packet\n");
        return Err(MigrationResult::InvalidParameter);
    }
    if header.length as usize != HelloPacketPayload::HELLO_PACKET_PAYLOAD_SIZE {
        log::error!("PreSessionMessage: Invalid length in hello packet\n");
        return Err(MigrationResult::InvalidParameter);
    }

    // Receive hello packet payload
    let mut hello_payload = vec![0u8; HelloPacketPayload::HELLO_PACKET_PAYLOAD_SIZE];
    receive_pre_session_data(transport, &mut hello_payload)
        .await
        .map_err(|e| {
            log::error!("receive_hello_packet payload: Network error: {:?}\n", e);
            e
        })?;

    HelloPacketPayload::read_from_bytes(&hello_payload)
        .ok_or(MigrationResult::InvalidParameter)
        .map_err(|_| {
            log::error!("receive_hello_packet: Failed to read HelloPacketPayload\n");
            MigrationResult::InvalidParameter
        })
}

// Exchange hello packet and negotiate a pre-session message version
pub(super) async fn exchange_hello_packet<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
) -> Result<u16> {
    send_hello_packet(transport).await.map_err(|e| {
        log::error!("exchange_hello_packet: send_hello_packet error: {:?}\n", e);
        e
    })?;
    let remote = receive_hello_packet(transport).await.map_err(|e| {
        log::error!(
            "exchange_hello_packet: receive_hello_packet error: {:?}\n",
            e
        );
        e
    })?;

    remote
        .negotiate_supported_version()
        .ok_or(MigrationResult::InvalidParameter)
}

/// Attacker-influenced (VMM-relayed) peer servTD CoRIM size ceiling, enforced
/// at decode time before any CBOR/COSE parsing allocates
/// (`ServtdCorim::decode_signed`). Production TCB-mapping CoRIMs enrolled via
/// the policy-v2 tooling are on the order of a few KB per mapped release; 64
/// KiB comfortably covers a multi-release cumulative mapping while remaining
/// far below the overall 1 MiB pre-session payload cap
/// (`MAX_PRE_SESSION_PAYLOAD_SIZE`).
pub(crate) const MAX_PEER_SERVTD_CORIM_SIZE: usize = 64 * 1024;

/// Borrowed `(policy, issuer_chain, servtd_corim)` slices decoded from a
/// peer-data blob. `servtd_corim` is `None` when the peer sent no CoRIM (see
/// [`decode_peer_data`] for exactly when that occurs).
pub(crate) type PeerData<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>);

/// Encode `(policy, issuer_chain, servtd_corim)` into the peer-data blob.
///
/// Format: `[u32 LE policy_len][policy][u32 LE chain_len][issuer_chain]
/// [u32 LE corim_len][servtd_corim]`. The trailing CoRIM field is a
/// wire-compatible *addition*: `servtd_corim` may be empty (no CoRIM
/// enrolled locally), in which case `corim_len` is sent as `0` so the
/// decoder can distinguish "peer build understands the field but has
/// nothing to send" from "peer build predates the field". Returns `None` if
/// any length exceeds `u32::MAX`.
pub(crate) fn encode_peer_data(
    policy: &[u8],
    issuer_chain: &[u8],
    servtd_corim: &[u8],
) -> Option<Vec<u8>> {
    let policy_len = u32::try_from(policy.len()).ok()?;
    let chain_len = u32::try_from(issuer_chain.len()).ok()?;
    let corim_len = u32::try_from(servtd_corim.len()).ok()?;

    let mut blob = Vec::with_capacity(12 + policy.len() + issuer_chain.len() + servtd_corim.len());
    blob.extend_from_slice(&policy_len.to_le_bytes());
    blob.extend_from_slice(policy);
    blob.extend_from_slice(&chain_len.to_le_bytes());
    blob.extend_from_slice(issuer_chain);
    blob.extend_from_slice(&corim_len.to_le_bytes());
    blob.extend_from_slice(servtd_corim);
    Some(blob)
}

/// Decode a peer-data blob produced by [`encode_peer_data`].
///
/// Returns borrowed `(policy, issuer_chain, servtd_corim)` slices. The CoRIM
/// element is `None` both when a peer built before this field existed sent a
/// blob that ends exactly after `issuer_chain` (legacy 2-field framing) and
/// when a peer that understands the field sent an explicit empty CoRIM
/// (`corim_len == 0`, e.g. no CoRIM enrolled locally). A present CoRIM larger
/// than [`MAX_PEER_SERVTD_CORIM_SIZE`] is rejected before the caller can
/// allocate/parse it. Rejects trailing bytes in all cases.
pub(crate) fn decode_peer_data(data: &[u8]) -> Option<PeerData<'_>> {
    if data.len() < 4 {
        return None;
    }
    let policy_len = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
    let chain_len_offset = 4usize.checked_add(policy_len)?;
    if data.len() < chain_len_offset.checked_add(4)? {
        return None;
    }
    let policy = &data[4..chain_len_offset];
    let chain_len = u32::from_le_bytes(
        data[chain_len_offset..chain_len_offset + 4]
            .try_into()
            .ok()?,
    ) as usize;
    let chain_offset = chain_len_offset + 4;
    let chain_end = chain_offset.checked_add(chain_len)?;
    if data.len() < chain_end {
        return None;
    }
    let issuer_chain = &data[chain_offset..chain_end];

    // Legacy (pre-CoRIM-transport) framing: nothing follows the issuer chain.
    if data.len() == chain_end {
        return Some((policy, issuer_chain, None));
    }

    // New framing: a `u32` corim_len + corim bytes must follow exactly.
    if data.len() < chain_end.checked_add(4)? {
        return None;
    }
    let corim_len = u32::from_le_bytes(data[chain_end..chain_end + 4].try_into().ok()?) as usize;
    if corim_len > MAX_PEER_SERVTD_CORIM_SIZE {
        return None;
    }
    let corim_offset = chain_end + 4;
    let end = corim_offset.checked_add(corim_len)?;
    // Require exact length — reject trailing bytes.
    if data.len() != end {
        return None;
    }
    let servtd_corim = &data[corim_offset..end];
    let servtd_corim = if servtd_corim.is_empty() {
        None
    } else {
        Some(servtd_corim)
    };
    Some((policy, issuer_chain, servtd_corim))
}

/// Build the local peer-data blob from configured policy, issuer chain, and
/// (when enrolled) signed servTD TCB-mapping CoRIM.
#[cfg(feature = "policy_v2")]
pub(crate) fn local_peer_data() -> Option<Vec<u8>> {
    let policy = crate::config::get_policy()?;
    // Send the signer-anchor source: the 48-byte anchor when enrolled
    // (CoRIM-only), else the policy issuer chain PEM. The peer resolves either
    // form via `policy::resolve_signer_anchor`.
    let issuer_chain = crate::config::get_signer_anchor_source()?;
    // Send our own signed CoRIM (if enrolled) so the peer resolves *our*
    // current/init hashes through *our* authenticated mapping instead of
    // theirs. Absent the `servtd_corim` feature, or when nothing is
    // enrolled, send an empty field — the peer then falls back to whatever
    // JSON `servtdCollateral` our policy carries (or fails closed if we ship
    // neither).
    #[cfg(feature = "servtd_corim")]
    let servtd_corim = crate::config::get_servtd_corim().unwrap_or(&[]);
    #[cfg(not(feature = "servtd_corim"))]
    let servtd_corim: &[u8] = &[];
    encode_peer_data(policy, issuer_chain, servtd_corim)
}

/// Exchange peer-data blobs (policy + issuer chain) with the remote.
///
/// Returns the peer's blob, validated to be well-formed with non-empty
/// policy and issuer chain.
#[cfg(feature = "policy_v2")]
pub(crate) async fn pre_session_data_exchange<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
) -> Result<Vec<u8>> {
    let version = exchange_hello_packet(transport)
        .await
        .log_err("pre_session_data_exchange: exchange_hello_packet")?;
    log::info!("Pre-Session-Message Version: 0x{:04x}\n", version);

    let local_blob = local_peer_data().ok_or_else(|| {
        log::error!("pre_session_data_exchange: failed to build local peer_data blob\n");
        MigrationResult::InvalidParameter
    })?;

    send_pre_session_data_packet(&local_blob, transport)
        .await
        .log_err("pre_session_data_exchange: send_pre_session_data_packet")?;
    let peer_blob = receive_pre_session_data_packet(transport)
        .await
        .log_err("pre_session_data_exchange: receive_pre_session_data_packet")?;

    let (peer_policy, peer_issuer_chain, _peer_servtd_corim) = decode_peer_data(&peer_blob)
        .ok_or_else(|| {
            log::error!("pre_session_data_exchange: malformed peer_data blob\n");
            MigrationResult::InvalidParameter
        })?;
    if peer_policy.is_empty() || peer_issuer_chain.is_empty() {
        log::error!("pre_session_data_exchange: Received empty policy or issuer chain from peer\n");
        return Err(MigrationResult::InvalidParameter);
    }

    send_start_session_packet(transport)
        .await
        .log_err("pre_session_data_exchange: send_start_session_packet")?;
    receive_start_session_packet(transport)
        .await
        .log_err("pre_session_data_exchange: receive_start_session_packet")?;

    Ok(peer_blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_corim() {
        let blob = encode_peer_data(b"policy", b"chain", b"corim").unwrap();
        let (policy, chain, corim) = decode_peer_data(&blob).unwrap();
        assert_eq!(policy, b"policy");
        assert_eq!(chain, b"chain");
        assert_eq!(corim, Some(b"corim".as_slice()));
    }

    #[test]
    fn round_trip_with_empty_corim_is_none() {
        // A peer that understands the field but has nothing to send still
        // sends the length-prefixed (empty) field explicitly.
        let blob = encode_peer_data(b"policy", b"chain", b"").unwrap();
        let (policy, chain, corim) = decode_peer_data(&blob).unwrap();
        assert_eq!(policy, b"policy");
        assert_eq!(chain, b"chain");
        assert_eq!(corim, None);
    }

    #[test]
    fn legacy_two_field_blob_decodes_with_no_corim() {
        // Simulate a pre-#229 peer: no third field at all.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&6u32.to_le_bytes());
        legacy.extend_from_slice(b"policy");
        legacy.extend_from_slice(&5u32.to_le_bytes());
        legacy.extend_from_slice(b"chain");

        let (policy, chain, corim) = decode_peer_data(&legacy).unwrap();
        assert_eq!(policy, b"policy");
        assert_eq!(chain, b"chain");
        assert_eq!(corim, None);
    }

    #[test]
    fn oversized_corim_is_rejected() {
        let oversized = vec![0u8; MAX_PEER_SERVTD_CORIM_SIZE + 1];
        let blob = encode_peer_data(b"policy", b"chain", &oversized).unwrap();
        assert!(decode_peer_data(&blob).is_none());
    }

    #[test]
    fn corim_at_size_limit_is_accepted() {
        let at_limit = vec![0x42u8; MAX_PEER_SERVTD_CORIM_SIZE];
        let blob = encode_peer_data(b"policy", b"chain", &at_limit).unwrap();
        let (_, _, corim) = decode_peer_data(&blob).unwrap();
        assert_eq!(corim, Some(at_limit.as_slice()));
    }

    #[test]
    fn trailing_bytes_after_corim_are_rejected() {
        let mut blob = encode_peer_data(b"policy", b"chain", b"corim").unwrap();
        blob.push(0xAA);
        assert!(decode_peer_data(&blob).is_none());
    }

    #[test]
    fn truncated_corim_length_prefix_is_rejected() {
        let mut blob = encode_peer_data(b"policy", b"chain", b"corim").unwrap();
        let len_offset = blob.len() - 5 - 4;
        blob[len_offset..len_offset + 4].copy_from_slice(&100u32.to_le_bytes());
        assert!(decode_peer_data(&blob).is_none());
    }
}
