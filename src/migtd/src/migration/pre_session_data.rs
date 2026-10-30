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
    // 0x0200: peer data is a sequence of TLV items.
    const LOWEST_VERSION: u16 = 0x0200;
    const HIGHEST_VERSION: u16 = 0x0200;

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
/// peer-data blob. `servtd_corim` is `None` when the peer sent no TCB mapping item.
pub(crate) type PeerData<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>);

// Peer-data TLV item types: one item per MigTD CFV artifact.
const PEER_ITEM_POLICY_ISSUER_CHAIN: u32 = 0x0001;
const PEER_ITEM_POLICY_DATA: u32 = 0x0002;
// servTD TCB mapping. Optional: omitted when no mapping is enrolled.
const PEER_ITEM_SERVTD_TCB_MAPPING: u32 = 0x0003;
/// Type (u32 LE) + Length (u32 LE).
const PEER_ITEM_HEADER_SIZE: usize = 8;

fn push_peer_item(blob: &mut Vec<u8>, item_type: u32, value: &[u8]) -> Option<()> {
    let len = u32::try_from(value.len()).ok()?;
    blob.extend_from_slice(&item_type.to_le_bytes());
    blob.extend_from_slice(&len.to_le_bytes());
    blob.extend_from_slice(value);
    Some(())
}

/// Encode `(policy, issuer_chain, servtd_corim)` into the peer-data blob as TLV
/// items in ascending type order: issuer chain, policy, then the TCB mapping item,
/// which is omitted when empty.
///
/// Format: repeated `[u32 LE type][u32 LE length][value]`.
///
/// Returns `None` if any length exceeds `u32::MAX`.
pub(crate) fn encode_peer_data(
    policy: &[u8],
    issuer_chain: &[u8],
    servtd_corim: &[u8],
) -> Option<Vec<u8>> {
    let mut blob = Vec::with_capacity(
        3 * PEER_ITEM_HEADER_SIZE + issuer_chain.len() + policy.len() + servtd_corim.len(),
    );
    push_peer_item(&mut blob, PEER_ITEM_POLICY_ISSUER_CHAIN, issuer_chain)?;
    push_peer_item(&mut blob, PEER_ITEM_POLICY_DATA, policy)?;
    if !servtd_corim.is_empty() {
        push_peer_item(&mut blob, PEER_ITEM_SERVTD_TCB_MAPPING, servtd_corim)?;
    }
    Some(blob)
}

/// Decode a peer-data blob produced by [`encode_peer_data`].
///
/// Returns borrowed `(policy, issuer_chain, servtd_corim)` slices. Rejects
/// out-of-order or duplicate types, unknown types, truncated items, trailing
/// bytes, a missing issuer chain or policy, an empty TCB mapping item, and a
/// mapping larger than [`MAX_PEER_SERVTD_CORIM_SIZE`] before the caller can
/// allocate/parse it.
pub(crate) fn decode_peer_data(data: &[u8]) -> Option<PeerData<'_>> {
    let mut rest = data;
    let mut last_type: Option<u32> = None;
    let mut issuer_chain = None;
    let mut policy = None;
    let mut servtd_corim = None;

    while !rest.is_empty() {
        if rest.len() < PEER_ITEM_HEADER_SIZE {
            return None;
        }
        let item_type = u32::from_le_bytes(rest[..4].try_into().ok()?);
        let len = u32::from_le_bytes(rest[4..8].try_into().ok()?) as usize;
        let end = PEER_ITEM_HEADER_SIZE.checked_add(len)?;
        if rest.len() < end {
            return None;
        }
        let value = &rest[PEER_ITEM_HEADER_SIZE..end];
        rest = &rest[end..];

        // Strictly ascending: also rejects duplicates.
        if last_type.is_some_and(|last| item_type <= last) {
            return None;
        }
        last_type = Some(item_type);

        match item_type {
            PEER_ITEM_POLICY_ISSUER_CHAIN => issuer_chain = Some(value),
            PEER_ITEM_POLICY_DATA => policy = Some(value),
            PEER_ITEM_SERVTD_TCB_MAPPING => {
                if value.is_empty() || value.len() > MAX_PEER_SERVTD_CORIM_SIZE {
                    return None;
                }
                servtd_corim = Some(value);
            }
            _ => return None,
        }
    }

    Some((policy?, issuer_chain?, servtd_corim))
}

/// Build the local peer-data blob from configured policy, issuer chain, and
/// (when enrolled) signed servTD TCB-mapping CoRIM.
#[cfg(feature = "policy_v2")]
pub(crate) fn local_peer_data() -> Option<Vec<u8>> {
    let policy = crate::config::get_policy()?;
    // Send the signer-anchor source: the enrolled 48-byte digest, else
    // the policy issuer chain PEM. Both use `policy::resolve_signer_anchor`.
    let issuer_chain = crate::config::get_signer_anchor_source()?;
    // Send our own signed CoRIM (if enrolled) so the peer resolves *our*
    // current/init hashes through *our* authenticated mapping instead of
    // theirs. Absent the `servtd_corim` feature, or when nothing is
    // enrolled, send an explicit zero length. The peer must then use our JSON
    // `servtdCollateral` mapping, or reject us if it is absent.
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

    fn item(item_type: u32, value: &[u8]) -> Vec<u8> {
        let mut v = item_type.to_le_bytes().to_vec();
        v.extend_from_slice(&(value.len() as u32).to_le_bytes());
        v.extend_from_slice(value);
        v
    }

    fn blob_with_mapping() -> Vec<u8> {
        encode_peer_data(b"policy", b"chain", b"mapping").unwrap()
    }

    #[test]
    fn round_trip_with_corim() {
        let blob = encode_peer_data(b"policy", b"chain", b"corim").unwrap();
        let (policy, chain, corim) = decode_peer_data(&blob).unwrap();
        assert_eq!(policy, b"policy");
        assert_eq!(chain, b"chain");
        assert_eq!(corim, Some(b"corim".as_slice()));
    }

    #[test]
    fn empty_mapping_omits_the_item() {
        let blob = encode_peer_data(b"p", b"c", b"").unwrap();
        assert_eq!(blob, b"\x01\0\0\0\x01\0\0\0c\x02\0\0\0\x01\0\0\0p");
        let (policy, chain, mapping) = decode_peer_data(&blob).unwrap();
        assert_eq!(
            (policy, chain, mapping),
            (b"p".as_slice(), b"c".as_slice(), None)
        );
    }

    #[test]
    fn encoding_is_tlv_in_type_order() {
        let blob = encode_peer_data(b"p", b"c", b"m").unwrap();
        assert_eq!(
            blob,
            b"\x01\0\0\0\x01\0\0\0c\x02\0\0\0\x01\0\0\0p\x03\0\0\0\x01\0\0\0m"
        );
    }

    #[test]
    fn missing_chain_or_policy_is_rejected() {
        let chain = item(PEER_ITEM_POLICY_ISSUER_CHAIN, b"c");
        let policy = item(PEER_ITEM_POLICY_DATA, b"p");
        assert!(decode_peer_data(&chain).is_none());
        assert!(decode_peer_data(&policy).is_none());
        assert!(decode_peer_data(&[]).is_none());
        assert!(decode_peer_data(&[chain, policy].concat()).is_some());
    }

    #[test]
    fn truncated_blob_is_rejected() {
        let blob = blob_with_mapping();
        // A cut right after the policy item is a valid blob without a TCB mapping.
        let valid_len = blob.len() - (PEER_ITEM_HEADER_SIZE + b"mapping".len());
        for cut in 0..blob.len() {
            if cut != valid_len {
                assert!(
                    decode_peer_data(&blob[..cut]).is_none(),
                    "accepted cut {cut}"
                );
            }
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut blob = blob_with_mapping();
        blob.push(0xAA);
        assert!(decode_peer_data(&blob).is_none());
    }

    #[test]
    fn duplicate_or_unordered_types_are_rejected() {
        let mut dup = blob_with_mapping();
        dup.extend(item(PEER_ITEM_SERVTD_TCB_MAPPING, b"again"));
        assert!(decode_peer_data(&dup).is_none());

        let unordered = [
            item(PEER_ITEM_POLICY_DATA, b"p"),
            item(PEER_ITEM_POLICY_ISSUER_CHAIN, b"c"),
        ]
        .concat();
        assert!(decode_peer_data(&unordered).is_none());
    }

    #[test]
    fn unknown_types_are_rejected() {
        for unknown in [0x0000, 0x0004, 0x8001, u32::MAX] {
            let mut blob = blob_with_mapping();
            blob.extend(item(unknown, b"x"));
            assert!(decode_peer_data(&blob).is_none(), "accepted {unknown:#x}");
        }
    }

    #[test]
    fn zero_length_mapping_item_is_rejected() {
        let blob = [
            item(PEER_ITEM_POLICY_ISSUER_CHAIN, b"c"),
            item(PEER_ITEM_POLICY_DATA, b"p"),
            item(PEER_ITEM_SERVTD_TCB_MAPPING, b""),
        ]
        .concat();
        assert!(decode_peer_data(&blob).is_none());
    }

    #[test]
    fn oversized_mapping_is_rejected_and_limit_is_accepted() {
        let oversized = vec![0u8; MAX_PEER_SERVTD_CORIM_SIZE + 1];
        let blob = encode_peer_data(b"p", b"c", &oversized).unwrap();
        assert!(decode_peer_data(&blob).is_none());

        let at_limit = vec![0x42u8; MAX_PEER_SERVTD_CORIM_SIZE];
        let blob = encode_peer_data(b"p", b"c", &at_limit).unwrap();
        let (_, _, mapping) = decode_peer_data(&blob).unwrap();
        assert_eq!(mapping, Some(at_limit.as_slice()));
    }

    #[test]
    fn oversized_length_is_rejected() {
        let mut blob = PEER_ITEM_POLICY_ISSUER_CHAIN.to_le_bytes().to_vec();
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        blob.extend_from_slice(b"c");
        assert!(decode_peer_data(&blob).is_none());
    }
}
