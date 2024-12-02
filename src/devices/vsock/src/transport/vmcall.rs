// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::protocol::field::HEADER_LEN;
use crate::protocol::Packet;
use crate::stream::{VsockStream, BINDING_PKT_QUEUES, CONNECTION_PKT_QUEUES};
use crate::{align_up, VsockAddr, VsockAddrPair, VsockTransportError, PAGE_SIZE};

use super::event::*;
use super::Result;

use alloc::vec::Vec;
use core::convert::TryInto;
use core::future::poll_fn;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Poll;
use td_payload::interrupt_handler_template;
use td_payload::mm::shared::SharedMemory;
use td_shim_interface::td_uefi_pi::pi::guid;
use tdx_tdcall::tdx;

const CURRENT_VERSION: u8 = 0;
const COMMAND_SEND: u8 = 3;
const COMMAND_RECV: u8 = 4;
const MAX_VSOCK_MTU: usize = 0x1000 * 16;
const VMCALL_COMMON_HEADER_LEN: usize = 36;
const VMCALL_STATUS_RESERVED: u32 = 0xffff_ffff;
const VMCALL_VECTOR: u8 = 0x52;

static VMCALL_FLAG: AtomicBool = AtomicBool::new(false);

const VMCALL_SERVICE_MIGTD_GUID: guid::Guid = guid::Guid::from_fields(
    0xe60e6330,
    0x1e09,
    0x4387,
    [0xa4, 0x44, 0x8f, 0x32, 0xb8, 0xd6, 0x11, 0xe5],
);

fn push_stream_queues(addrs: &VsockAddrPair, buf: Vec<u8>) {
    if buf.is_empty() {
        return;
    }

    if let Some(stream_queue) = CONNECTION_PKT_QUEUES.lock().get_mut(addrs) {
        stream_queue.push_back(buf);
    } else if let Some(stream_queue) = BINDING_PKT_QUEUES.lock().get_mut(&addrs.local) {
        stream_queue.push_back(buf);
    }
}

fn pop_stream_queues(addrs: &VsockAddrPair) -> Option<Vec<u8>> {
    if let Some(stream_queue) = CONNECTION_PKT_QUEUES.lock().get_mut(addrs) {
        stream_queue.pop_front()
    } else if let Some(stream_queue) = BINDING_PKT_QUEUES.lock().get_mut(&addrs.local) {
        stream_queue.pop_front()
    } else {
        None
    }
}

// Parse the packet header and data from the untrusted source.
//
// pkt = Stream Message Header + MigTD Communication Packet
fn recv_packet(pkt: &[u8]) -> Result<()> {
    let mut header = Vec::new();
    let mut data = Vec::new();

    if pkt.len() < HEADER_LEN {
        return Err(VsockTransportError::InvalidVsockPacket);
    }
    // Read out the packet header into a safe place
    header.extend_from_slice(&pkt[..HEADER_LEN]);

    // Parse the data length from the packet header and copy it out from DMA buffer
    let packet_hdr =
        Packet::new_checked(&header[..]).map_err(|_| VsockTransportError::InvalidVsockPacket)?;
    let data_len = packet_hdr.data_len();
    if data_len != 0 {
        if data_len as usize > pkt.len() - HEADER_LEN {
            return Err(VsockTransportError::InvalidParameter);
        }
        data.extend_from_slice(&pkt[HEADER_LEN..HEADER_LEN + data_len as usize])
    }

    let key = VsockAddrPair {
        local: VsockAddr::new(packet_hdr.dst_cid() as u32, packet_hdr.dst_port()),
        remote: VsockAddr::new(packet_hdr.src_cid() as u32, packet_hdr.src_port()),
    };

    push_stream_queues(&key, header);
    push_stream_queues(&key, data);

    Ok(())
}

pub fn vsock_transport_init() {
    register_callback(VMCALL_VECTOR, vmcall_notification);
    log::info!("Interrupt callback is registered for vmcall-vsock\n");
}

// Get current device CID
pub fn vsock_transport_get_cid() -> core::result::Result<u64, VsockTransportError> {
    Err(VsockTransportError::InvalidParameter)
}

pub async fn vsock_transport_enqueue(
    stream: &VsockStream,
    hdr: &[u8],
    buf: &[u8],
    timeout: u32,
) -> Result<usize> {
    let command_pages = align_up(VMCALL_COMMON_HEADER_LEN + hdr.len() + buf.len()) / PAGE_SIZE;
    let mut command = SharedMemory::new(command_pages).ok_or(VsockTransportError::DmaAllocation)?;

    let response_pages = align_up(VMCALL_COMMON_HEADER_LEN) / PAGE_SIZE;
    let mut response =
        SharedMemory::new(response_pages).ok_or(VsockTransportError::DmaAllocation)?;

    // Request sending out the message
    vmcall_service_migtd_send(
        command.as_mut_bytes(),
        response.as_mut_bytes(),
        hdr,
        buf,
        stream.transport_context(),
        timeout,
    )
    .await
}

pub async fn vsock_transport_dequeue(stream: &VsockStream, timeout: u32) -> Result<Vec<u8>> {
    if let Some(data) = pop_stream_queues(&stream.addr()) {
        return Ok(data);
    }

    let command_pages = align_up(VMCALL_COMMON_HEADER_LEN) / PAGE_SIZE;
    let mut command = SharedMemory::new(command_pages).ok_or(VsockTransportError::DmaAllocation)?;

    let response_pages = MAX_VSOCK_MTU / PAGE_SIZE;
    let mut response =
        SharedMemory::new(response_pages).ok_or(VsockTransportError::DmaAllocation)?;

    vmcall_service_migtd_receive(
        command.as_mut_bytes(),
        response.as_mut_bytes(),
        &stream.addr(),
        stream.transport_context(),
        timeout,
    )
    .await
}

/// Whether can send packet.
pub fn vsock_transport_can_send() -> bool {
    true
}

/// Whether can receive packet.
pub fn vsock_transport_can_recv() -> Result<bool> {
    Ok(false)
}

async fn vmcall_service_migtd_send(
    command: &mut [u8],
    response: &mut [u8],
    header: &[u8],
    data: &[u8],
    mid: u64,
    timeout: u32,
) -> Result<usize> {
    set_command(command, COMMAND_SEND, &[header, data], mid)?;
    set_response(response)?;

    log::info!("Sending vsock message thru VMCALL...\n");
    tdx::tdvmcall_service(command, response, VMCALL_VECTOR as u64, timeout as u64)
        .map_err(|e| VsockTransportError::Vmcall(e))?;

    poll_fn(|_cx| -> Poll<Result<usize>> {
        // Parse the response data
        // Check the GUID of the reponse
        let reply = Response::new(response).ok_or(VsockTransportError::InvalidParameter)?;

        // Status is set as `VMCALL_STATUS_RESERVED` to check if the response is returned by VMM
        if reply.status() == VMCALL_STATUS_RESERVED {
            return Poll::Pending;
        }

        log::info!("VMM has received the vsock message.\n");

        // Do the sanity check
        if reply.guid() != VMCALL_SERVICE_MIGTD_GUID.as_bytes()
            || reply.status() != 0
            || reply.data()[0] != CURRENT_VERSION
            || reply.data()[1] != COMMAND_SEND
            || u64::from_le_bytes(reply.data()[4..12].try_into().unwrap()) != mid
        {
            log::error!("Failed at checking `VMCALL_MIGTD_SEND` response\n");
            return Poll::Ready(Err(VsockTransportError::InvalidParameter));
        }

        Poll::Ready(Ok(data.len()))
    })
    .await
}

async fn vmcall_service_migtd_receive(
    command: &mut [u8],
    response: &mut [u8],
    addrs: &VsockAddrPair,
    mid: u64,
    timeout: u32,
) -> Result<Vec<u8>> {
    set_command(command, COMMAND_RECV, &[], mid)?;
    set_response(response)?;

    log::info!("Receving vsock message thru VMCALL...\n");
    tdx::tdvmcall_service(command, response, VMCALL_VECTOR as u64, timeout as u64)
        .map_err(|e| VsockTransportError::Vmcall(e))?;

    poll_fn(|_cx| -> Poll<Result<Vec<u8>>> {
        // Parse the response data
        // Check the GUID of the reponse
        let reply = Response::new(response).ok_or(VsockTransportError::InvalidParameter)?;

        // Status is set as `VMCALL_STATUS_RESERVED` to check if the response is returned by VMM
        if reply.status() == VMCALL_STATUS_RESERVED {
            return Poll::Pending;
        }

        // Do the sanity check
        if reply.guid() != VMCALL_SERVICE_MIGTD_GUID.as_bytes()
            || reply.status() != 0
            || reply.data()[0] != CURRENT_VERSION
            || reply.data()[1] != COMMAND_RECV
            || u64::from_le_bytes(reply.data()[4..12].try_into().unwrap()) != mid
        {
            log::error!("Failed at checking `VMCALL_MIGTD_RECV` response\n");
            return Poll::Ready(Err(VsockTransportError::InvalidParameter));
        }

        recv_packet(&reply.data()[12..])?;
        Poll::Ready(pop_stream_queues(addrs).ok_or(VsockTransportError::InvalidVsockPacket))
    })
    .await
}

fn set_command(page: &mut [u8], cmd: u8, data: &[&[u8]], mid: u64) -> Result<()> {
    let mut command = Command::new(page, &VMCALL_SERVICE_MIGTD_GUID)
        .ok_or(VsockTransportError::InvalidParameter)?;
    // Version: 0
    command.write(&[0]);
    // Command
    command.write(&[cmd]);
    // Reserved
    command.write(&[0, 0]);
    // MigRequestId
    command.write(&mid.to_le_bytes());
    for &bytes in data {
        command.write(bytes);
    }

    Ok(())
}

fn set_response(page: &mut [u8]) -> Result<usize> {
    Response::fill(page, &VMCALL_SERVICE_MIGTD_GUID).ok_or(VsockTransportError::InvalidParameter)
}

struct Command<'a> {
    data: &'a mut [u8],
    offset: usize,
}

impl<'a> Command<'a> {
    pub const COMMAND_HEADER_LENGTH: usize = 24;

    pub fn new(data: &'a mut [u8], guid: &guid::Guid) -> Option<Self> {
        if data.len() < Self::COMMAND_HEADER_LENGTH {
            return None;
        }
        data.fill(0);
        // GUID field
        data[0..16].copy_from_slice(guid.as_bytes());
        // Length field
        data[16..20].copy_from_slice(&u32::to_le_bytes(24));
        // Reserved field
        data[20..24].copy_from_slice(&u32::to_le_bytes(0));
        Some(Self { data, offset: 24 })
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.data[self.offset..self.offset + bytes.len()].copy_from_slice(bytes);
        self.offset += bytes.len();

        // Update the length field
        self.data[16..20].copy_from_slice(&u32::to_le_bytes(self.offset as u32));
    }
}

struct Response<'a> {
    response: &'a [u8],
}

impl<'a> Response<'a> {
    pub const RESPONSE_HDR_LEN: usize = 24;

    pub fn fill(response: &mut [u8], guid: &guid::Guid) -> Option<usize> {
        if response.len() < Self::RESPONSE_HDR_LEN {
            return None;
        }
        let len = response.len();
        response.fill(0);
        // GUID field
        response[0..16].copy_from_slice(guid.as_bytes());
        // Length field
        response[16..20].copy_from_slice(&u32::to_le_bytes(len as u32));
        // Status field
        response[20..24].copy_from_slice(&u32::to_le_bytes(VMCALL_STATUS_RESERVED));

        Some(len)
    }

    pub fn new(response: &'a [u8]) -> Option<Self> {
        if response.len() < Self::RESPONSE_HDR_LEN {
            return None;
        }
        // Safty:
        // length of slice response has been checked
        let length = u32::from_le_bytes(response[16..20].try_into().unwrap()) as usize;

        // Validate the content read from VMM input data
        if length < Self::RESPONSE_HDR_LEN || length > response.len() {
            return None;
        }
        speculation_barrier();

        Some(Self {
            response: &response[..length],
        })
    }

    pub fn guid(&self) -> &[u8] {
        &self.response[0..16]
    }

    pub fn status(&self) -> u32 {
        u32::from_le_bytes(self.response[20..24].try_into().unwrap())
    }

    pub fn data(&self) -> &[u8] {
        &self.response[Self::RESPONSE_HDR_LEN..]
    }
}

interrupt_handler_template!(vmcall_notification, _stack, {
    VMCALL_FLAG.store(true, Ordering::SeqCst);
});

fn speculation_barrier() {
    unsafe { core::arch::x86_64::_mm_lfence() };
}
