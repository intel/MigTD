// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::protocol::field::HEADER_LEN;
use crate::protocol::Packet;
use crate::stream::{VsockStream, BINDING_PKT_QUEUES, CONNECTION_PKT_QUEUES};
use crate::{
    align_up, VsockAddr, VsockAddrPair, VsockDmaPageAllocator, VsockTimeout, VsockTransport,
    VsockTransportError, PAGE_SIZE,
};

use super::event::*;
use super::Result;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::sync::atomic::{AtomicBool, Ordering};
use td_payload::arch::idt::InterruptStack;
use td_shim_interface::td_uefi_pi::pi::guid;
use tdx_tdcall::tdx;

const CURRENT_VERSION: u8 = 0;
const COMMAND_SEND: u8 = 3;
const COMMAND_RECV: u8 = 4;
const MAX_VSOCK_MTU: usize = 0x1000 * 16;
const VMCALL_VECTOR: u8 = 0x52;

static VMCALL_FLAG: AtomicBool = AtomicBool::new(false);

const VMCALL_SERVICE_MIGTD_GUID: guid::Guid = guid::Guid::from_fields(
    0xe60e6330,
    0x1e09,
    0x4387,
    [0xa4, 0x44, 0x8f, 0x32, 0xb8, 0xd6, 0x11, 0xe5],
);

pub struct VmcallVsock {
    mid: u64,
    cid: u64,
    dma_allocator: Box<dyn VsockDmaPageAllocator>,
    timer: Box<dyn VsockTimeout>,
    // DMA record table
    dma_record: BTreeMap<u64, usize>,
}

impl VmcallVsock {
    pub fn new(
        mid: u64,
        cid: u64,
        dma_allocator: Box<dyn VsockDmaPageAllocator>,
        timer: Box<dyn VsockTimeout>,
    ) -> Result<Self> {
        register_callback(VMCALL_VECTOR, vmcall_notification)?;

        Ok(Self {
            mid,
            cid,
            dma_allocator,
            timer,
            dma_record: BTreeMap::new(),
        })
    }

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
    fn recv_packet(&self, pkt: &[u8]) -> Result<()> {
        let mut header = Vec::new();
        let mut data = Vec::new();

        if pkt.len() < HEADER_LEN {
            return Err(VsockTransportError::InvalidVsockPacket);
        }
        // Read out the packet header into a safe place
        header.extend_from_slice(&pkt[..HEADER_LEN]);

        // Parse the data length from the packet header and copy it out from DMA buffer
        let packet_hdr = Packet::new_checked(&header[..])
            .map_err(|_| VsockTransportError::InvalidVsockPacket)?;
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

        Self::push_stream_queues(&key, header);
        Self::push_stream_queues(&key, data);

        Ok(())
    }

    fn vmcall_service_migtd_send(
        &mut self,
        command: &mut [u8],
        response: &mut [u8],
        header: &[u8],
        data: &[u8],
        timeout: u64,
    ) -> Result<usize> {
        self.set_command(command, COMMAND_SEND, &[header, data])?;
        self.set_response(response)?;

        self.timer.set_timeout(timeout);
        tdx::tdvmcall_service(command, response, VMCALL_VECTOR as u64, timeout)
            .map_err(|e| VsockTransportError::Vmcall(e))?;

        if !wait_for_event(&VMCALL_FLAG, self.timer.as_ref()) {
            return Err(VsockTransportError::Timeout);
        }
        self.timer.reset_timeout();

        // Parse the response data
        // Check the GUID of the reponse
        let reply = Response::new(response).ok_or(VsockTransportError::InvalidParameter)?;

        // Do the sanity check
        if reply.guid() != VMCALL_SERVICE_MIGTD_GUID.as_bytes()
            || reply.status() != 0
            || reply.data()[0] != CURRENT_VERSION
            || reply.data()[1] != COMMAND_SEND
            || u64::from_le_bytes(reply.data()[4..12].try_into().unwrap()) != self.mid
        {
            return Err(VsockTransportError::InvalidParameter);
        }

        Ok(data.len())
    }

    fn vmcall_service_migtd_receive(
        &mut self,
        command: &mut [u8],
        response: &mut [u8],
        addrs: &VsockAddrPair,
        timeout: u64,
    ) -> Result<Vec<u8>> {
        self.set_command(command, COMMAND_RECV, &[])?;
        self.set_response(response)?;

        self.timer.set_timeout(timeout);
        tdx::tdvmcall_service(command, response, VMCALL_VECTOR as u64, timeout)
            .map_err(|e| VsockTransportError::Vmcall(e))?;

        // TO DO:
        // Refactor the waiting logic
        loop {
            if !wait_for_event(&VMCALL_FLAG, self.timer.as_ref()) {
                return Err(VsockTransportError::Timeout);
            }
            self.timer.reset_timeout();

            // Parse the response data
            // Check the GUID of the reponse
            let reply = Response::new(response).ok_or(VsockTransportError::InvalidParameter)?;

            // Do the sanity check
            if reply.guid() != VMCALL_SERVICE_MIGTD_GUID.as_bytes()
                || reply.status() != 0
                || reply.data()[0] != CURRENT_VERSION
                || reply.data()[1] != COMMAND_RECV
                || u64::from_le_bytes(reply.data()[4..12].try_into().unwrap()) != self.mid
            {
                return Err(VsockTransportError::InvalidParameter);
            }

            self.recv_packet(&reply.data()[12..])?;

            if let Some(data) = Self::pop_stream_queues(addrs) {
                return Ok(data);
            }
        }
    }

    fn set_command(&mut self, page: &mut [u8], cmd: u8, data: &[&[u8]]) -> Result<()> {
        let mut command = Command::new(page, &VMCALL_SERVICE_MIGTD_GUID)
            .ok_or(VsockTransportError::InvalidParameter)?;
        // Version: 0
        command.write(&[0]);
        // Command
        command.write(&[cmd]);
        // Reserved
        command.write(&[0, 0]);
        // MigRequestId
        command.write(&self.mid.to_le_bytes());
        for &bytes in data {
            command.write(bytes);
        }

        Ok(())
    }

    fn set_response(&mut self, page: &mut [u8]) -> Result<usize> {
        Response::fill(page, &VMCALL_SERVICE_MIGTD_GUID)
            .ok_or(VsockTransportError::InvalidParameter)
    }

    fn allocate_dma(&mut self, size: usize) -> Result<&'static mut [u8]> {
        let dma_size = align_up(size);
        let dma_addr = self
            .dma_allocator
            .alloc_pages(dma_size / PAGE_SIZE)
            .ok_or(VsockTransportError::DmaAllocation)?;

        Ok(unsafe { core::slice::from_raw_parts_mut(dma_addr as *mut u8, dma_size) })
    }

    fn free_dma(&mut self, dma: &[u8]) {
        self.dma_allocator
            .free_pages(dma.as_ptr() as u64, dma.len() / PAGE_SIZE);
    }
}

impl VsockTransport for VmcallVsock {
    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    // Get current device CID
    fn get_cid(&self) -> Result<u64> {
        Ok(self.cid)
    }

    fn enqueue(
        &mut self,
        _stream: &VsockStream,
        hdr: &[u8],
        buf: &[u8],
        timeout: u64,
    ) -> Result<usize> {
        let command = self.allocate_dma(36 + hdr.len() + buf.len())?;

        let response = if let Ok(response) = self.allocate_dma(36) {
            response
        } else {
            self.free_dma(command);
            return Err(VsockTransportError::DmaAllocation);
        };

        // Request sending out the message
        self.vmcall_service_migtd_send(command, response, hdr, buf, timeout)
            .map(|res| {
                self.free_dma(command);
                self.free_dma(response);
                res
            })
    }

    fn dequeue(&mut self, stream: &VsockStream, timeout: u64) -> Result<Vec<u8>> {
        if let Some(data) = Self::pop_stream_queues(&stream.addr()) {
            return Ok(data);
        }

        let command = self.allocate_dma(36)?;

        let response = if let Ok(response) = self.allocate_dma(MAX_VSOCK_MTU) {
            response
        } else {
            self.free_dma(command);
            return Err(VsockTransportError::DmaAllocation);
        };

        self.vmcall_service_migtd_receive(command, response, &stream.addr(), timeout)
            .map(|res| {
                self.free_dma(command);
                self.free_dma(response);
                res
            })
    }

    /// Whether can send packet.
    fn can_send(&self) -> bool {
        true
    }

    /// Whether can receive packet.
    fn can_recv(&self) -> bool {
        true
    }
}

impl Drop for VmcallVsock {
    fn drop(&mut self) {
        for record in &self.dma_record {
            self.dma_allocator
                .free_pages(*record.0, *record.1 / PAGE_SIZE)
        }
    }
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
        // Reserved field
        response[20..24].copy_from_slice(&u32::to_le_bytes(0));

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

fn vmcall_notification(_: &mut InterruptStack) {
    VMCALL_FLAG.store(true, Ordering::SeqCst);
}

fn speculation_barrier() {
    unsafe { core::arch::x86_64::_mm_lfence() };
}
