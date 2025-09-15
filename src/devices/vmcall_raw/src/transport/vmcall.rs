// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::event::*;
use crate::stream::{VmcallRaw, CONNECTION_PKT_QUEUES};
use crate::{align_up, VmcallRawError, PAGE_SIZE};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::future::poll_fn;
use core::result::Result;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Poll;
use lazy_static::lazy_static;
use spin::Mutex;
use td_payload::arch::idt::InterruptStack;
use td_payload::mm::shared::SharedMemory;
use tdx_tdcall::tdx;

const MAX_VMCALL_RAW_STREAM_MTU: usize = 0x1000 * 16;
const VMCALL_VECTOR: u8 = 0x52;

lazy_static! {
    pub static ref VMCALL_MIG_CONTEXT_FLAGS: Mutex<BTreeMap<u64, AtomicBool>> =
        Mutex::new(BTreeMap::new());
}
const TDX_VMCALL_VMM_SUCCESS: u8 = 1;

fn push_stream_queues(stream: &VmcallRaw, buf: Vec<u8>) {
    if buf.is_empty() {
        return;
    }

    if let Some(stream_queue) = CONNECTION_PKT_QUEUES.lock().get_mut(&stream.addr) {
        stream_queue.push_back(buf);
    }
}

fn pop_stream_queues(stream: &VmcallRaw) -> Option<Vec<u8>> {
    if let Some(stream_queue) = CONNECTION_PKT_QUEUES.lock().get_mut(&stream.addr) {
        stream_queue.pop_front()
    } else {
        None
    }
}

// Parse the packet data from the untrusted source.
//
// pkt = MigTD Communication Packet
fn recv_packet(pkt: &[u8], pkt_len: usize, stream: &VmcallRaw) -> Result<(), ()> {
    let data: Vec<u8> = pkt
        .get(..pkt_len)
        .expect("pkt_len exceeds buffer length")
        .to_vec();

    assert_eq!(data.len(), pkt_len);
    push_stream_queues(stream, data);

    Ok(())
}

pub fn vmcall_raw_transport_init() -> Result<(), VmcallRawError> {
    register_callback(VMCALL_VECTOR, vmcall_raw_intr_notification)?;
    Ok(())
}

// Get current device CID
pub fn vmcall_raw_transport_get_mid() -> Result<u64, VmcallRawError> {
    Err(VmcallRawError::Illegal)
}

pub async fn vmcall_raw_transport_enqueue(
    stream: &VmcallRaw,
    buf: &[u8],
) -> Result<usize, VmcallRawError> {
    let data_status: u64 = 0;
    let data_length: u32 = buf.len() as u32;

    let data_buffer_size = 8 + 4 + buf.len();
    let data_buffer_page_count = align_up(data_buffer_size) / PAGE_SIZE;
    let mut data_buffer =
        SharedMemory::new(data_buffer_page_count).ok_or(VmcallRawError::Illegal)?;

    let data_buffer = data_buffer.as_mut_bytes();

    data_buffer[0..8].copy_from_slice(&u64::to_le_bytes(data_status));
    data_buffer[8..12].copy_from_slice(&u32::to_le_bytes(data_length));
    data_buffer[12..(12 + buf.len())].copy_from_slice(buf);
    let truncated_buf = &mut data_buffer[..data_buffer_size];

    vmcall_service_migtd_send(stream.addr.transport_context(), truncated_buf).await
}

pub async fn vmcall_raw_transport_dequeue(stream: &VmcallRaw) -> Result<Vec<u8>, VmcallRawError> {
    if let Some(data) = pop_stream_queues(stream) {
        return Ok(data);
    }

    let response_buffer_page_count = MAX_VMCALL_RAW_STREAM_MTU / PAGE_SIZE;
    let mut response_buffer =
        SharedMemory::new(response_buffer_page_count).ok_or(VmcallRawError::Illegal)?;

    vmcall_service_migtd_receive(stream, response_buffer.as_mut_bytes()).await
}

/// Whether can send packet.
pub fn vmcall_raw_transport_can_send() -> bool {
    true
}

/// Whether can receive packet.
pub fn vmcall_raw_transport_can_recv() -> Result<bool, ()> {
    Ok(false)
}

async fn vmcall_service_migtd_send(
    mig_request_id: u64,
    data_buffer: &mut [u8],
) -> Result<usize, VmcallRawError> {
    tdx::tdvmcall_migtd_send(mig_request_id, data_buffer, VMCALL_VECTOR)
        .map_err(|_e| VmcallRawError::TdVmcallErr)?;

    poll_fn(|_cx| -> Poll<Result<usize, VmcallRawError>> {
        if let Some(flag) = VMCALL_MIG_CONTEXT_FLAGS.lock().get(&mig_request_id) {
            if flag.load(Ordering::SeqCst) {
                flag.store(false, Ordering::SeqCst);
            } else {
                return Poll::Pending;
            }
        } else {
            let _ = Poll::Ready(Err::<Vec<u8>, _>(VmcallRawError::Illegal));
        }

        let (_send_buf, data_status, data_length) = process_buffer(data_buffer);
        let data_status_bytes = data_status.to_le_bytes();

        if data_status_bytes[0] != TDX_VMCALL_VMM_SUCCESS {
            return Poll::Pending;
        }

        Poll::Ready(Ok(data_length as usize))
    })
    .await
}

fn process_buffer(buffer: &mut [u8]) -> (&mut [u8], u64, u32) {
    assert!(buffer.len() >= 12, "Buffer too small!");

    let (header, payload_buffer) = buffer.split_at_mut(12); // Split at 12th byte

    let data_status = u64::from_le_bytes(header[0..8].try_into().unwrap()); // First 8 bytes
    let data_length = u32::from_le_bytes(header[8..12].try_into().unwrap()); // Next 4 bytes

    (payload_buffer, data_status, data_length)
}

async fn vmcall_service_migtd_receive(
    stream: &VmcallRaw,
    data_buffer: &mut [u8],
) -> Result<Vec<u8>, VmcallRawError> {
    tdx::tdvmcall_migtd_receive(stream.addr.transport_context(), data_buffer, VMCALL_VECTOR)
        .map_err(|_e| VmcallRawError::TdVmcallErr)?;

    poll_fn(|_cx| -> Poll<Result<Vec<u8>, VmcallRawError>> {
        let mig_request_id = stream.addr.transport_context();
        if let Some(flag) = VMCALL_MIG_CONTEXT_FLAGS.lock().get(&mig_request_id) {
            if flag.load(Ordering::SeqCst) {
                flag.store(false, Ordering::SeqCst);
            } else {
                return Poll::Pending;
            }
        } else {
            let _ = Poll::Ready(Err::<Vec<u8>, _>(VmcallRawError::Illegal));
        }

        let (response_buf, data_status, data_length) = process_buffer(data_buffer);
        let data_status_bytes = data_status.to_le_bytes();

        if data_status_bytes[0] != TDX_VMCALL_VMM_SUCCESS {
            return Poll::Pending;
        }

        recv_packet(&response_buf, data_length as usize, stream)?;

        //push a placeholder vector to maintain return type of this function
        let mut placeholder_stub: Vec<u8> = Vec::new();
        placeholder_stub.push(1);

        Poll::Ready(Some(placeholder_stub).ok_or(VmcallRawError::Illegal))
    })
    .await
}

fn vmcall_raw_intr_notification(_: &mut InterruptStack) {
    for (_key, flag) in VMCALL_MIG_CONTEXT_FLAGS.lock().iter() {
        flag.store(true, Ordering::SeqCst);
    }
}
