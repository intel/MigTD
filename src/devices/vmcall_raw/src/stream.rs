// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::transport::vmcall::{
    vmcall_raw_transport_can_recv, vmcall_raw_transport_dequeue, vmcall_raw_transport_enqueue,
    vmcall_raw_transport_init, VMCALL_MIG_CONTEXT_FLAGS,
};
use core::sync::atomic::AtomicBool;

use crate::{VmcallRawAddr, VmcallRawError};

use alloc::{collections::BTreeMap, collections::VecDeque, vec::Vec};
use async_io::{AsyncRead, AsyncWrite};
use lazy_static::lazy_static;
use rust_std_stub::io;
use spin::Mutex;

type Result<T = ()> = core::result::Result<T, VmcallRawError>;

lazy_static! {
    pub(crate) static ref CONNECTION_PKT_QUEUES: Mutex<BTreeMap<VmcallRawAddr, VecDeque<Vec<u8>>>> =
        Mutex::new(BTreeMap::new());
}

fn add_stream_to_connection_map(stream: &VmcallRaw) {
    CONNECTION_PKT_QUEUES
        .lock()
        .insert(stream.addr, VecDeque::new());
}

fn remove_stream_from_connection_map(stream: &VmcallRaw) {
    CONNECTION_PKT_QUEUES.lock().remove(&stream.addr);
}

pub struct VmcallRaw {
    pub addr: VmcallRawAddr,
    pub data_queue: VecDeque<Vec<u8>>,
}

impl AsyncRead for VmcallRaw {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf, 0).await.map_err(|e| e.into())
    }
}

impl AsyncWrite for VmcallRaw {
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf, 0).await.map_err(|e| e.into())
    }
}

impl VmcallRaw {
    pub fn new() -> Result<Self> {
        VmcallRaw::new_with_mid(0)
    }

    pub fn new_with_mid(mid: u64) -> Result<Self> {
        Ok(VmcallRaw {
            addr: VmcallRawAddr {
                transport_context: mid,
            },
            data_queue: VecDeque::new(),
        })
    }

    pub async fn connect(&mut self) -> Result {
        add_stream_to_connection_map(self);
        let _ = vmcall_raw_transport_init();
        VMCALL_MIG_CONTEXT_FLAGS
            .lock()
            .insert(self.addr.transport_context(), AtomicBool::new(false));

        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result {
        self.reset().await
    }

    pub async fn send(&mut self, buf: &[u8], _flags: u32) -> Result<usize> {
        let _ = vmcall_raw_transport_enqueue(self, buf).await?;
        Ok(buf.len())
    }

    pub async fn recv(&mut self, buf: &mut [u8], _flags: u32) -> Result<usize> {
        if self.data_queue.is_empty() {
            loop {
                self.recv_packet_connected().await?;

                // If there are received packets, continue to pop them out and insert to the
                // `data_queue`. If there is no packet left in the device, break the loop.
                if !vmcall_raw_transport_can_recv()? {
                    break;
                }
            }
        }

        let mut used = 0;
        while !self.data_queue.is_empty() && used < buf.len() {
            let head = self.data_queue.front_mut().unwrap();
            let free = buf.len() - used;
            if head.len() <= free {
                buf[used..used + head.len()].copy_from_slice(head);
                used += head.len();
                self.data_queue.pop_front();
            } else {
                buf[used..].copy_from_slice(&head[..free]);
                used += free;
                head.drain(..free);
            }
        }

        Ok(used)
    }

    async fn reset(&mut self) -> Result {
        remove_stream_from_connection_map(self);
        VMCALL_MIG_CONTEXT_FLAGS
            .lock()
            .remove(&self.addr.transport_context());
        Ok(())
    }

    async fn recv_packet_connected(&mut self) -> Result<()> {
        let recv = vmcall_raw_transport_dequeue(self).await?;

        if recv.len() > 0 {
            let mut recv = vmcall_raw_transport_dequeue(self).await?;

            recv.truncate(recv.len() as usize);
            self.data_queue.push_back(recv);
        }

        Ok(())
    }
}
