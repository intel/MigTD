// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::transport::vmcall::{
    vmcall_raw_transport_can_recv, vmcall_raw_transport_dequeue, vmcall_raw_transport_enqueue,
    vmcall_raw_transport_init, VMCALL_MIG_CONTEXT_FLAGS, VMCALL_RAW_SEND_PAYLOAD_MTU,
};
use core::sync::atomic::AtomicBool;

use crate::{VmcallRawAddr, VmcallRawError};

use alloc::{collections::VecDeque, vec::Vec};
use async_io::{AsyncRead, AsyncWrite};
use rust_std_stub::io;

type Result<T = ()> = core::result::Result<T, VmcallRawError>;

pub struct VmcallRaw {
    pub addr: VmcallRawAddr,
    pub data_queue: VecDeque<Vec<u8>>,
    registered: bool,
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
            registered: false,
        })
    }

    pub async fn connect(&mut self) -> Result {
        vmcall_raw_transport_init()?;
        VMCALL_MIG_CONTEXT_FLAGS
            .lock()
            .insert(self.addr.transport_context(), AtomicBool::new(false));
        self.registered = true;

        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result {
        self.reset().await
    }

    pub async fn send(&mut self, buf: &[u8], _flags: u32) -> Result<usize> {
        // A single Service.MigTD.Send VMCALL can only carry one MTU-sized
        // payload (the same cap the receive side advertises). Chunk here so
        // callers that don't loop on partial writes (TLS, SPDM transport)
        // keep working when the pre-session policy + issuer chain blob
        // exceeds one VMCALL.
        let mut sent = 0;
        while sent < buf.len() {
            let end = core::cmp::min(buf.len(), sent + VMCALL_RAW_SEND_PAYLOAD_MTU);
            let _ = vmcall_raw_transport_enqueue(self, &buf[sent..end]).await?;
            sent = end;
        }
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
        VMCALL_MIG_CONTEXT_FLAGS
            .lock()
            .remove(&self.addr.transport_context());
        self.registered = false;
        Ok(())
    }

    async fn recv_packet_connected(&mut self) -> Result<()> {
        let recv = vmcall_raw_transport_dequeue(self).await?;

        if !recv.is_empty() {
            self.data_queue.push_back(recv);
        }

        Ok(())
    }
}

impl Drop for VmcallRaw {
    fn drop(&mut self) {
        if self.registered {
            VMCALL_MIG_CONTEXT_FLAGS
                .lock()
                .remove(&self.addr.transport_context());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    fn run_ready<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("future unexpectedly pending"),
        }
    }

    fn registered_stream(context: u64) -> VmcallRaw {
        VMCALL_MIG_CONTEXT_FLAGS
            .lock()
            .insert(context, AtomicBool::new(false));
        VmcallRaw {
            addr: VmcallRawAddr {
                transport_context: context,
            },
            data_queue: VecDeque::new(),
            registered: true,
        }
    }

    #[test]
    fn drop_removes_registered_context() {
        let context = 0xABCD_EF01_2345_6789;
        VMCALL_MIG_CONTEXT_FLAGS.lock().remove(&context);
        drop(registered_stream(context));
        assert!(!VMCALL_MIG_CONTEXT_FLAGS.lock().contains_key(&context));
    }

    #[test]
    fn drop_without_registration_is_a_noop() {
        let context = 0x1111_2222_3333_4444;
        VMCALL_MIG_CONTEXT_FLAGS.lock().remove(&context);
        drop(VmcallRaw::new_with_mid(context).unwrap());
        assert!(!VMCALL_MIG_CONTEXT_FLAGS.lock().contains_key(&context));
    }

    #[test]
    fn shutdown_removes_registered_context_before_drop() {
        let context = 0x5555_6666_7777_8888;
        VMCALL_MIG_CONTEXT_FLAGS.lock().remove(&context);
        let mut stream = registered_stream(context);

        run_ready(stream.shutdown()).unwrap();

        assert!(!VMCALL_MIG_CONTEXT_FLAGS.lock().contains_key(&context));
        assert!(!stream.registered);
    }
}
