// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{collections::VecDeque, vec::Vec};
use rust_std_stub::io::{self, Read, Write};

use crate::{Result, VirtioSerialError, SERIAL_DEVICE};

const DEFAULT_TIMEOUT: u64 = 8000;

pub struct VirtioSerialPort {
    port_id: u32,
    cache: VecDeque<Vec<u8>>,
}

impl Write for VirtioSerialPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf).map_err(|e| e.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for VirtioSerialPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf).map_err(|e| e.into())
    }
}

impl VirtioSerialPort {
    pub fn new(port_id: u32) -> Self {
        Self {
            port_id,
            cache: VecDeque::new(),
        }
    }

    pub fn open(&self) -> Result<()> {
        SERIAL_DEVICE
            .lock()
            .get_mut()
            .ok_or(VirtioSerialError::InvalidParameter)?
            .allocate_port(self.port_id)
    }

    pub fn close(&self) -> Result<()> {
        SERIAL_DEVICE
            .lock()
            .get_mut()
            .ok_or(VirtioSerialError::InvalidParameter)?
            .free_port(self.port_id)
    }

    pub fn send(&self, data: &[u8]) -> Result<usize> {
        SERIAL_DEVICE
            .lock()
            .get_mut()
            .ok_or(VirtioSerialError::InvalidParameter)?
            .enqueue(data, self.port_id, DEFAULT_TIMEOUT)
    }

    pub fn recv(&mut self, data: &mut [u8]) -> Result<usize> {
        if self.cache.is_empty() {
            let recv_bytes = SERIAL_DEVICE
                .lock()
                .get_mut()
                .ok_or(VirtioSerialError::InvalidParameter)?
                .dequeue(self.port_id, DEFAULT_TIMEOUT)?;
            self.cache.push_back(recv_bytes);
        }

        let mut recvd = 0;
        if !self.cache.is_empty() {
            let front = self.cache.front_mut().unwrap();
            let expect = data.len() - recvd;
            if front.len() <= expect {
                data[..front.len()].copy_from_slice(&front);
                recvd += front.len();
                self.cache.pop_front();
            } else {
                data[recvd..].copy_from_slice(&front[..expect]);
                front.drain(..expect);
                recvd = expect;
            }
        }

        Ok(recvd)
    }
}

impl Drop for VirtioSerialPort {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
