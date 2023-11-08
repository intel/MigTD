// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_main]
use libfuzzer_sys::fuzz_target;

mod fuzzlib;
use conquer_once::spin::OnceCell;
use fuzzlib::{init, COMMON_HEADER,virtio_pci::FuzzVirtioTransport};
use std::thread::spawn;
pub static VSOCK_DEVICE: OnceCell<VirtioVsockDevice<FuzzVirtioTransport>> = OnceCell::uninit();
use virtio::Result;
use vsock::{
    register,
    virtio_vsock_device::VirtioVsockDevice,
    vsock::{VsockAddr, VsockStream},
};

const PTR_OFFSET: u64 = 0x10000;
const PAGE_SIZE: usize = 0x1000;
const BARU64_1_OFFSET: u64 = 0x10;
const BARU64_2_OFFSET: u64 = 0x18;
const BARU64_3_OFFSET: u64 = 0x20;

const VEC_CAPACITY: usize = 0x10000_0000;
const TD_PAYLOAD_SHARED_MEMORY_SIZE: usize = 0x100_0000;
const PTR_ALIGN_VAR: u64 = 0xffff_ffff_ffff_0000;

const DATA_LEN: usize = 0x100_0000;

const PACKET_LEN: usize = 44;
const USED_LEN_VAL_2: u16 = 2;
const USED_LEN_VAL_4: u16 = 4;
const USED_LEN_VAL_6: u16 = 6;
const FIRST_USED_OFFSET: u64 = 2;
const ZERO_USED_LEN_OFFSET: u64 = 8;
const FIRST_USED_LEN_OFFSET: u64 = 16;
const TWO_USED_LEN_OFFSET: u64 = 24;
const THREE_USED_LEN_OFFSET: u64 = 32;

fn send(bufs: &[&[u8]]) -> Result<usize> {
    VSOCK_DEVICE
        .try_get()
        .expect("get vsock device failed")
        .send(bufs)
}

fn recv(bufs: &[&mut [u8]]) -> Result<usize> {
    VSOCK_DEVICE
        .try_get()
        .expect("get vsock device failed")
        .recv(bufs)
}

fn get_cid() -> u64 {
    VSOCK_DEVICE
        .try_get()
        .expect("get vsock device failed")
        .get_cid()
}

fn fuzz_vsock(paddr: u64, packet: &[u8]) {
    let mut packet = packet.to_vec();
    if packet.len() < PACKET_LEN {
        return;
    }
    let vsock_device_id = 1;
    let pci_device = pci::PciDevice::new(0, vsock_device_id, 0);
    let virtio_transport = FuzzVirtioTransport::new(pci_device);

    let virtio_vsock_device = VirtioVsockDevice::new(virtio_transport).unwrap();
    virtio_vsock_device.init().expect("init vsock device faild");
    let _ = virtio_vsock_device.can_send();
    let _ = virtio_vsock_device.can_recv();
    packet[30..32].copy_from_slice(&[1, 0]);
    // let device_addr = paddr - PAGE_SIZE as u64 + 0x100 + 0x200;
    if !VSOCK_DEVICE.is_initialized() {
        VSOCK_DEVICE.init_once(|| virtio_vsock_device);
    }

    if !register(send, recv, get_cid) {
        println!("register failed");
        return;
    }
    unsafe {
        // Modify the self.used.idx.read() value of send queue and recv queue  to 2
        std::ptr::write_volatile(
            (paddr + PAGE_SIZE as u64 + FIRST_USED_OFFSET) as *mut u16,
            USED_LEN_VAL_2,
        );
        std::ptr::write_volatile(
            (paddr + (PAGE_SIZE * 3) as u64 + FIRST_USED_OFFSET) as *mut u16,
            USED_LEN_VAL_2,
        );
        // Modify the uesd len value in the queue to 44
        std::ptr::write_volatile(
            (paddr + PAGE_SIZE as u64 + ZERO_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        std::ptr::write_volatile(
            (paddr + (PAGE_SIZE * 3) as u64 + ZERO_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        let dma_input = core::slice::from_raw_parts_mut(
            (paddr + (PAGE_SIZE * 6) as u64) as *mut u8,
            PACKET_LEN,
        );
        dma_input.copy_from_slice(&packet[..PACKET_LEN]);
    }

    let mut server_socket = VsockStream::new();
    let listen_addrss = VsockAddr::new(33, 1234);
    println!("{:?}", listen_addrss);
    server_socket.bind(&listen_addrss).expect("bind error\n");
    let _ = server_socket.listen(1);
    let _ = server_socket.accept();

    unsafe {
        std::ptr::write_volatile(
            (paddr + PAGE_SIZE as u64 + FIRST_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        std::ptr::write_volatile(
            (paddr + (PAGE_SIZE * 3) as u64 + FIRST_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        std::ptr::write_volatile(
            (paddr + PAGE_SIZE as u64 + TWO_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        std::ptr::write_volatile(
            (paddr + (PAGE_SIZE * 3) as u64 + TWO_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        std::ptr::write_volatile(
            (paddr + PAGE_SIZE as u64 + THREE_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        std::ptr::write_volatile(
            (paddr + (PAGE_SIZE * 3) as u64 + THREE_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        let dma_input = core::slice::from_raw_parts_mut(
            (paddr + (PAGE_SIZE * 6) as u64) as *mut u8,
            PACKET_LEN,
        );
        dma_input[30] = 0;
        dma_input[31] = 0;
    }

    let sp = spawn(move || loop {
        unsafe {
            let dma_input = core::slice::from_raw_parts_mut(
                (paddr + (PAGE_SIZE * 6) as u64) as *mut u8,
                PACKET_LEN,
            );
            if dma_input[30] == 1 && dma_input[31] == 0 {
                dma_input[30] = 2;
                std::ptr::write_volatile(
                    (paddr + PAGE_SIZE as u64 + FIRST_USED_OFFSET) as *mut u16,
                    USED_LEN_VAL_4,
                );
                std::ptr::write_volatile(
                    (paddr + (PAGE_SIZE * 3) as u64 + FIRST_USED_OFFSET) as *mut u16,
                    USED_LEN_VAL_4,
                );
                break;
            }
        }
    });
    let mut s = VsockStream::new();
    let con_res = s.connect(&VsockAddr::new(0, 40000));
    sp.join().unwrap();
    if con_res.is_ok() {
        let _ = s.send(&[], 1);
        let _ = s.recv(&mut [1, 2, 3, 4], 1);
        let sp = spawn(move || loop {
            unsafe {
                let dma_input = core::slice::from_raw_parts_mut(
                    (paddr + (PAGE_SIZE * 6) as u64) as *mut u8,
                    PACKET_LEN,
                );
                if dma_input[30] == 4 && dma_input[31] == 0 {
                    dma_input[30] = 3;
                    std::ptr::write_volatile(
                        (paddr + PAGE_SIZE as u64 + 2) as *mut u16,
                        USED_LEN_VAL_6,
                    );
                    std::ptr::write_volatile(
                        (paddr + (PAGE_SIZE * 3) as u64 + 2) as *mut u16,
                        USED_LEN_VAL_6,
                    );
                    break;
                }
            }
        });
        let _ = s.shutdown();
        sp.join().unwrap();
    }
}

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let tmp = [
        0xf4, 0x1a, 0x53, 0x10, 0x07, 0x04, 0x10, 0x00, 0x01, 0x00, 0x80, 0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0c, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4,
        0x1a, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x01, 0x00, 0x00, 0x09, 0x00, 0x10, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x09, 0x40, 0x10, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x09, 0x50, 0x10, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x09, 0x60, 0x14, 0x02, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0x70, 0x14,
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x11, 0x84, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0xff, 0x01,
        0x00, 0x00, 0x00,
    ];
    let mut ptr: Vec<u8> = Vec::with_capacity(VEC_CAPACITY);
    ptr.fill(0);
    let ptr = (ptr.as_ptr() as u64 & PTR_ALIGN_VAR) + PTR_OFFSET as u64;
    let data = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, DATA_LEN) };
    data[..tmp.len()].copy_from_slice(&tmp);
    let common_addr = ptr + 0x10c;
    let paddr = ptr + PAGE_SIZE as u64;
    init(paddr as usize, TD_PAYLOAD_SHARED_MEMORY_SIZE);
    COMMON_HEADER.try_init_once(|| ptr).expect("init error");

    unsafe {
        std::ptr::write_volatile((ptr + BARU64_1_OFFSET) as *mut u64, 0);
        std::ptr::write_volatile((ptr + BARU64_2_OFFSET) as *mut u64, 0);
        std::ptr::write_volatile((ptr + BARU64_3_OFFSET) as *mut u64, common_addr);
    }
    fuzz_vsock(paddr, &tmp);
});
