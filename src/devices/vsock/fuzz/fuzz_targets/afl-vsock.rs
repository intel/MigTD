// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod fuzzlib;
use conquer_once::spin::OnceCell;
use fuzzlib::{init, virtio_dma_alloc, virtio_dma_dealloc, COMMON_HEADER};
use spin::{once::Once, Mutex};
use std::thread::spawn;
use virtio::{virtio_pci::VirtioPciTransport, Result};
use vsock::{
    stream::{register_vsock_device, VsockDevice, VsockStream},
    transport::VirtioVsock,
    VsockAddr, VsockDmaPageAllocator, VsockTimeout, VsockTransport,
};

const PTR_OFFSET: u64 = 0x10000;
const PAGE_SIZE: usize = 0x1000;
const BARU64_1_OFFSET: u64 = 0x10;
const BARU64_2_OFFSET: u64 = 0x18;
const BARU64_3_OFFSET: u64 = 0x20;

const VEC_CAPACITY: usize = 0x10000_0000;
const TD_PAYLOAD_DMA_SIZE: usize = 0x100_0000;
const PTR_ALIGN_VAR: u64 = 0xffff_ffff_ffff_0000;

const DATA_LEN: usize = 0x100_0000;

const PACKET_LEN: usize = 44;
const USED_LEN_VAL_1: u16 = 1;
const USED_LEN_VAL_2: u16 = 2;
const USED_LEN_VAL_4: u16 = 4;
const USED_LEN_VAL_6: u16 = 6;
const FIRST_USED_OFFSET: u64 = 2;
const ZERO_USED_LEN_OFFSET: u64 = 8;
const FIRST_USED_LEN_OFFSET: u64 = 16;
const TWO_USED_LEN_OFFSET: u64 = 24;
const THREE_USED_LEN_OFFSET: u64 = 32;

const DEVICE_HEADER: [u8; 288] = [
    0xf4, 0x1a, 0x53, 0x10, 0x07, 0x04, 0x10, 0x00, 0x01, 0x00, 0x80, 0x07, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x1a, 0x00, 0x11,
    0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x00, 0x00,
    0x09, 0x00, 0x10, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x09, 0x40, 0x10, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x09, 0x50, 0x10, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x09, 0x60, 0x14, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x09, 0x70, 0x14, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x84, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x03, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x10, 0x00, 0xff, 0xff, 0x01, 0x00, 0x10, 0x00,
];

struct Allocator;

impl VsockDmaPageAllocator for Allocator {
    fn alloc_pages(&self, page_num: usize) -> Option<u64> {
        let addr = virtio_dma_alloc(page_num);
        if addr == 0 {
            None
        } else {
            Some(addr as u64)
        }
    }

    fn free_pages(&self, addr: u64, page_num: usize) {
        virtio_dma_dealloc(addr as usize, page_num);
    }
}

struct VsockTimer;

impl VsockTimeout for VsockTimer {
    fn is_timeout(&self) -> bool {
        true
    }

    fn reset_timeout(&self) {}

    fn set_timeout(&self, timeout: u64) -> Option<u64> {
        Some(timeout)
    }
}

fn fuzz_vsock(paddr: u64, packet: &[u8]) {
    let mut packet = packet.to_vec();
    if packet.len() < PACKET_LEN {
        return;
    }

    let pci_device = pci::PciDevice::new(0, 1, 0);
    let virtio_transport = VirtioPciTransport::new(pci_device);
    let vsock_transport = if let Ok(vsock_transport) = VirtioVsock::new(
        Box::new(virtio_transport),
        Box::new(Allocator {}),
        Box::new(VsockTimer {}),
    ) {
        vsock_transport
    } else {
        return;
    };

    let _ = VsockTransport::get_cid(&vsock_transport);
    let _ = VsockTransport::can_send(&vsock_transport);
    let _ = VsockTransport::can_recv(&vsock_transport);
    register_vsock_device(VsockDevice::new(Box::new(vsock_transport)));

    packet[30..32].copy_from_slice(&[1, 0]);
    let device_addr = paddr - PAGE_SIZE as u64 + 0x100 + 0x200;

    unsafe {
        // Modify the self.used.idx.read() value of send queue and recv queue  to 2
        std::ptr::write_volatile(
            (paddr + PAGE_SIZE as u64 + FIRST_USED_OFFSET) as *mut u16,
            USED_LEN_VAL_1,
        );
        std::ptr::write_volatile(
            (paddr + (PAGE_SIZE * 3) as u64 + FIRST_USED_OFFSET) as *mut u16,
            USED_LEN_VAL_1,
        );
        // Modify the uesd len value in the queue to 44
        std::ptr::write_volatile(
            (paddr + ZERO_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        std::ptr::write_volatile(
            (paddr + (PAGE_SIZE * 2) as u64 + ZERO_USED_LEN_OFFSET) as *mut u32,
            PACKET_LEN as u32,
        );
        let dma_input = core::slice::from_raw_parts_mut(
            (paddr + (PAGE_SIZE * 8) as u64) as *mut u8,
            PACKET_LEN,
        );
        dma_input.copy_from_slice(&packet[..PACKET_LEN]);
    }

    let mut server_socket = VsockStream::new().unwrap();
    let listen_addrss = VsockAddr::new(33, 1234);

    server_socket.connect(&listen_addrss);
    server_socket.bind(&listen_addrss);
    let _ = server_socket.listen(1);
    let _ = server_socket.accept();

    // unsafe {
    //     std::ptr::write_volatile(
    //         (paddr + PAGE_SIZE as u64 + FIRST_USED_LEN_OFFSET) as *mut u32,
    //         PACKET_LEN as u32,
    //     );
    //     std::ptr::write_volatile(
    //         (paddr + (PAGE_SIZE * 3) as u64 + FIRST_USED_LEN_OFFSET) as *mut u32,
    //         PACKET_LEN as u32,
    //     );
    //     std::ptr::write_volatile(
    //         (paddr + PAGE_SIZE as u64 + TWO_USED_LEN_OFFSET) as *mut u32,
    //         PACKET_LEN as u32,
    //     );
    //     std::ptr::write_volatile(
    //         (paddr + (PAGE_SIZE * 3) as u64 + TWO_USED_LEN_OFFSET) as *mut u32,
    //         PACKET_LEN as u32,
    //     );
    //     std::ptr::write_volatile(
    //         (paddr + PAGE_SIZE as u64 + THREE_USED_LEN_OFFSET) as *mut u32,
    //         PACKET_LEN as u32,
    //     );
    //     std::ptr::write_volatile(
    //         (paddr + (PAGE_SIZE * 3) as u64 + THREE_USED_LEN_OFFSET) as *mut u32,
    //         PACKET_LEN as u32,
    //     );
    //     let dma_input = core::slice::from_raw_parts_mut(
    //         (paddr + (PAGE_SIZE * 6) as u64) as *mut u8,
    //         PACKET_LEN,
    //     );
    //     dma_input[30] = 0;
    //     dma_input[31] = 0;
    // }

    // let sp = spawn(move || loop {
    //     unsafe {
    //         let dma_input = core::slice::from_raw_parts_mut(
    //             (paddr + (PAGE_SIZE * 6) as u64) as *mut u8,
    //             PACKET_LEN,
    //         );
    //         if dma_input[30] == 1 && dma_input[31] == 0 {
    //             dma_input[30] = 2;
    //             std::ptr::write_volatile(
    //                 (paddr + PAGE_SIZE as u64 + FIRST_USED_OFFSET) as *mut u16,
    //                 USED_LEN_VAL_4,
    //             );
    //             std::ptr::write_volatile(
    //                 (paddr + (PAGE_SIZE * 3) as u64 + FIRST_USED_OFFSET) as *mut u16,
    //                 USED_LEN_VAL_4,
    //             );
    //             break;
    //         }
    //     }
    // });
    // let mut s = VsockStream::new().unwrap();
    // let con_res = s.connect(&VsockAddr::new(0, 40000));
    // sp.join().unwrap();
    // if con_res.is_ok() {
    //     let _ = s.send(&[], 1);
    //     let _ = s.recv(&mut [1, 2, 3, 4], 1);
    //     let sp = spawn(move || loop {
    //         unsafe {
    //             let dma_input = core::slice::from_raw_parts_mut(
    //                 (paddr + (PAGE_SIZE * 6) as u64) as *mut u8,
    //                 PACKET_LEN,
    //             );
    //             if dma_input[30] == 4 && dma_input[31] == 0 {
    //                 dma_input[30] = 3;
    //                 std::ptr::write_volatile(
    //                     (paddr + PAGE_SIZE as u64 + 2) as *mut u16,
    //                     USED_LEN_VAL_6,
    //                 );
    //                 std::ptr::write_volatile(
    //                     (paddr + (PAGE_SIZE * 3) as u64 + 2) as *mut u16,
    //                     USED_LEN_VAL_6,
    //                 );
    //                 break;
    //             }
    //         }
    //     });
    //     let _ = s.shutdown();
    //     sp.join().unwrap();
    // }
}

fn main() {
    let mut ptr: Vec<u8> = Vec::with_capacity(VEC_CAPACITY);
    ptr.fill(0);
    let ptr = (ptr.as_ptr() as u64 & PTR_ALIGN_VAR) + PTR_OFFSET as u64;
    let data = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, DATA_LEN) };
    data[..DEVICE_HEADER.len()].copy_from_slice(&DEVICE_HEADER);
    COMMON_HEADER.try_init_once(|| ptr).expect("init error");
    let paddr = ptr + PAGE_SIZE as u64;
    init(paddr as usize, TD_PAYLOAD_DMA_SIZE);

    #[cfg(not(feature = "fuzz"))]
    {
        // Command line input seed file location
        let mut args = std::env::args().skip(1);
        if let Some(arg) = args.next() {
            println!("{}", arg);
            let paths = std::path::Path::new(&arg);

            if paths.is_file() {
                let tmp = std::fs::read(paths).expect("read crash file fail");
                fuzz_vsock(paddr, &tmp);
            } else if paths.is_dir() {
                for path in std::fs::read_dir(paths).unwrap() {
                    let path = &path.unwrap().path();
                    if path.ends_with("README.txt") {
                        continue;
                    }
                    let tmp = std::fs::read(paths).expect("read crash file fail");
                    fuzz_vsock(paddr, &tmp);
                }
            }
        } else {
            println!("No valid file path entered");
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|tmp: &[u8]| {
        data[..DEVICE_HEADER.len()].copy_from_slice(&DEVICE_HEADER);
        fuzz_vsock(paddr, tmp);
    });
}
