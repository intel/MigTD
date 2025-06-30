// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod fuzzlib;
use conquer_once::spin::OnceCell;
use fuzzlib::{init, virtio_dma_alloc, virtio_dma_dealloc, COMMON_HEADER};
use spin::{once::Once, Mutex};
use std::thread::spawn;
use virtio::{virtio_pci::VirtioPciTransport, Result};
use virtio_serial::*;
mod timer;
use virtio_serial::VirtioSerialPort;
    


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

const VIRTIO_SERIAL_PORT_ID: u32 = 1;

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
    0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x03, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x10, 0x00, 0xff, 0xff, 0x01, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

struct SerialTimer;

impl Timer for SerialTimer {
    fn is_timeout(&self) -> bool {
        timer::timeout()
    }

    fn reset_timeout(&self) {
        timer::reset_timer()
    }

    fn set_timeout(&self, timeout: u32) -> Option<u32> {
        timer::schedule_timeout(timeout)?;

        // enable the interrupt to accept the timeout event
        x86_64::instructions::interrupts::enable();

        Some(timeout)
    }
}

struct Allocator;
impl DmaPageAllocator for Allocator {
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

fn fuzz_virtio_serial(paddr: u64, packet: &[u8]) {
    let mut packet = packet.to_vec();
    if packet.len() < PACKET_LEN {
        return;
    }

    // Create a mock PCI device with device type 0x3 (virtio-console)
    let pci_device = pci::PciDevice::new(0, 0x3, 0);
    let virtio_transport = virtio::virtio_pci::VirtioPciTransport::new(pci_device);

    // Initialize the virtio-serial device
    let serial = match virtio_serial::VirtioSerial::new(
        Box::new(virtio_transport),
        Box::new(Allocator {}),
        Box::new(SerialTimer {}),
    ) {
        Ok(s) => s,
        Err(_) => return, // Early return if device creation fails
    };

    // Register the serial device
    if virtio_serial::register_serial_device(serial).is_err() {
        return; 
    }

    let mut port = VirtioSerialPort::new(VIRTIO_SERIAL_PORT_ID);
    let _ = port.open();
    let _ = port.send(&packet);
    let _ = port.recv(&mut packet);
    let _ = port.close();
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
                fuzz_virtio_serial(paddr, &tmp);
            } else if paths.is_dir() {
                for path in std::fs::read_dir(paths).unwrap() {
                    let path = &path.unwrap().path();
                    if path.ends_with("README.txt") {
                        continue;
                    }
                    let tmp = std::fs::read(paths).expect("read crash file fail");
                    fuzz_virtio_serial(paddr, &tmp);
                }
            }
        } else {
            println!("No valid file path entered");
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|tmp: &[u8]| {
        data[..DEVICE_HEADER.len()].copy_from_slice(&DEVICE_HEADER);
        fuzz_virtio_serial(paddr, tmp);
    });
}
