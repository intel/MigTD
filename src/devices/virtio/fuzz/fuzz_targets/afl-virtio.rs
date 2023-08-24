// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod fuzzlib;
use fuzzlib::{fuzz_virtio, get_fuzz_seed_address, init, COMMON_HEADER};
use pci::PciDevice;
use virtio::{virtio_pci::VirtioPciTransport, virtqueue::VirtQueue, VirtioTransport};

const VIRTIO_SUBSYSTEM_VSOCK: u32 = 19;
const PTR_OFFSET: u64 = 0x10000;
const PAGE_SIZE: usize = 0x1000;
const BARU64_1_OFFSET: u64 = 0x10;
const BARU64_2_OFFSET: u64 = 0x18;
const BARU64_3_OFFSET: u64 = 0x20;

const VEC_CAPACITY: usize = 0x10000_0000;
const TD_PAYLOAD_DMA_SIZE: usize = 0x100_0000;
const PTR_ALIGN_VAR: u64 = 0xffff_ffff_ffff_0000;

const DATA_LEN: usize = 0x100_0000;

fn main() {
    let mut ptr: Vec<u8> = Vec::with_capacity(VEC_CAPACITY);
    ptr.fill(0);
    let ptr = (ptr.as_ptr() as u64 & PTR_ALIGN_VAR) + PTR_OFFSET as u64;
    let data = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, DATA_LEN) };

    let common_addr = 0;
    let paddr = ptr + PAGE_SIZE as u64;
    init(paddr as usize, TD_PAYLOAD_DMA_SIZE);
    COMMON_HEADER.try_init_once(|| ptr).expect("init error");

    #[cfg(not(feature = "fuzz"))]
    {
        // Command line input seed file location
        let mut args = std::env::args().skip(1);
        if let Some(arg) = args.next() {
            println!("{}", arg);
            let paths = std::path::Path::new(&arg);

            if paths.is_file() {
                let tmp = std::fs::read(paths).expect("read crash file fail");
                data[..tmp.len()].clone_from_slice(&tmp);
                fuzz_virtio(paddr);
            } else if paths.is_dir() {
                for path in std::fs::read_dir(paths).unwrap() {
                    let path = &path.unwrap().path();
                    if path.ends_with("README.txt") {
                        continue;
                    }
                    let tmp = std::fs::read(&path).expect("read crash file fail");
                    data[..tmp.len()].clone_from_slice(&tmp);
                    fuzz_virtio(paddr);
                }
            } else {
                println!("No valid file path entered");
            }
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|tmp: &[u8]| {
        data[..tmp.len()].clone_from_slice(&tmp);
        fuzz_virtio(paddr);
    });
}
