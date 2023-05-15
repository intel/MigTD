// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_main]
use libfuzzer_sys::fuzz_target;
mod fuzzlib;
use fuzzlib::*;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let mut ptr_vec: Vec<u8> = Vec::with_capacity(VEC_CAPACITY);
    ptr_vec.fill(0);
    // let mut ptr_vec = [0u8;VEC_CAPACITY];
    let ptr = (ptr_vec.as_ptr() as u64 & PTR_ALIGN_VAR) + PTR_OFFSET as u64;
    let tmp = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, DATA_LEN) };

    let common_addr = ptr + 0x10c;
    let paddr = ptr + PAGE_SIZE as u64;
    init(paddr as usize, TD_PAYLOAD_DMA_SIZE);
    // COMMON_HEADER.try_init_once(|| ptr).expect("init error");
    if !COMMON_HEADER.is_initialized() {
        COMMON_HEADER.init_once(|| ptr);
    }
    tmp[..data.len()].clone_from_slice(&data);
    unsafe {
        std::ptr::write_volatile((ptr + BARU64_1_OFFSET) as *mut u64, 0);
        std::ptr::write_volatile((ptr + BARU64_2_OFFSET) as *mut u64, 0);
        std::ptr::write_volatile((ptr + BARU64_3_OFFSET) as *mut u64, common_addr);
    }
    fuzz_virtio(paddr);
});
