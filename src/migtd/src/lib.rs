// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]

#[macro_use]
extern crate alloc;

pub mod config;
pub mod driver;
pub mod event_log;
pub mod mig_policy;
pub mod migration;
pub mod ratls;

/// The entry point of MigTD-Core
///
/// For the x86_64-unknown-none target, the entry point name is '_start'
#[no_mangle]
#[cfg(not(test))]
#[cfg(target_os = "none")]
pub extern "C" fn _start(hob: u64, payload: u64) -> ! {
    use td_payload::arch;
    #[cfg(any(feature = "virtio-serial", feature = "virtio-vsock"))]
    use td_payload::mm::end_of_ram;
    use td_payload::mm::layout::*;

    const STACK_SIZE: usize = 0x18_0000;
    const HEAP_SIZE: usize = 0x68_0000;
    const PT_SIZE: usize = 0x8_0000;
    const DMA_SIZE: usize = 0x50_0000;

    extern "C" {
        fn main();
    }

    let layout = RuntimeLayout {
        heap_size: HEAP_SIZE,
        stack_size: STACK_SIZE,
        page_table_size: PT_SIZE,
        dma_size: DMA_SIZE,
        #[cfg(feature = "cet-shstk")]
        shadow_stack_size: DEFAULT_SHADOW_STACK_SIZE,
    };

    arch::init::pre_init(hob as u64, &layout);

    // Init internal heap
    attestation::attest_init_heap();

    // Run the global constructors
    init(payload);

    // Initialize the timer based on the APIC TSC deadline mode
    driver::timer::init_timer();

    #[cfg(feature = "virtio-serial")]
    driver::serial::virtio_serial_device_init(end_of_ram() as u64);

    // Init the vsock-virtio device
    #[cfg(feature = "virtio-vsock")]
    driver::vsock::virtio_vsock_device_init(end_of_ram() as u64);

    arch::init::init(&layout, main);
}

#[cfg(target_os = "none")]
fn init(payload: u64) {
    use td_loader::elf;

    let elf = unsafe {
        core::slice::from_raw_parts(
            payload as *const u8,
            td_layout::runtime::exec::PAYLOAD_SIZE as usize,
        )
    };

    // Call the init functions (contains C++ constructions of global variables)
    if let Some(range) = elf::parse_init_array_section(elf) {
        let mut init_start = payload as usize + range.start;
        let init_end = payload as usize + range.end;
        while init_start < init_end {
            let init_fn = init_start as *const fn();
            unsafe { (*init_fn)() };
            init_start += 8;
        }
    }
}
