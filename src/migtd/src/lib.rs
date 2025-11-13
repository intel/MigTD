// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(any(test, feature = "AzCVMEmu")), no_std)]
#![cfg_attr(not(any(test, feature = "AzCVMEmu")), no_main)]

// AzCVMEmu only supports the vmcall-raw transport.
#[cfg(all(
    feature = "AzCVMEmu",
    any(
        feature = "virtio-serial",
        feature = "vmcall-vsock",
        feature = "virtio-vsock"
    )
))]
compile_error!("AzCVMEmu only supports vmcall-raw transport. Disable virtio-serial/vmcall-vsock/virtio-vsock when enabling AzCVMEmu.");

#[cfg_attr(feature = "main", macro_use)]
extern crate alloc;

// Re-export TDX dependencies conditionally to avoid feature gates throughout the code
#[cfg(not(feature = "AzCVMEmu"))]
extern crate td_payload;
#[cfg(not(feature = "AzCVMEmu"))]
extern crate td_shim_interface;
#[cfg(not(feature = "AzCVMEmu"))]
extern crate tdx_tdcall;

#[cfg(feature = "AzCVMEmu")]
extern crate td_payload_emu as td_payload;
#[cfg(feature = "AzCVMEmu")]
extern crate td_shim_interface_emu as td_shim_interface;
#[cfg(feature = "AzCVMEmu")]
extern crate tdx_tdcall_emu as tdx_tdcall;

pub mod config;
pub mod driver;
pub mod event_log;
pub mod mig_policy;
pub mod migration;
pub mod ratls;
pub mod spdm;

pub const STACK_SIZE: usize = 0x20_0000;
pub const HEAP_SIZE: usize = 0x70_0000;

/// The entry point of MigTD-Core
///
/// For the x86_64-unknown-none target, the entry point name is '_start'
#[no_mangle]
#[cfg(not(test))]
#[cfg(target_os = "none")]
pub extern "C" fn _start(hob: u64, payload: u64) -> ! {
    use td_payload::arch;
    use td_payload::mm::layout::*;

    const PT_SIZE: usize = 0x8_0000;
    const SHARED_MEMORY_SIZE: usize = 0x1C_0000;
    const SHADOW_STACK_SIZE: usize = 0x10000;

    extern "C" {
        fn main();
    }

    let layout = RuntimeLayout {
        heap_size: HEAP_SIZE,
        stack_size: STACK_SIZE,
        page_table_size: PT_SIZE,
        shared_memory_size: SHARED_MEMORY_SIZE,
        #[cfg(feature = "cet-shstk")]
        shadow_stack_size: SHADOW_STACK_SIZE,
    };

    arch::init::pre_init(hob as u64, &layout, true);

    // Init internal heap
    #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
    attestation::attest_init_heap();

    // Run the global constructors
    init(payload);

    // Initilize the APIC timer
    driver::timer::init_timer();

    #[cfg(feature = "virtio-serial")]
    driver::serial::virtio_serial_device_init();

    // Init the vsock-virtio device
    #[cfg(feature = "virtio-vsock")]
    driver::vsock::virtio_vsock_device_init();

    // Init the vmcall-vsock device
    #[cfg(feature = "vmcall-vsock")]
    driver::vsock::vmcall_vsock_device_init();

    // Init the vmcall-raw device
    #[cfg(feature = "vmcall-raw")]
    driver::vmcall_raw::vmcall_raw_device_init();

    // Initilize the system ticks
    driver::ticks::init_sys_tick();

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
