// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::sync::atomic::{AtomicBool, Ordering};
use td_payload::arch::apic::*;
use td_payload::arch::idt::register;
use td_payload::interrupt_handler_template;

pub const VMCALL_SERVICE_VECTOR: u8 = 0x50;
pub static VMCALL_SERVICE_FLAG: AtomicBool = AtomicBool::new(false);

interrupt_handler_template!(vmcall_service_callback, _stack, {
    VMCALL_SERVICE_FLAG.store(true, Ordering::SeqCst);
});

pub fn register_callback() {
    register(VMCALL_SERVICE_VECTOR, vmcall_service_callback);
}

pub fn wait_for_event(event_flag: &AtomicBool) {
    while !event_flag.load(Ordering::SeqCst) {
        // Halt to wait until interrupt comming
        enable_and_hlt();
        if event_flag.load(Ordering::SeqCst) {
            break;
        }
    }

    // Reset the value of RX_FLAG
    event_flag.store(false, Ordering::SeqCst);
    disable();
}
