// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::sync::atomic::{AtomicBool, Ordering};
pub use td_payload::arch::apic::*;
use td_payload::arch::idt::register;
pub use td_payload::{eoi, interrupt_handler_template};

use crate::Timer;

pub fn register_callback(vector: u8, cb: unsafe extern "C" fn()) {
    register(vector, cb);
}

pub fn wait_for_event(event_flag: &AtomicBool, timer: &dyn Timer) -> bool {
    while !event_flag.load(Ordering::SeqCst) {
        // Halt to wait until interrupt comming
        enable_and_hlt();
        if event_flag.load(Ordering::SeqCst) {
            break;
        } else if timer.is_timeout() {
            timer.reset_timeout();
            return false;
        }
    }

    // Reset the value of RX_FLAG
    event_flag.store(false, Ordering::SeqCst);
    disable();

    true
}
