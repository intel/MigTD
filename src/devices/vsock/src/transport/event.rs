// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::sync::atomic::{AtomicBool, Ordering};
pub use td_payload::arch::apic::*;
pub use td_payload::{eoi, interrupt_handler_template};

use crate::VsockTimeout;

#[cfg(not(feature = "fuzz"))]
pub fn register_callback(vector: u8, cb: unsafe extern "C" fn()) {
    register(vector, cb);
}
#[cfg(feature = "fuzz")]
pub fn register_callback(vector: u8, cb: unsafe extern "C" fn()) {}

pub fn wait_for_event(event_flag: &AtomicBool, timer: &dyn VsockTimeout) -> bool {
    while !event_flag.load(Ordering::SeqCst) {
        // Halt to wait until interrupt comming
        #[cfg(not(feature = "fuzz"))]
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
