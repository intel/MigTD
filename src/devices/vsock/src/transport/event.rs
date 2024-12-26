// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::VsockTransportError;

use core::result::Result;
use core::sync::atomic::{AtomicBool, Ordering};
use td_payload::arch::apic::*;
use td_payload::arch::idt::{register_interrupt_callback, InterruptCallback, InterruptStack};

use crate::VsockTimeout;

#[cfg(not(feature = "fuzz"))]
pub fn register_callback(
    vector: u8,
    cb: fn(&mut InterruptStack),
) -> Result<(), VsockTransportError> {
    register_interrupt_callback(vector as usize, InterruptCallback::new(cb))
        .map_err(|_| VsockTransportError::Interrupt)
}

#[cfg(feature = "fuzz")]
pub fn register_callback(
    vector: u8,
    cb: fn(&mut InterruptStack),
) -> Result<(), VsockTransportError> {
    Ok(())
}

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
