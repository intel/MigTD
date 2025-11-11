// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::driver::vmcall_raw::panic_with_guest_crash_reg_report;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;
use td_payload::arch::apic::*;
use td_payload::arch::idt::{register_interrupt_callback, InterruptCallback, InterruptStack};

pub const VMCALL_SERVICE_VECTOR: u8 = 0x50;
pub static VMCALL_SERVICE_FLAG: AtomicBool = AtomicBool::new(false);

lazy_static! {
    pub static ref VMCALL_MIG_REPORTSTATUS_FLAGS: Mutex<BTreeMap<u64, AtomicBool>> =
        Mutex::new(BTreeMap::new());
}

fn vmcall_service_callback(_stack: &mut InterruptStack) {
    VMCALL_SERVICE_FLAG.store(true, Ordering::SeqCst);

    for (_key, flag) in VMCALL_MIG_REPORTSTATUS_FLAGS.lock().iter() {
        flag.store(true, Ordering::SeqCst);
    }
}

pub fn register_callback() {
    if register_interrupt_callback(
        VMCALL_SERVICE_VECTOR as usize,
        InterruptCallback::new(vmcall_service_callback),
    )
    .is_err()
    {
        panic_with_guest_crash_reg_report(
            0xFF,
            b"Failed to set interrupt callback for VMCALL_SERVICE",
        );
    }
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
