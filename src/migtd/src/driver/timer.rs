// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;
use td_payload::arch::apic::*;
use td_payload::arch::idt::register;
use td_payload::interrupt_handler_template;

static TIMEOUT_FLAG: AtomicBool = AtomicBool::new(false);
static TIMEOUT_CALLBACK: Once<fn()> = Once::new();

const TIMEOUT_VECTOR: u8 = 33;
const CPUID_TSC_DEADLINE_BIT: u32 = 1 << 24;

pub fn init_timer() {
    let cpuid = unsafe { core::arch::x86_64::__cpuid_count(0x1, 0) };
    if cpuid.ecx & CPUID_TSC_DEADLINE_BIT == 0 {
        panic!("Please enable TSC deadline mode for TD");
    }

    set_timer_notification(TIMEOUT_VECTOR)
}

pub fn schedule_timeout(timeout: u32) -> Option<u64> {
    reset_timer();
    let cpuid = unsafe { core::arch::x86_64::__cpuid_count(0x15, 0) };
    let tsc_frequency = cpuid.ecx * (cpuid.ebx / cpuid.eax);
    let deadline = (tsc_frequency / 1000) as u64 * timeout as u64;

    apic_timer_lvtt_setup(TIMEOUT_VECTOR);
    one_shot_tsc_deadline_mode(deadline)
}

pub fn timeout() -> bool {
    TIMEOUT_FLAG.load(Ordering::SeqCst)
}

pub fn reset_timer() {
    one_shot_tsc_deadline_mode_reset();
    TIMEOUT_FLAG.store(false, Ordering::SeqCst);
}

fn set_lvtt(val: u32) {
    unsafe { x86::msr::wrmsr(MSR_LVTT, val as u64) }
}

fn apic_timer_lvtt_setup(vector: u8) {
    let lvtt = (2 << 17) | (vector as u32);
    set_lvtt(lvtt);
}

fn set_timer_notification(vector: u8) {
    // Setup interrupt handler
    register(vector, timer);
}

pub fn set_timer_callback(cb: fn()) {
    TIMEOUT_CALLBACK.call_once(|| cb);
}

interrupt_handler_template!(timer, _stack, {
    TIMEOUT_CALLBACK
        .get()
        .unwrap_or(&(default_callback as fn()))();
});

fn default_callback() {
    TIMEOUT_FLAG.store(true, Ordering::SeqCst);
}
