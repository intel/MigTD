// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::vmcall_raw::panic_with_guest_crash_reg_report;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;
use td_payload::arch::apic::*;
use td_payload::arch::idt::{register_interrupt_callback, InterruptCallback, InterruptStack};

/// A simple apic timer notification handler used to handle the
/// time out events
static TIMEOUT_FLAG: AtomicBool = AtomicBool::new(false);
static TIMEOUT_CALLBACK: Once<fn()> = Once::new();
static TSC_DEADLINE_ENABLED: AtomicBool = AtomicBool::new(true);

const TIMEOUT_VECTOR: u8 = 33;
const CPUID_TSC_DEADLINE_BIT: u32 = 1 << 24;

// APIC Timer Modes
#[cfg(feature = "oneshot-apic")]
const APIC_TIMER_MODE_ONESHOT: u32 = 0;
#[cfg(not(feature = "oneshot-apic"))]
const _APIC_TIMER_MODE_ONESHOT: u32 = 0;
const _APIC_TIMER_MODE_PERIODIC: u32 = 1;
const APIC_TIMER_MODE_TSC_DEADLINE: u32 = 2;

// APIC Frequency
#[cfg(feature = "oneshot-apic")]
const APIC_FREQUENCY: u32 = 200000000;

fn timer_handler(_stack: &mut InterruptStack) {
    TIMEOUT_CALLBACK
        .get()
        .unwrap_or(&(default_callback as fn()))();
}

pub fn init_timer() {
    let cpuid = unsafe { core::arch::x86_64::__cpuid_count(0x1, 0) };

    if cpuid.ecx & CPUID_TSC_DEADLINE_BIT == 0 {
        TSC_DEADLINE_ENABLED.store(false, Ordering::SeqCst);
        #[cfg(not(feature = "oneshot-apic"))]
        {
            panic!("Please enable TSC deadline mode for TD");
        }
    }

    set_timer_notification(TIMEOUT_VECTOR)
}

pub fn schedule_timeout(timeout: u32) -> Option<u64> {
    reset_timer();
    let cpuid = unsafe { core::arch::x86_64::__cpuid_count(0x15, 0) };
    let tsc_frequency = cpuid.ecx * (cpuid.ebx / cpuid.eax);
    let deadline = (tsc_frequency / 1000) as u64 * timeout as u64;

    apic_timer_lvtt_setup(TIMEOUT_VECTOR);
    if TSC_DEADLINE_ENABLED.load(Ordering::SeqCst) {
        one_shot_tsc_deadline_mode(deadline)
    } else {
        // Enabling OneShot APIC timers only for windows
        #[cfg(all(
            feature = "oneshot-apic",
            any(feature = "vmcall-vsock", feature = "vmcall-raw")
        ))]
        {
            // measuring Ticks Per Milli Seconds based on APIC frequency used for windows
            let ticks_per_ms = (APIC_FREQUENCY / 1000) as u64;
            one_shot(ticks_per_ms * timeout as u64);
        }
        None
    }
}

pub fn timeout() -> bool {
    TIMEOUT_FLAG.load(Ordering::SeqCst)
}

pub fn reset_timer() {
    if TSC_DEADLINE_ENABLED.load(Ordering::SeqCst) {
        one_shot_tsc_deadline_mode_reset();
    }
    // Enabling OneShot APIC timers only for windows
    #[cfg(all(
        feature = "oneshot-apic",
        any(feature = "vmcall-vsock", feature = "vmcall-raw")
    ))]
    {
        if !TSC_DEADLINE_ENABLED.load(Ordering::SeqCst) {
            one_shot_reset();
        }
    }
    TIMEOUT_FLAG.store(false, Ordering::SeqCst);
}

fn set_lvtt(val: u32) {
    unsafe { x86::msr::wrmsr(MSR_LVTT, val as u64) }
}

fn apic_timer_lvtt_setup(vector: u8) {
    // setting default mode to be TSC deadline
    let mut mode = APIC_TIMER_MODE_TSC_DEADLINE;
    if TSC_DEADLINE_ENABLED.load(Ordering::SeqCst) {
        mode = APIC_TIMER_MODE_TSC_DEADLINE;
    }
    // Enabling OneShot APIC timers only for windows
    #[cfg(all(
        feature = "oneshot-apic",
        any(feature = "vmcall-vsock", feature = "vmcall-raw")
    ))]
    {
        if !TSC_DEADLINE_ENABLED.load(Ordering::SeqCst) {
            mode = APIC_TIMER_MODE_ONESHOT;
        }
    }
    let lvtt = (mode << 17) | (vector as u32);
    set_lvtt(lvtt);
}

fn set_timer_notification(vector: u8) {
    // Setup interrupt handler
    if register_interrupt_callback(vector as usize, InterruptCallback::new(timer_handler)).is_err()
    {
        panic_with_guest_crash_reg_report(0xFF, b"Failed to set interrupt callback for timer");
    }
}

pub fn set_timer_callback(cb: fn()) {
    TIMEOUT_CALLBACK.call_once(|| cb);
}

fn default_callback() {
    TIMEOUT_FLAG.store(true, Ordering::SeqCst);
}
