// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! APIC emulation stubs for AzCVMEmu mode
//!
//! In emulation mode, there's no real APIC hardware, so we provide
//! stub implementations that are safe no-ops.

/// Disable interrupts (no-op in emulation mode)
pub fn disable() {
    // No-op in emulation mode - no real APIC to disable
}

/// Enable interrupts and halt (yields CPU in emulation mode)
pub fn enable_and_hlt() {
    // In emulation mode, there's no real halt instruction
    // Just yield the CPU with a spin loop hint
    // The caller's loop will check the NOTIFIER flag and break when set
    core::hint::spin_loop();
}

/// One-shot TSC deadline mode (no-op in emulation mode)
pub fn one_shot_tsc_deadline_mode(_period: u64) -> Option<u64> {
    // No-op in emulation mode - no real APIC timer
    None
}

/// Reset one-shot TSC deadline mode (no-op in emulation mode)
pub fn one_shot_tsc_deadline_mode_reset() {
    // No-op in emulation mode
}

/// One-shot APIC timer mode (no-op in emulation mode)
#[cfg(feature = "oneshot-apic")]
pub fn one_shot(_ticks: u64) {
    // No-op in emulation mode
}

/// Reset one-shot APIC timer (no-op in emulation mode)
#[cfg(feature = "oneshot-apic")]
pub fn one_shot_reset() {
    // No-op in emulation mode
}

/// MSR LVTT register constant (for compatibility)
pub const MSR_LVTT: u32 = 0x832;
