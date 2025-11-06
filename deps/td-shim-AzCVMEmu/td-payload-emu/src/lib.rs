// Copyright (c) 2022 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]

extern crate alloc;

// Re-export most of the real td-payload functionality
pub use td_payload_real::*;

// Override specific modules that need emulation behavior
pub mod arch {
    // Re-export most arch functionality from real td-payload
    pub use td_payload_real::arch::*;

    // Override the IDT module for emulation
    pub mod idt;

    // Override the APIC module for emulation
    pub mod apic;
}

pub mod mm {
    // Re-export most mm functionality from real td-payload
    pub use td_payload_real::mm::*;

    // Override only the shared module for emulation
    pub mod shared;
}

// Override the ACPI module for emulation
pub mod acpi;
