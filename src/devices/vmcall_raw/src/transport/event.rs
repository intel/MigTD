// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::VmcallRawError;

use core::result::Result;
use td_payload::arch::idt::{register_interrupt_callback, InterruptCallback, InterruptStack};

pub fn register_callback(vector: u8, cb: fn(&mut InterruptStack)) -> Result<(), VmcallRawError> {
    register_interrupt_callback(vector as usize, InterruptCallback::new(cb))
        .map_err(|_| VmcallRawError::Interrupt)
}
