// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::VsockTransportError;

use core::result::Result;
use td_payload::arch::idt::{register_interrupt_callback, InterruptCallback, InterruptStack};

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
