// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

// Interrupt emulation registry for AzCVMEmu.
// Stores callbacks by vector and allows software-triggered dispatch.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use lazy_static::lazy_static;
use spin::Mutex;

// Match the shape vmcall_raw expects when passing a stack object to callbacks.
#[repr(C)]
pub struct InterruptStack;

pub type Callback = fn(&mut InterruptStack);

lazy_static! {
    static ref CALLBACKS: Mutex<[Option<Callback>; 256]> = Mutex::new([None; 256]);
}

pub fn register(vector: u8, cb: Callback) {
    CALLBACKS.lock()[vector as usize] = Some(cb);
}

pub fn trigger(vector: u8) {
    if let Some(cb) = CALLBACKS.lock()[vector as usize] {
        let mut stack = InterruptStack;
        cb(&mut stack);
    }
}
