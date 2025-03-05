// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

extern crate alloc;

mod attest;
mod binding;
mod ghci;
mod root_ca;

pub use attest::*;
pub use root_ca::set_ca;

pub const TD_VERIFIED_REPORT_SIZE: usize = 734;

#[derive(Debug)]
pub enum Error {
    InvalidRootCa,
    InitHeap,
    GetQuote,
    VerifyQuote,
    InvalidOutput,
    InvalidQuote,
    OutOfMemory,
}
