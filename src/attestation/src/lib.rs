// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![feature(naked_functions)]

extern crate alloc;

#[cfg(not(test))]
mod ghci;

#[cfg(not(test))]
mod binding;

#[cfg(not(test))]
mod attest;
#[cfg(not(test))]
pub use attest::*;

pub mod root_ca;

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
