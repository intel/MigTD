// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![feature(naked_functions)]

extern crate alloc;

#[cfg(all(feature = "remote-attestation", not(test)))]
mod ghci;

#[cfg(all(feature = "remote-attestation", not(test)))]
mod binding;

#[cfg(all(feature = "remote-attestation", not(test)))]
mod attest;
#[cfg(all(feature = "remote-attestation", not(test)))]
pub use attest::*;

#[cfg(any(not(feature = "remote-attestation"), test))]
mod null;
#[cfg(any(not(feature = "remote-attestation"), test))]
pub use null::*;

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
