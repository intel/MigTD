// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]

mod config;
mod consts;
mod mmio;
pub use config::*;
pub use consts::*;
pub use mmio::*;

#[cfg(feature = "fuzz")]
pub static COMMON_HEADER: conquer_once::spin::OnceCell<u64> =
    conquer_once::spin::OnceCell::uninit();
#[cfg(feature = "fuzz")]
pub fn get_fuzz_seed_address() -> u64 {
    *COMMON_HEADER.try_get().unwrap()
}

pub type Result<T> = core::result::Result<T, PciError>;

#[derive(Debug)]
pub enum PciError {
    InvalidParameter,
    MmioOutofResource,
    InvalidBarType,
    Misaligned,
}
