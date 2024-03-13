// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

mod config;
mod verify;

use alloc::string::String;
pub use config::*;
pub use verify::*;

#[repr(C)]
#[derive(Debug)]
pub enum PolicyError {
    FailGetReport,
    InvalidParameter,
    InvalidPolicy,
    InvalidEventLog,
    PlatformNotFound(String),
    PlatformNotMatch(String, String),
    UnqulifiedPlatformInfo,
    UnqulifiedQeInfo,
    UnqulifiedTdxModuleInfo,
    UnqulifiedMigTdInfo,
    Crypto,
}
