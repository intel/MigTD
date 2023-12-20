// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

mod config;
mod verify;

pub use config::*;
pub use verify::*;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    FailGetReport,
    InvalidParameter,
    InvalidPolicy,
    InvalidEventLog,
    UnqulifiedPlatformInfo,
    UnqulifiedQeInfo,
    UnqulifiedTdxModuleInfo,
    UnqulifiedMigTdInfo,
    Crypto,
}
