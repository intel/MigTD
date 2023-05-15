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
pub enum PolicyVerifyReulst {
    Succeed = 0,
    FailGetReport = 1,
    InvalidParameter = 2,
    InvalidPolicy = 3,
    UnqulifiedTeeTcbInfo = 4,
    UnqulifiedTdInfo = 5,
    UnqulifiedEventLog = 6,
}
