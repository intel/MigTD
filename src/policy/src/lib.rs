// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

mod config;
mod verify;

use alloc::{format, string::String};
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
    UnqulifiedPlatformInfo(PolicyErrorDetails),
    UnqulifiedQeInfo(PolicyErrorDetails),
    UnqulifiedTdxModuleInfo(PolicyErrorDetails),
    UnqulifiedMigTdInfo(PolicyErrorDetails),
    Crypto,
}

#[derive(Debug)]
pub struct PolicyErrorDetails {
    pub property: String,
    pub policy: Property,
    pub local_fmspc: Option<String>,
    pub remote_fmspc: Option<String>,
    pub local: String,
    pub remote: String,
}

impl PolicyErrorDetails {
    pub(crate) fn new(
        property: String,
        policy: Property,
        local_fmspc: Option<String>,
        remote_fmspc: Option<String>,
        local: &[u8],
        remote: &[u8],
    ) -> Self {
        Self {
            property,
            policy,
            local: format!("{:x?}", local),
            remote: format!("{:x?}", remote),
            local_fmspc,
            remote_fmspc,
        }
    }
}
