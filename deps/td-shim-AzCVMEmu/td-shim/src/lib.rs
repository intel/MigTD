// Copyright (c) 2022 Alibaba Cloud
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Minimal TD-shim emulation for Azure CVM environments
//!
//! This crate provides minimal emulation of td-shim functionality needed
//! to build the policy crate in environments where the full td-shim is not available.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod event_log;
