// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Shared mock TD quote and report data for testing
//!
//! This crate provides reusable mock data and utilities for testing TD attestation
//! in a no-std environment.

#![no_std]

pub mod mock_quote_data;
pub mod mock_report;

// Re-export commonly used items
pub use mock_quote_data::QUOTE;
pub use mock_report::create_mock_td_report;
