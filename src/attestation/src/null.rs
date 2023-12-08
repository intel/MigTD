// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;

use crate::Error;

pub fn attest_init_heap() {}

pub fn get_quote(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(td_report.to_vec())
}

pub fn verify_quote(quote: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(quote.to_vec())
}

pub fn get_fmspc_from_quote(_quote: &[u8]) -> Result<[u8; 6], Error> {
    Err(Error::InvalidQuote)
}
