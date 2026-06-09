// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use migtd::migration::data::read_mig_info;

type Result<T> = core::result::Result<T, MigrationError>;

#[derive(Debug)]
pub enum MigrationError {
    ParseResponse,
}

pub fn fuzz_read_mig_info(data: &[u8]) -> Result<()> {
    let _ = read_mig_info(data).ok_or(MigrationError::ParseResponse)?;
    Ok(())
}
