// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use curl::easy::Easy;

pub mod platform_tcb;
pub mod policy;
pub mod qe_identity;

pub(crate) fn fetch_data_from_url(url: &str) -> Result<(u32, Vec<u8>), curl::Error> {
    let mut handle = Easy::new();
    let mut data = Vec::new();

    handle.url(url)?;
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }

    Ok((handle.response_code()?, data))
}
