// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use ring::digest::{digest, SHA384};

use crate::{Error, Result, SHA384_DIGEST_SIZE};

pub fn digest_sha384(data: &[u8]) -> Result<Vec<u8>> {
    let digest = digest(&SHA384, data);

    if digest.as_ref().len() != SHA384_DIGEST_SIZE {
        return Err(Error::CalculateDigest);
    }

    Ok(digest.as_ref().to_vec())
}
