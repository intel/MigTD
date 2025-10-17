// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use crypto::x509::{Certificate, Decode};
use spin::Once;

use crate::Error;

pub static ROOT_CA_PUBLIC_KEY: Once<Vec<u8>> = Once::new();

pub fn set_ca(cert: &[u8]) -> Result<(), Error> {
    ROOT_CA_PUBLIC_KEY
        .try_call_once(|| {
            Certificate::from_der(cert)
                .map_err(|_| Error::InvalidRootCa)?
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or(Error::InvalidRootCa)
                .map(|k| k.to_vec())
        })
        .map(|_| ())
}
