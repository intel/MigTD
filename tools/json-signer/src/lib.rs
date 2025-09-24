// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::result::Result;
pub use serde_json::Error as JsonError;
use serde_json::{Map, Value};

#[derive(Debug)]
pub enum Error {
    InvalidJson(JsonError),
    InvalidKey,
    Sign,
}

impl From<JsonError> for Error {
    fn from(e: JsonError) -> Self {
        Error::InvalidJson(e)
    }
}

pub fn json_sign(json_key: &str, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, Error> {
    let private_key_der =
        crypto::ecdsa::pem_to_der_from_slice(&private_key).map_err(|_| Error::InvalidKey)?;
    let signature = crypto::ecdsa::ecdsa_sign(&private_key_der, &data).map_err(|_| Error::Sign)?;
    json_set_signature(json_key, data, &signature)
}

pub fn json_set_signature(
    key: &str,
    json_slice: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, Error> {
    let val: Value = serde_json::from_slice(json_slice)?;

    let sig_hex = bytes_to_hex_string(signature);

    let mut map = Map::new();
    map.insert(key.to_string(), val);
    map.insert("signature".to_string(), Value::String(sig_hex));

    let output = serde_json::to_vec(&map)?;
    Ok(output)
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}
