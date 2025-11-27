// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

extern crate alloc;

use alloc::{
    boxed::Box, collections::BTreeMap, format, string::String, string::ToString, vec::Vec,
};
use core::result::Result;
use crypto::x509::SubjectPublicKeyInfo;
use der::Decode;
pub use serde_json::Error as JsonError;
use serde_json::{value::RawValue, Map, Value};

const SIGNATURE_KEY: &str = "signature";

#[derive(Debug)]
pub enum Error {
    InvalidJson(JsonError),
    InvalidKey,
    InvalidString,
    InvalidSignedJson,
    Sign,
    Verify,
    NotCanonical,
    NoPublicKey,
}

impl From<JsonError> for Error {
    fn from(e: JsonError) -> Self {
        Error::InvalidJson(e)
    }
}

pub fn json_sign(json_key: &str, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, Error> {
    let value: Value = serde_json::from_slice(data)?;
    let canonical_data = serde_json::to_vec(&value)?;

    if data != canonical_data {
        return Err(Error::NotCanonical);
    }

    let private_key_der =
        crypto::ecdsa::pem_to_der_from_slice(private_key).map_err(|_| Error::InvalidKey)?;
    let signature = crypto::ecdsa::ecdsa_sign(&private_key_der, data).map_err(|_| Error::Sign)?;

    json_set_signature(json_key, data, &signature)
}

pub fn json_sign_detached(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, Error> {
    let private_key_der =
        crypto::ecdsa::pem_to_der_from_slice(private_key).map_err(|_| Error::InvalidKey)?;
    let signature = crypto::ecdsa::ecdsa_sign(&private_key_der, data).map_err(|_| Error::Sign)?;

    Ok(signature.to_vec())
}

pub fn json_verify(data: &[u8], public_key: &[u8], signature: &[u8]) -> Result<(), Error> {
    let public_key_der =
        crypto::ecdsa::pem_to_der_from_slice(public_key).map_err(|_| Error::InvalidKey)?;
    let public_key_raw = extract_public_key_bytes(&public_key_der)?;

    crypto::ecdsa::ecdsa_verify(&public_key_raw, data, signature).map_err(|_| Error::Verify)
}

pub fn json_verify_from_signed(
    json_key: &str,
    signed_json: &[u8],
    public_key: &[u8],
) -> Result<(), Error> {
    let public_key_der =
        crypto::ecdsa::pem_to_der_from_slice(public_key).map_err(|_| Error::InvalidKey)?;
    let public_key_raw = extract_public_key_bytes(&public_key_der)?;
    let parsed: BTreeMap<String, &RawValue> = serde_json::from_slice(signed_json)?;

    // Must have exactly 2 keys
    if parsed.len() != 2 {
        return Err(Error::InvalidSignedJson);
    }

    if !parsed.contains_key(SIGNATURE_KEY) || !parsed.contains_key(json_key) {
        return Err(Error::InvalidSignedJson);
    }

    let sig_hex = parsed
        .get(SIGNATURE_KEY)
        .and_then(|v| serde_json::from_str::<String>(v.get()).ok())
        .ok_or(Error::InvalidSignedJson)?;
    let signature = hex_string_to_bytes(&sig_hex)?;
    let data_bytes = parsed
        .get(json_key)
        .ok_or(Error::InvalidSignedJson)?
        .get()
        .as_bytes();

    crypto::ecdsa::ecdsa_verify(&public_key_raw, data_bytes, &signature).map_err(|_| Error::Verify)
}

fn hex_string_to_bytes(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 2 != 0 {
        return Err(Error::InvalidString);
    }

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error::InvalidString))
        .collect::<Result<Vec<u8>, Error>>()
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
    map.insert(SIGNATURE_KEY.to_string(), Value::String(sig_hex));

    let output = serde_json::to_vec(&map)?;
    Ok(output)
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn extract_public_key_bytes(spki_der: &[u8]) -> Result<Vec<u8>, Error> {
    let spki = SubjectPublicKeyInfo::from_der(spki_der).map_err(|_| Error::InvalidKey)?;
    spki.subject_public_key
        .as_bytes()
        .map(|bytes| bytes.to_vec())
        .ok_or(Error::NoPublicKey)
}
