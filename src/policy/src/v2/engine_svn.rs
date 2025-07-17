// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{string::String, vec::Vec};
use core::convert::TryInto;
use serde::{Deserialize, Serialize};
use serde_json::{self, value::RawValue};

use crate::{
    parse_events,
    v2::{bytes_to_hex_string, ecdsa_der_pubkey_to_raw, hex_string_to_bytes, verify_event_hash},
    EventName, MigTdInfoProperty, PolicyError, Report,
};

pub fn verify_engine_signature<'a>(
    engine: &'a [u8],
    public_key: &[u8],
) -> Result<PartialEngineSvnMap<'a>, PolicyError> {
    let partial_engine_svn_map = PartialEngineSvnMap::deserialize_from_json(engine)?;

    let signature_bytes = hex_string_to_bytes(
        &partial_engine_svn_map
            .signature
            .as_ref()
            .ok_or(PolicyError::SignatureVerificationFailed)?,
    )?;
    let public_key = ecdsa_der_pubkey_to_raw(public_key).map_err(|_| PolicyError::Crypto)?;

    crypto::ecdsa::ecdsa_verify_with_raw_public_key(
        &public_key,
        partial_engine_svn_map.engine_svn.get().as_bytes(),
        &signature_bytes,
    )
    .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    Ok(partial_engine_svn_map)
}

pub fn verify_engine_integrity(
    engine: &[u8],
    public_key: &[u8],
    event_log: &[u8],
) -> Result<EngineSvnMap, PolicyError> {
    let partial_engine_svn_map = verify_engine_signature(engine, public_key)?;
    let events = parse_events(event_log).ok_or(PolicyError::InvalidEventLog)?;

    if !verify_event_hash(
        &events,
        &EventName::MigTdEngine,
        partial_engine_svn_map.engine_svn.get().as_bytes(),
    )? {
        return Err(PolicyError::InvalidEngineSvnMap);
    }
    partial_engine_svn_map.try_into()
}

pub fn get_engine_svn_from_map(engine: &[u8], report: &[u8]) -> Result<u32, PolicyError> {
    let engine_svn_map = parse_engine_svn_map(engine)?;
    let report_values = Report::new(report)?;

    engine_svn_map
        .get_engine_svn(&report_values)
        .ok_or(PolicyError::SvnMismatch)
}

fn parse_engine_svn_map(engine: &[u8]) -> Result<EngineSvnMap, PolicyError> {
    // Remove the trailing zeros
    let engine_str = core::str::from_utf8(engine)
        .map(|s| s.trim_matches(char::from(0)))
        .map_err(|_| PolicyError::InvalidPolicy)?;
    serde_json::from_str::<EngineSvnMap>(engine_str).map_err(|_| PolicyError::InvalidPolicy)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialEngineSvnMap<'a> {
    #[serde(borrow)]
    engine_svn: &'a RawValue,
    signature: Option<String>,
}

impl<'a> PartialEngineSvnMap<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<PartialEngineSvnMap>(slice)
            .map_err(|_| PolicyError::InvalidEngineSvnMap)
    }

    pub fn sign(&mut self, signing_key: &[u8]) -> Result<(), PolicyError> {
        let signature = crypto::ecdsa::ecdsa_sign(self.engine_svn.get().as_bytes(), signing_key)
            .map_err(|_| PolicyError::Crypto)?;
        self.signature = Some(bytes_to_hex_string(&signature));

        Ok(())
    }
}

impl TryInto<EngineSvnMap> for PartialEngineSvnMap<'_> {
    type Error = PolicyError;
    fn try_into(self) -> Result<EngineSvnMap, Self::Error> {
        let engine_svn = serde_json::from_str(self.engine_svn.get())
            .map_err(|_| PolicyError::InvalidEngineSvnMap)?;
        Ok(EngineSvnMap {
            engine_svn,
            signature: self.signature.ok_or(PolicyError::InvalidEngineSvnMap)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EngineSvn {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub svn: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EngineSvnMap {
    pub engine_svn: Vec<EngineSvn>,
    pub signature: String,
}

impl EngineSvnMap {
    pub fn get_engine_svn(&self, report: &Report) -> Option<u32> {
        self.get_engine_svn_by_values(
            report
                .get_migtd_info_property(&MigTdInfoProperty::MrTd)
                .ok()?,
            report
                .get_migtd_info_property(&MigTdInfoProperty::Rtmr0)
                .ok()?,
            report
                .get_migtd_info_property(&MigTdInfoProperty::Rtmr1)
                .ok()?,
        )
    }

    fn get_engine_svn_by_values(&self, mrtd: &[u8], rtmr0: &[u8], rtmr1: &[u8]) -> Option<u32> {
        self.engine_svn.iter().find_map(|engine| {
            if engine.mrtd.as_bytes() == mrtd
                && engine.rtmr0.as_bytes() == rtmr0
                && engine.rtmr1.as_bytes() == rtmr1
            {
                Some(engine.svn)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify_engine_signature() {
        let engine_bytes = include_bytes!("../../test/policy_v2/engine.json");
        let public_key = include_bytes!("../../test/policy_v2/engine-public.der");
        verify_engine_signature(engine_bytes, public_key).unwrap();
    }

    #[test]
    fn test_get_engine_svn() {
        let engine_bytes = include_bytes!("../../test/policy_v2/engine.json");
        let engine: EngineSvnMap = serde_json::from_slice(engine_bytes).unwrap();

        let mrtd = b"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let rtmr0 = b"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let rtmr1 = b"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        assert_eq!(engine.get_engine_svn_by_values(mrtd, rtmr0, rtmr1), Some(1));

        let mrtd = b"01234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde";
        let rtmr0 = b"bcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890a";
        let rtmr1 = b"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        assert!(engine
            .get_engine_svn_by_values(mrtd, rtmr0, rtmr1)
            .is_none());
    }
}
