// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{format, string::String, vec::Vec};
use ring::{
    rand,
    signature::{
        EcdsaKeyPair, UnparsedPublicKey, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
    },
};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::{
    v2::collateral::{get_tcb_evaluation_number_from_collateral, Collateral},
    MigTdInfoProperty, PolicyError, Report, REPORT_DATA_SIZE,
};

pub mod collateral;

pub fn verify_policy(
    policy: &[u8],
    engine_svn_map: &[u8],
    report_peer: &[u8],
    tcb_status: &str,
    collateral: &Collateral<'_>,
) -> Result<(), PolicyError> {
    if report_peer.len() < REPORT_DATA_SIZE {
        return Err(PolicyError::InvalidParameter);
    }

    let report_peer = Report::new(report_peer)?;
    let policy = parse_mig_policy(policy)?;
    let engine = parse_engine_svn_map(engine_svn_map)?;
    let tcb_evaluation_number = get_tcb_evaluation_number_from_collateral(collateral)?;

    evaluate_policy(
        &policy,
        &engine,
        &report_peer,
        tcb_status,
        tcb_evaluation_number,
    )
}

pub fn verify_policy_signature(policy: &[u8], public_key: &[u8]) -> Result<(), PolicyError> {
    let policy = parse_mig_policy(policy)?;
    policy.verify_signature(public_key)
}

pub fn verify_engine_signature(engine: &[u8], public_key: &[u8]) -> Result<(), PolicyError> {
    let engine = parse_engine_svn_map(engine)?;
    engine.verify_signature(public_key)
}

fn parse_mig_policy(policy: &[u8]) -> Result<MigPolicy, PolicyError> {
    // Remove the trailing zeros
    let policy_str = core::str::from_utf8(policy)
        .map(|s| s.trim_matches(char::from(0)))
        .map_err(|_| PolicyError::InvalidPolicy)?;

    serde_json::from_str::<MigPolicy>(policy_str).map_err(|_| PolicyError::InvalidPolicy)
}

fn parse_engine_svn_map(engine: &[u8]) -> Result<EngineSvnMap, PolicyError> {
    // Remove the trailing zeros
    let engine_str = core::str::from_utf8(engine)
        .map(|s| s.trim_matches(char::from(0)))
        .map_err(|_| PolicyError::InvalidPolicy)?;
    serde_json::from_str::<EngineSvnMap>(engine_str).map_err(|_| PolicyError::InvalidPolicy)
}

fn evaluate_policy(
    policy: &MigPolicy,
    engine: &EngineSvnMap,
    report_peer: &Report,
    tcb_status: &str,
    tcb_evaluation_number: u32,
) -> Result<(), PolicyError> {
    let mrtd = report_peer.get_migtd_info_property(&MigTdInfoProperty::MrTd)?;
    let rtmr0 = report_peer.get_migtd_info_property(&MigTdInfoProperty::Rtmr0)?;
    let rtmr1 = report_peer.get_migtd_info_property(&MigTdInfoProperty::Rtmr1)?;

    let svn = engine
        .get_engine_svn(mrtd, rtmr0, rtmr1)
        .ok_or(PolicyError::SvnMismatch)?;
    // Evaluate the policy against the report and event log
    for policy_type in &policy.policy.policy {
        match policy_type {
            PolicyTypes::Global(global) => {
                // Evaluate global policy
                global
                    .tcb_number
                    .tcb_evaluation_data_number
                    .evaluate(tcb_evaluation_number)?;
                global.tcb_number.tcb_status.evaluate(tcb_status)?;
            }
            PolicyTypes::MigTD(migtd) => {
                migtd.migtd_identity.svn.evaluate(svn)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigPolicy {
    policy: Policy,
    signature: Option<String>,
}

impl MigPolicy {
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<(), PolicyError> {
        // Serialize the `policy` field to JSON
        let data_to_verify = serde_json::to_vec(&self.policy)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        let signature_bytes = hex_string_to_bytes(
            &self
                .signature
                .as_ref()
                .ok_or(PolicyError::SignatureVerificationFailed)?,
        )?;
        verify_ecdsa_384_signature(&data_to_verify, &signature_bytes, public_key)?;

        Ok(())
    }

    pub fn sign(&mut self, signing_key: &[u8]) -> Result<(), PolicyError> {
        // Serialize the policy field to JSON
        let data_to_sign = serde_json::to_vec(&self.policy)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        let signature = ecdsa_p384_sign(&data_to_sign, signing_key)?;
        self.signature = Some(bytes_to_hex_string(&signature));

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    id: String,
    version: String,
    policy: Vec<PolicyTypes>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PolicyTypes {
    Global(GlobalPolicy),
    MigTD(MigTdPolicy),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Global {
    #[serde(rename = "Global")]
    global_policy: GlobalPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalPolicy {
    #[serde(rename = "TcbNumber")]
    pub tcb_number: TcbNumberPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbNumberPolicy {
    pub tcb_evaluation_data_number: PolicyOperation<u32>,
    pub tcb_status: PolicyOperation<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigTd {
    #[serde(rename = "MigTD")]
    pub migtd_policy: MigTdPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigTdPolicy {
    #[serde(rename = "MigTdIdentity")]
    pub migtd_identity: MigTdIdentityPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigTdIdentityPolicy {
    #[serde(rename = "SVN")]
    pub svn: PolicyOperation<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyOperation<T> {
    pub operation: String,
    pub reference: T,
}

impl PolicyOperation<u32> {
    /// Evaluate a u32 operation against a reference value
    pub fn evaluate(&self, value: u32) -> Result<bool, PolicyError> {
        match self.operation.as_str() {
            "equal" => Ok(value == self.reference),
            "greater-than" => Ok(value > self.reference),
            "less-than" => Ok(value < self.reference),
            "greater-or-equal" => Ok(value >= self.reference),
            "less-or-equal" => Ok(value <= self.reference),
            "not-equal" => Ok(value != self.reference),
            _ => Err(PolicyError::InvalidOperation),
        }
    }
}

impl PolicyOperation<String> {
    /// Evaluate a String operation against a reference value
    pub fn evaluate(&self, value: &str) -> Result<bool, PolicyError> {
        match self.operation.as_str() {
            "equal" => Ok(value == self.reference),
            "not-equal" => Ok(value != self.reference),
            "contains" => Ok(self.reference.contains(value)),
            "starts-with" => Ok(value.starts_with(&self.reference)),
            "ends-with" => Ok(value.ends_with(&self.reference)),
            "in-list" => {
                // Check if value is in comma-separated list
                let items: Vec<&str> = self.reference.split(',').map(|s| s.trim()).collect();
                Ok(items.contains(&value))
            }
            _ => Err(PolicyError::InvalidOperation),
        }
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
    /// Verifies the signature of the engine_svn map using the provided public key
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<(), PolicyError> {
        // Serialize the `engine_svn`` field to JSON
        let data_to_verify = serde_json::to_vec(&self.engine_svn)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        let signature_bytes = hex_string_to_bytes(&self.signature)?;
        verify_ecdsa_384_signature(&data_to_verify, &signature_bytes, public_key)?;

        Ok(())
    }

    pub fn get_engine_svn(&self, mrtd: &[u8], rtmr0: &[u8], rtmr1: &[u8]) -> Option<u32> {
        self.engine_svn.iter().find_map(|engine| {
            if engine.mrtd.as_bytes() == mrtd && engine.rtmr0.as_bytes() == rtmr0 && engine.rtmr1.as_bytes() == rtmr1 {
                Some(engine.svn)
            } else {
                None
            }
        })
    }

    pub fn sign_engine(&mut self, signing_key: &[u8]) -> Result<(), PolicyError> {
        // Serialize the `engine_svn` field to JSON
        let data_to_sign = serde_json::to_vec(&self.engine_svn).unwrap();

        let signature = ecdsa_p384_sign(&data_to_sign, signing_key)?;
        self.signature = bytes_to_hex_string(&signature);

        Ok(())
    }
}

/// Convert a hex string to bytes without using external crates
fn hex_string_to_bytes(hex: &str) -> Result<Vec<u8>, PolicyError> {
    // Ensure even number of characters
    if hex.len() % 2 != 0 {
        return Err(PolicyError::SignatureVerificationFailed);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    // Process two hex digits at a time
    for i in (0..hex.len()).step_by(2) {
        if i + 2 > hex.len() {
            break;
        }

        // Get the hex byte as a string slice
        let byte_str = &hex[i..i + 2];

        // Convert to numeric value
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        bytes.push(byte);
    }

    Ok(bytes)
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// Convert ECDSA DER public key to raw bytes (04 || x || y)
fn ecdsa_der_pubkey_to_raw(der_pubkey: &[u8]) -> Result<Vec<u8>, PolicyError> {
    // Check for SEQUENCE tag
    if der_pubkey.len() < 2 || der_pubkey[0] != 0x30 {
        return Err(PolicyError::Crypto);
    }

    // Find the BIT STRING tag (0x03) that contains the actual key
    let mut pos = 0;
    while pos < der_pubkey.len() - 2 {
        if der_pubkey[pos] == 0x03 {
            // Found BIT STRING
            pos += 1;

            // Get length
            let len = der_pubkey[pos] as usize;
            pos += 1;

            // Skip unused bits byte
            pos += 1;

            // The rest is the key data
            return Ok(der_pubkey[pos..pos + len - 1].to_vec());
        }
        pos += 1;
    }

    Err(PolicyError::Crypto)
}

fn verify_ecdsa_384_signature(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), PolicyError> {
    let public_key = ecdsa_der_pubkey_to_raw(public_key).map_err(|_| PolicyError::Crypto)?;

    // Verify the signature with `ring`
    let signature_verifier = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &public_key);
    signature_verifier
        .verify(data, signature)
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    Ok(())
}

fn ecdsa_p384_sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let rng = rand::SystemRandom::new();
    let ecdsa_key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, private_key, &rng)
            .map_err(|_| PolicyError::Crypto)?;

    let signature = ecdsa_key_pair
        .sign(&rng, data)
        .map_err(|_| PolicyError::Crypto)?
        .as_ref()
        .to_vec();
    Ok(signature)
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{string::ToString, vec};

    #[test]
    fn test_hex_string_to_bytes() {
        // Test valid hex strings
        assert_eq!(
            hex_string_to_bytes("48656c6c6f").unwrap(),
            vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]
        );
        assert_eq!(
            hex_string_to_bytes("ff00ff").unwrap(),
            vec![0xff, 0x00, 0xff]
        );

        // Test invalid hex strings
        assert!(hex_string_to_bytes("123g").is_err());
        assert!(hex_string_to_bytes("123").is_err()); // Odd length
    }

    #[test]
    fn test_verify_policy_signature() {
        let policy_bytes = include_bytes!("../../test/policy_v2/policy.json");
        let policy = serde_json::from_slice::<MigPolicy>(policy_bytes).unwrap();
        let public_key = include_bytes!("../../test/policy_v2/policy-public.der");
        policy.verify_signature(public_key).unwrap();
    }

    #[test]
    fn test_verify_engine_signature() {
        let engine_bytes = include_bytes!("../../test/policy_v2/engine.json");
        let engine = serde_json::from_slice::<EngineSvnMap>(engine_bytes).unwrap();
        let public_key = include_bytes!("../../test/policy_v2/engine-public.der");
        engine.verify_signature(public_key).unwrap();
    }

    #[test]
    fn test_get_engine_svn() {
        let engine_bytes = include_bytes!("../../test/policy_v2/engine.json");
        let engine: EngineSvnMap = serde_json::from_slice(engine_bytes).unwrap();

        let mrtd = b"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let rtmr0 = b"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let rtmr1 = b"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        assert_eq!(engine.get_engine_svn(mrtd, rtmr0, rtmr1), Some(1));

        let mrtd = b"01234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde";
        let rtmr0 = b"bcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890a";
        let rtmr1 = b"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        assert!(engine.get_engine_svn(mrtd, rtmr0, rtmr1).is_none());
    }

    #[test]
    fn test_gen_policy() {
        extern crate std;

        let mut policy = MigPolicy {
            policy: Policy {
                id: "5752E5CA-1E06-4883-A110-2D4405D35BAD".to_string(),
                version: 2.to_string(),
                policy: vec![
                    PolicyTypes::Global(GlobalPolicy {
                        tcb_number: TcbNumberPolicy {
                            tcb_evaluation_data_number: PolicyOperation {
                                operation: "greater-or-equal".to_string(),
                                reference: 3,
                            },
                            tcb_status: PolicyOperation {
                                operation: "in-list".to_string(),
                                reference: "UpToDate;ConfigurationNeeded".to_string(),
                            },
                        },
                    }),
                    PolicyTypes::MigTD(MigTdPolicy {
                        migtd_identity: MigTdIdentityPolicy {
                            svn: PolicyOperation {
                                operation: "greater-or-equal".to_string(),
                                reference: 5,
                            },
                        },
                    }),
                ],
            },
            signature: None,
        };
        let signing_key = include_bytes!("../../test/policy_v2/policy-private.pk8");
        policy.sign(signing_key).unwrap();

        let policy_json = serde_json::to_string(&policy).unwrap();
        std::fs::write("test/policy_v2/policy.json", policy_json).unwrap();
    }

    #[test]
    fn test_gen_engine() {
        extern crate std;

        let mut engine = EngineSvnMap {
            engine_svn: vec![EngineSvn {
                mrtd: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                    .to_string(),
                rtmr0: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    .to_string(),
                rtmr1: "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
                    .to_string(),
                svn: 1,
            }],
            signature: String::new(),
        };

        let signing_key = include_bytes!("../../test/policy_v2/engine-private.pk8");
        engine.sign_engine(signing_key).unwrap();

        let policy_json = serde_json::to_string(&engine).unwrap();
        std::fs::write("test/policy_v2/engine.json", policy_json).unwrap();
    }
}
