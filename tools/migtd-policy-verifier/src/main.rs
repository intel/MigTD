// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{Context, Result};
use clap::Parser;
use policy::RawPolicyData;
use std::fs;

/// MigTD Policy Verifier Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to signed policy file (JSON)
    #[arg(short, long)]
    policy: String,

    /// Path to issuer certificate chain (PEM)
    #[arg(short, long)]
    cert_chain: String,

    /// Path to standalone signed servTD TCB mapping (JSON)
    #[arg(long)]
    servtd_tcb_mapping: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let policy_bytes = fs::read(&args.policy)
        .with_context(|| format!("Failed to read policy file: {}", args.policy))?;
    let cert_chain_bytes = fs::read(&args.cert_chain)
        .with_context(|| format!("Failed to read cert chain file: {}", args.cert_chain))?;
    let mapping_bytes = fs::read(&args.servtd_tcb_mapping).with_context(|| {
        format!(
            "Failed to read servTD TCB mapping file: {}",
            args.servtd_tcb_mapping
        )
    })?;

    verify_policy(&policy_bytes, &cert_chain_bytes, &mapping_bytes)
        .map_err(|e| anyhow::anyhow!("Policy verification failed: {e:?}"))?;

    println!("Policy, standalone TCB mapping, and signer chains verified successfully.");

    Ok(())
}

fn verify_policy(
    policy_bytes: &[u8],
    cert_chain_bytes: &[u8],
    mapping_bytes: &[u8],
) -> Result<(), policy::PolicyError> {
    // Match firmware rejection of legacy embedded mapping fields.
    policy::extract_canonical_policy_data_bytes(policy_bytes)?;
    let raw = RawPolicyData::deserialize_from_json(policy_bytes)?;
    let mut verified = raw.verify(cert_chain_bytes)?;
    verified.attach_verified_json_mapping(mapping_bytes, cert_chain_bytes)?;
    verified.verify_signer_chains_not_revoked(verified.servtd_crl.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy::PolicyError;
    use serde_json::{json, Value};

    #[allow(dead_code)]
    mod fixtures {
        include!("../../../src/crypto/test/crl/fixtures.rs");
    }

    fn policy_json(crl: &[u8]) -> Value {
        let mut policy: Value = serde_json::from_slice(include_bytes!(
            "../../../src/policy/test/policy_v2/policy_v2.json"
        ))
        .unwrap();
        let collateral = &mut policy["policyData"]["servtdCollateral"];
        collateral["servtdIdentity"] = serde_json::from_slice(fixtures::SIGNED_IDENTITY).unwrap();
        collateral["servtdIdentityIssuerChain"] = core::str::from_utf8(fixtures::IDENTITY_CHAIN)
            .unwrap()
            .into();
        collateral["servtdCrl"] = core::str::from_utf8(crl).unwrap().into();
        policy
    }

    #[test]
    fn verifies_standalone_mapping() {
        let input = serde_json::to_vec(&policy_json(fixtures::EMPTY_CRL)).unwrap();
        verify_policy(&input, fixtures::POLICY_CHAIN, fixtures::SIGNED_MAPPING).unwrap();
    }

    #[test]
    fn rejects_missing_tampered_or_embedded_mapping() {
        let mut policy = policy_json(fixtures::EMPTY_CRL);
        let input = serde_json::to_vec(&policy).unwrap();
        let mut mapping: Value = serde_json::from_slice(fixtures::SIGNED_MAPPING).unwrap();
        mapping["signature"] = json!("00");
        let tampered = serde_json::to_vec(&mapping).unwrap();
        for mapping in [b"".as_slice(), tampered.as_slice()] {
            assert!(verify_policy(&input, fixtures::POLICY_CHAIN, mapping).is_err());
        }

        policy["policyData"]["servtdCollateral"]["servtdTcbMapping"] =
            serde_json::from_slice(fixtures::SIGNED_MAPPING).unwrap();
        let input = serde_json::to_vec(&policy).unwrap();
        assert!(matches!(
            verify_policy(&input, fixtures::POLICY_CHAIN, fixtures::SIGNED_MAPPING),
            Err(PolicyError::InvalidPolicy)
        ));
    }

    #[test]
    fn rejects_revoked_mapping_signer() {
        let input = serde_json::to_vec(&policy_json(fixtures::REVOKED_POLICY_CRL)).unwrap();
        assert!(matches!(
            verify_policy(&input, fixtures::POLICY_CHAIN, fixtures::SIGNED_MAPPING),
            Err(PolicyError::SignerRevoked)
        ));
    }

    #[test]
    fn rejects_unauthenticated_crl_without_identity() {
        let mut policy = policy_json(fixtures::TAMPERED_CRL);
        let collateral = policy["policyData"]["servtdCollateral"]
            .as_object_mut()
            .unwrap();
        collateral.remove("servtdIdentity");
        collateral.remove("servtdIdentityIssuerChain");
        let input = serde_json::to_vec(&policy).unwrap();
        assert!(matches!(
            verify_policy(&input, fixtures::POLICY_CHAIN, fixtures::SIGNED_MAPPING),
            Err(PolicyError::SignerRevoked)
        ));
    }
}
