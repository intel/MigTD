// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::string::ToString;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../crypto/test/crl/fixtures.rs"
));

pub fn policy_json(crl: &[u8]) -> serde_json::Value {
    let mut policy: serde_json::Value =
        serde_json::from_slice(include_bytes!("policy_v2.json")).unwrap();
    let collateral = &mut policy["policyData"]["servtdCollateral"];
    collateral["servtdIdentityIssuerChain"] = core::str::from_utf8(IDENTITY_CHAIN).unwrap().into();
    collateral["servtdIdentity"] = serde_json::from_slice(SIGNED_IDENTITY).unwrap();
    collateral["servtdTcbMapping"] = serde_json::from_slice(SIGNED_MAPPING).unwrap();
    collateral["servtdCrl"] =
        serde_json::Value::String(core::str::from_utf8(crl).unwrap().to_string());
    policy
}
