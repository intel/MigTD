// SPDX-License-Identifier: BSD-2-Clause-Patent

// Public P-384/SHA-384 test fixtures; no private keys are retained.
// Leaf serials 0x80 and 0x81 exercise DER INTEGER sign-padding normalization.
pub const ROOT_CERT: &[u8] = include_bytes!("root.pem");
pub const ISSUER_CERT: &[u8] = include_bytes!("issuer.pem");
pub const POLICY_CHAIN: &[u8] = concat!(
    include_str!("policy.pem"),
    include_str!("issuer.pem"),
    include_str!("root.pem")
)
.as_bytes();
pub const ROTATED_POLICY_CHAIN: &[u8] = concat!(
    include_str!("policy_rotated.pem"),
    include_str!("issuer.pem"),
    include_str!("root.pem")
)
.as_bytes();
pub const IDENTITY_CHAIN: &[u8] = concat!(
    include_str!("identity.pem"),
    include_str!("issuer.pem"),
    include_str!("root.pem")
)
.as_bytes();
pub const IDENTITY_OTHER_ISSUER_CHAIN: &[u8] = concat!(
    include_str!("identity_other_issuer.pem"),
    include_str!("root.pem")
)
.as_bytes();

pub const EMPTY_CRL: &[u8] = include_bytes!("empty.crl.pem");
pub const REVOKED_POLICY_CRL: &[u8] = include_bytes!("revoked_policy.crl.pem");
pub const REVOKED_IDENTITY_CRL: &[u8] = include_bytes!("revoked_identity.crl.pem");
pub const REVOKED_ISSUER_CRL: &[u8] = include_bytes!("revoked_issuer.crl.pem");
pub const UNRELATED_CRL: &[u8] = include_bytes!("unrelated.crl.pem");
pub const TAMPERED_CRL: &[u8] = include_bytes!("tampered.crl.pem");
pub const NON_CA_CRL: &[u8] = include_bytes!("non_ca.crl.pem");
pub const ROOT_EMPTY_CRL: &[u8] = include_bytes!("root_empty.crl.pem");
pub const NO_NUMBER_CRL: &[u8] = include_bytes!("no_number.crl.pem");

pub const SIGNED_IDENTITY: &[u8] = include_bytes!("signed_identity.json");
pub const SIGNED_IDENTITY_OTHER_ISSUER: &[u8] = include_bytes!("signed_identity_other_issuer.json");
pub const SIGNED_MAPPING: &[u8] = include_bytes!("signed_mapping.json");
pub const SIGNED_MAPPING_ROTATED: &[u8] = include_bytes!("signed_mapping_rotated.json");
