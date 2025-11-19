// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crypto::{
    x509::{DerError, ObjectIdentifier},
    Error as CryptoError,
};
use tdx_tdcall::TdCallError;

#[cfg(feature = "main")]
mod server_client;
#[cfg(feature = "main")]
pub use server_client::*;

#[derive(Debug)]
pub enum RatlsError {
    GetQuote,
    VerifyQuote,
    TdxModule(TdCallError),
    Crypto(CryptoError),
    X509(DerError),
    InvalidEventlog,
    InvalidPolicy,
}

impl From<TdCallError> for RatlsError {
    fn from(value: TdCallError) -> Self {
        Self::TdxModule(value)
    }
}

impl From<CryptoError> for RatlsError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<DerError> for RatlsError {
    fn from(value: DerError) -> Self {
        Self::X509(value)
    }
}

pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
pub const MIGTD_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.5.5.1.1");
pub const EXTNID_MIGTD_QUOTE_REPORT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.5.5.1.2");
pub const EXTNID_MIGTD_EVENT_LOG: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.5.5.1.3");
pub const EXTNID_MIGTD_POLICY_HASH: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.5.5.1.4");

// As specified in https://datatracker.ietf.org/doc/html/rfc5480#appendix-A
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//     iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1
// }
pub const ID_EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
// secp384r1 OBJECT IDENTIFIER ::= {
//     iso(1) identified-organization(3) certicom(132) curve(0) 34
// }
pub const SECP384R1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub const KEY_USAGE_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
pub const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
pub const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
pub const ID_EC_SIG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

pub const MIG_POLICY_UNSATISFIED_ERROR: &str = "PolicyUnsatisfiedError";
pub const INVALID_MIG_POLICY_ERROR: &str = "InvalidPolicyError";
pub const MUTUAL_ATTESTATION_ERROR: &str = "MutualAttestationError";
pub const MISMATCH_PUBLIC_KEY: &str = "MismatchPublicKeyError";
