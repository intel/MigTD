// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

#[macro_use]
extern crate alloc;

use alloc::string::String;

cfg_if::cfg_if! {
    if #[cfg(feature = "rustls")] {
        pub mod rustls_impl;
        pub use rustls_impl::ecdsa;
        pub use rustls_impl::hash;
        pub use rustls_impl::tls;
    }
}

pub mod x509;

pub type Result<T> = core::result::Result<T, Error>;

pub const SHA384_DIGEST_SIZE: usize = 48;

#[derive(Debug)]
pub enum Error {
    /// Couldn't caculate the hash digest of the given data
    CalculateDigest,

    /// Couldn't generate random number
    GetRandom,

    /// Failed to generate asymmetric key
    GenerateKeyPair,

    /// Failed to generate X.509 certificate used for TLS
    GenerateCertificate(x509::DerError),

    /// Failed to parse X.509 certificate
    ParseCertificate,

    /// Failed to calculate the ECDSA digital signature of the given data
    EcdsaSign,

    /// Failed to verify the ECDSA digital signature of the given data
    EcdsaVerify,

    /// Couldn't configure the TLS contex, e.g., cipher suite, TLS protocol version.
    SetupTlsContext(tls::TlsLibError),

    /// Invalid DNS name
    InvalidDnsName,

    /// Error occurs during reading/writing the tls connection
    TlsStream,

    /// Unable to get the TLS peer's certificates
    TlsGetPeerCert,

    /// Unable to verify the TLS peer's certificates
    TlsVerifyPeerCert(String),

    /// Error occurs during processing the tls connection
    TlsConnection,

    /// Pem certificate parsing error
    DecodePemCert,

    /// Unexpected error that should not happen
    Unexpected,
}

impl From<x509::DerError> for Error {
    fn from(e: x509::DerError) -> Error {
        Error::GenerateCertificate(e)
    }
}
