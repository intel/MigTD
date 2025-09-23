// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use ring::pkcs8::Document;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair, UnparsedPublicKey};
use rustls_pemfile::Item;
use zeroize::Zeroize;

use crate::{Error, Result};

// Re-export ring's ECDSA verification algorithms for convenient access
pub use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA384_ASN1,
    ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED,
};

pub struct EcdsaPk {
    pk: Document,
}

impl core::fmt::Debug for EcdsaPk {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

impl EcdsaPk {
    pub fn new() -> Result<Self> {
        let rand = SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &rand)
            .map(|pk| Self { pk })
            .map_err(|_| Error::GenerateKeyPair)
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rand = SystemRandom::new();
        let ecdsa_key = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            self.pk.as_ref(),
            &rand,
        )
        .map_err(|_| Error::GenerateKeyPair)?;

        ecdsa_key
            .sign(&rand, data)
            .as_ref()
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| Error::EcdsaSign)
    }

    pub fn private_key(&self) -> &[u8] {
        self.pk.as_ref()
    }

    pub fn public_key(&self) -> Result<Vec<u8>> {
        let rand = SystemRandom::new();
        let ecdsa_key = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            self.pk.as_ref(),
            &rand,
        )
        .map_err(|_| Error::GenerateKeyPair)?;
        Ok(ecdsa_key.public_key().as_ref().to_vec())
    }
}

impl Drop for EcdsaPk {
    fn drop(&mut self) {
        sensitive_data_cleanup(self)
    }
}

pub fn ecdsa_verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let pk = UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, public_key);
    pk.verify(data, signature).map_err(|_e| Error::EcdsaVerify)
}

pub fn ecdsa_verify_with_algorithm(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
    algorithm: &'static dyn signature::VerificationAlgorithm,
) -> Result<()> {
    let pk = UnparsedPublicKey::new(algorithm, public_key);
    pk.verify(data, signature).map_err(|_e| Error::EcdsaVerify)
}

pub fn ecdsa_verify_with_raw_public_key(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    let pk = UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, public_key);
    pk.verify(data, signature).map_err(|_e| Error::EcdsaVerify)
}

pub fn ecdsa_sign(pkcs8: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let rand = SystemRandom::new();
    let ecdsa_key =
        EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8, &rand).unwrap();

    ecdsa_key
        .sign(&rand, data)
        .as_ref()
        .map(|s| s.as_ref().to_vec())
        .map_err(|_| Error::EcdsaSign)
}

pub fn pem_to_der_from_slice(pem_data: &[u8]) -> Result<Vec<u8>> {
    match rustls_pemfile::read_one_from_slice(pem_data).map_err(|_| Error::DecodePemCert)? {
        Some((Item::X509Certificate(cert), _remaining)) => Ok(cert.to_vec()),
        Some((Item::Pkcs8Key(key), _)) => Ok(key.secret_pkcs8_der().to_vec()),
        Some((Item::Pkcs1Key(key), _)) => Ok(key.secret_pkcs1_der().to_vec()),
        Some((Item::Sec1Key(key), _)) => Ok(key.secret_sec1_der().to_vec()),
        _ => Err(Error::DecodePemCert),
    }
}

// Here is a workaround to cleanup the structures that contain sensitive
// data, since some of the structure defined by ring do not implement the
// trait 'drop' to zero the content
// See https://github.com/briansmith/ring/issues/15
fn sensitive_data_cleanup<T: Sized>(t: &mut T) {
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(t as *mut T as *mut u8, core::mem::size_of::<T>())
    };
    bytes.zeroize();
}
