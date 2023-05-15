// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use ring::pkcs8::Document;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair, UnparsedPublicKey};
use zeroize::Zeroize;

use crate::{Error, Result};

pub struct EcdsaPk {
    pk: Document,
}

impl EcdsaPk {
    pub fn new() -> Result<Self> {
        let rand = SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &rand)
            .map(|pk| Self { pk })
            .map_err(|_| Error::GenerateKeyPair)
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let ecdsa_key =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, self.pk.as_ref())
                .map_err(|_| Error::GenerateKeyPair)?;
        let rand = SystemRandom::new();

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
        let ecdsa_key =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, self.pk.as_ref())
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

// Here is a workaround to cleanup the structures that contain sensitive
// data, since some of the structure defined by ring do not implement the
// trait 'drop' to zero the content
// See https://github.com/briansmith/ring/issues/15
fn sensitive_data_cleanup<T: Sized>(t: &mut T) {
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(t as *mut T as u64 as *mut u8, core::mem::size_of::<T>())
    };
    bytes.zeroize();
}
