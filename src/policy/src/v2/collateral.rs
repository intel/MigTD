// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;

use alloc::{string::String, vec::Vec};
use crypto::x509::{self, AnyRef, Decode, DerResult, ObjectIdentifier, OctetStringRef, Reader};
use serde::Deserialize;

use crate::PolicyError;

pub fn get_fmspc_from_quote(quote: &[u8]) -> Result<[u8; 6], PolicyError> {
    const PEM_CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----\n";
    const PEM_CERT_END: &str = "-----END CERTIFICATE-----\n";

    let mid = String::from_utf8_lossy(quote);
    let start_index = mid.find(PEM_CERT_BEGIN).ok_or(PolicyError::InvalidQuote)?;
    let end_index = mid.find(PEM_CERT_END).ok_or(PolicyError::InvalidQuote)? + PEM_CERT_END.len();

    let pck_cert = mid[start_index..end_index].as_bytes();
    let pck_der = crypto::pem_cert_to_der(pck_cert).map_err(|_| PolicyError::InvalidQuote)?;

    parse_fmspc_from_pck_cert(pck_der.as_ref())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InnerValue<'a> {
    pub id: ObjectIdentifier,
    pub value: Option<AnyRef<'a>>,
}

impl<'a> Decode<'a> for InnerValue<'a> {
    fn decode<R: Reader<'a>>(decoder: &mut R) -> DerResult<Self> {
        decoder.sequence(|decoder| {
            let id = decoder.decode()?;
            let value = decoder.decode()?;

            Ok(Self { id, value })
        })
    }
}

fn parse_fmspc_from_pck_cert(pck_der: &[u8]) -> Result<[u8; 6], PolicyError> {
    const PCK_FMSPC_EXTENSION_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
    const PCK_FMSPC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");

    let x509 = x509::Certificate::from_der(pck_der).map_err(|_| PolicyError::InvalidQuote)?;
    let extensions = x509
        .tbs_certificate
        .extensions
        .ok_or(PolicyError::InvalidQuote)?;
    for ext in extensions.get() {
        if ext.extn_id == PCK_FMSPC_EXTENSION_OID {
            let vals = Vec::<InnerValue>::from_der(
                ext.extn_value.ok_or(PolicyError::InvalidQuote)?.as_bytes(),
            )
            .map_err(|_| PolicyError::InvalidQuote)?;
            for val in vals {
                if val.id == PCK_FMSPC_OID {
                    return val
                        .value
                        .ok_or(PolicyError::InvalidQuote)?
                        .decode_as::<OctetStringRef>()
                        .map_err(|_| PolicyError::InvalidQuote)?
                        .as_bytes()
                        .try_into()
                        .map_err(|_| PolicyError::InvalidQuote);
                }
            }
        }
    }
    Err(PolicyError::InvalidQuote)
}

pub struct Collateral<'a> {
    pub fmspc: [u8; 6],
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: &'a [u8],
    pub root_ca_crl: &'a [u8],
    pub pck_crl: &'a [u8],
    pub tcb_info_issuer_chain: &'a [u8],
    pub tcb_info: &'a [u8],
    pub qe_identity_issuer_chain: &'a [u8],
    pub qe_identity: &'a [u8],
}

impl<'a> Collateral<'a> {
    /// Read a Collateral instance from a byte slice.
    pub fn read_from_bytes(bytes: &'a [u8]) -> Result<Self, PolicyError> {
        // Check minimum size for header
        if bytes.len() < 18 {
            // 4(size) + 2(major) + 2(minor) + 4(tee) + 6(fmspc)
            return Err(PolicyError::InvalidCollateral);
        }

        let size = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if bytes.len() < size as usize {
            return Err(PolicyError::InvalidCollateral);
        }

        // Read FMSPC
        let mut fmspc = [0u8; 6];
        fmspc.copy_from_slice(&bytes[4..10]);

        let major_version = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
        let minor_version = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
        let tee_type = u32::from_le_bytes(bytes[14..18].try_into().unwrap());

        // Parse variable length sections
        let mut offset = 18;

        // Helper closure to read a variable length field
        let read_field = |offset: &mut usize| -> Result<&'a [u8], PolicyError> {
            if *offset + 4 > bytes.len() {
                return Err(PolicyError::InvalidCollateral);
            }

            let len = u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().unwrap()) as usize;
            *offset += 4;

            if *offset + len > bytes.len() {
                return Err(PolicyError::InvalidCollateral);
            }

            let data = &bytes[*offset..*offset + len];
            *offset += len;

            Ok(data)
        };

        let pck_crl_issuer_chain = read_field(&mut offset)?;
        let root_ca_crl = read_field(&mut offset)?;
        let pck_crl = read_field(&mut offset)?;
        let tcb_info_issuer_chain = read_field(&mut offset)?;
        let tcb_info = read_field(&mut offset)?;
        let qe_identity_issuer_chain = read_field(&mut offset)?;
        let qe_identity = read_field(&mut offset)?;

        Ok(Self {
            fmspc,
            major_version,
            minor_version,
            tee_type,
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            qe_identity_issuer_chain,
            qe_identity,
        })
    }
}

pub fn get_collateral_with_fmspc<'a>(
    fmspc: &[u8],
    collaterals: &'a [u8],
) -> Result<Collateral<'a>, PolicyError> {
    if fmspc.len() != 6 {
        return Err(PolicyError::InvalidParameter);
    }

    let mut offset = 0;
    while offset < collaterals.len() {
        if offset + 10 > collaterals.len() {
            return Err(PolicyError::InvalidCollateral);
        }
        let collateral_size =
            u32::from_le_bytes(collaterals[offset..offset + 4].try_into().unwrap()) as usize;

        if collateral_size < 10 || offset + collateral_size > collaterals.len() {
            return Err(PolicyError::InvalidCollateral);
        }

        if &collaterals[offset + 4..offset + 10] == fmspc {
            return Collateral::read_from_bytes(&collaterals[offset..offset + collateral_size]);
        }

        // Move to the next collateral
        offset += collateral_size;
    }

    Err(PolicyError::InvalidCollateral)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformTcb {
    tcb_info: TcbInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub tcb_evaluation_data_number: u32,
}

pub fn get_tcb_evaluation_number_from_collateral(
    collateral: &Collateral,
) -> Result<u32, PolicyError> {
    let platform_tcb = serde_json::from_slice::<PlatformTcb>(collateral.tcb_info)
        .map_err(|_| PolicyError::InvalidCollateral)?;
    Ok(platform_tcb.tcb_info.tcb_evaluation_data_number)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_get_collateral_with_fmspc() {
        let fmspc = [0x30, 0x80, 0x6F, 0x00, 0x00, 0x00];
        let collaterals = include_bytes!("../../../../config/collateral_pre_production_fmspc");

        let result = super::get_collateral_with_fmspc(&fmspc, collaterals);
        assert!(result.is_ok());
    }
}
