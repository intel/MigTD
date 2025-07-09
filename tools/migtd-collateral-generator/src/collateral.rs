// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

use crate::pcs_client::{
    fetch_data_from_url, fetch_pck_crl, fetch_qe_identity, get_platform_tcb_list,
};

pub type Collaterals = HashMap<String, Collateral>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Collateral {
    major_version: u16,
    minor_version: u16,
    tee_type: u32,
    pck_crl_issuer_chain: String,
    root_ca_crl: String,
    pck_crl: String,
    tcb_info_issuer_chain: String,
    tcb_info: String,
    qe_identity_issuer_chain: String,
    qe_identity: String,
}

impl Collateral {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pck_crl_issuer_chain: String,
        root_ca_crl: Vec<u8>,
        pck_crl: Vec<u8>,
        tcb_info_issuer_chain: String,
        tcb_info: Vec<u8>,
        qe_identity_issuer_chain: String,
        qe_identity: Vec<u8>,
    ) -> Result<Self> {
        let root_ca_crl = String::from_utf8(root_ca_crl)
            .unwrap_or_else(|_| "Invalid UTF-8 in root CA CRL".to_string());
        let pck_crl =
            String::from_utf8(pck_crl).unwrap_or_else(|_| "Invalid UTF-8 in PCK CRL".to_string());
        let tcb_info =
            String::from_utf8(tcb_info).unwrap_or_else(|_| "Invalid UTF-8 in TCB info".to_string());
        let qe_identity = String::from_utf8(qe_identity)
            .unwrap_or_else(|_| "Invalid UTF-8 in TCB info".to_string());

        Ok(Collateral {
            major_version: 1,
            minor_version: 0,
            tee_type: 1,
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            qe_identity_issuer_chain,
            qe_identity,
        })
    }

    pub fn tcb_info(&self) -> &str {
        &self.tcb_info
    }
}

#[allow(unused)]
fn fmspc_str_to_bytes(fmspc: &str) -> Result<[u8; 6]> {
    if fmspc.len() != 12 {
        return Err(anyhow!("FMSPC string must be 12 hex characters"));
    }
    let mut bytes = [0u8; 6];
    for i in 0..6 {
        let byte_str = &fmspc[2 * i..2 * i + 2];
        bytes[i] =
            u8::from_str_radix(byte_str, 16).map_err(|e| anyhow!("Invalid hex in FMSPC: {}", e))?;
    }
    Ok(bytes)
}

pub fn get_collateral(for_production: bool) -> Result<Collaterals> {
    let mut collaterals = HashMap::new();
    let (qe_identity, qe_identity_issuer_chain) = fetch_qe_identity(true)?;
    let (pck_crl, pck_crl_issuer_chain) = fetch_pck_crl(for_production)?;
    let platform_tcb_list = get_platform_tcb_list(for_production)?;
    let root_ca_crl_url = get_root_ca_crl(qe_identity_issuer_chain.as_str())?;
    let root_ca_crl = fetch_data_from_url(&root_ca_crl_url)?.data;

    for platform_tcb in platform_tcb_list {
        collaterals.insert(
            platform_tcb.fmspc,
            Collateral::new(
                pck_crl_issuer_chain.clone(),
                root_ca_crl.clone(),
                pck_crl.clone(),
                platform_tcb.tcb_issuer_chain,
                platform_tcb.tcb,
                qe_identity_issuer_chain.clone(),
                qe_identity.clone(),
            )?,
        );
    }

    Ok(collaterals)
}

fn get_root_ca_crl(qe_identity_issuer_chain: &str) -> Result<String> {
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    // find the root certificate in the issuer chain
    let mut certs = Vec::new();
    let mut start = 0;
    while let Some(begin) = qe_identity_issuer_chain[start..].find(begin_marker) {
        let begin = start + begin;
        if let Some(end) = qe_identity_issuer_chain[begin..].find(end_marker) {
            let end = begin + end + end_marker.len();
            let cert = &qe_identity_issuer_chain[begin..end];
            certs.push(cert.trim().to_string());
            start = end;
        } else {
            break;
        }
    }
    let cert = certs
        .get(1)
        .ok_or_else(|| anyhow!("Issuer chain does not contain root cert"))?
        .clone();

    // Extract CRL URL(s) from the second certificate
    let urls = get_crl_urls_from_pem_cert(&cert)?;

    let url = urls
        .first()
        .ok_or_else(|| anyhow!("No CRL URL found in root cert"))?
        .to_string();

    Ok(url)
}

fn get_crl_urls_from_pem_cert(pem_cert: &str) -> Result<Vec<String>> {
    // Parse PEM to DER
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_cert.as_bytes())
        .map_err(|e| anyhow!("Invalid PEM: {:?}", e))?;
    // Parse DER to X509Certificate
    let (_, cert) =
        X509Certificate::from_der(&pem.contents).map_err(|e| anyhow!("Invalid DER: {:?}", e))?;

    // Extract CRL Distribution Points
    let urls = cert
        .extensions()
        .iter()
        .filter_map(|ext| {
            if let ParsedExtension::CRLDistributionPoints(points) = &ext.parsed_extension() {
                Some(points)
            } else {
                None
            }
        })
        .flat_map(|points| points.iter())
        .flat_map(|point| {
            point
                .distribution_point
                .as_ref()
                .and_then(|name| match name {
                    DistributionPointName::FullName(names) => Some(
                        names
                            .iter()
                            .filter_map(|gn| {
                                if let GeneralName::URI(uri) = gn {
                                    Some(uri.to_string())
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>(),
                    ),
                    _ => None,
                })
                .unwrap_or_default()
        })
        .collect();

    Ok(urls)
}
