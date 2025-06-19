// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::io::Write;

use anyhow::{anyhow, Result};
use x509_parser::prelude::*;

use crate::pcs_client::{
    fetch_data_from_url, fetch_pck_crl, fetch_qe_identity, get_platform_tcb_list,
};

pub struct Collateral {
    fmspc: [u8; 6],
    size: u32, // size of the whole collateral in bytes.
    major_version: u16,
    minor_version: u16,
    tee_type: u32,
    pck_crl_issuer_chain: Vec<u8>,
    root_ca_crl: Vec<u8>,
    pck_crl: Vec<u8>,
    tcb_info_issuer_chain: Vec<u8>,
    tcb_info: Vec<u8>,
    qe_identity_issuer_chain: Vec<u8>,
    qe_identity: Vec<u8>,
}

impl Collateral {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fmspc: String,
        pck_crl_issuer_chain: Vec<u8>,
        root_ca_crl: Vec<u8>,
        pck_crl: Vec<u8>,
        tcb_info_issuer_chain: Vec<u8>,
        tcb_info: Vec<u8>,
        qe_identity_issuer_chain: Vec<u8>,
        qe_identity: Vec<u8>,
    ) -> Result<Self> {
        let size = (6 // fmspc
            + 4 // size
            + 2 // major_version
            + 2 // minor_version
            + 4 // tee_type
            + pck_crl_issuer_chain.len()
            + root_ca_crl.len()
            + pck_crl.len()
            + tcb_info_issuer_chain.len()
            + tcb_info.len()
            + qe_identity_issuer_chain.len()
            + qe_identity.len()) as u32;

        Ok(Collateral {
            fmspc: fmspc_str_to_bytes(&fmspc)?,
            size,
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

    pub fn tcb_info(&self) -> &[u8] {
        &self.tcb_info
    }

    pub fn write_to_writer<W: Write>(&self, mut writer: W) -> Result<()> {
        writer.write_all(&self.size.to_le_bytes())?;
        writer.write_all(&self.fmspc)?;
        writer.write_all(&self.major_version.to_le_bytes())?;
        writer.write_all(&self.minor_version.to_le_bytes())?;
        writer.write_all(&self.tee_type.to_le_bytes())?;
        writer.write_all(&self.pck_crl_issuer_chain.len().to_le_bytes())?;
        writer.write_all(&self.pck_crl_issuer_chain)?;
        writer.write_all(&self.root_ca_crl.len().to_le_bytes())?;
        writer.write_all(&self.root_ca_crl)?;
        writer.write_all(&self.pck_crl.len().to_le_bytes())?;
        writer.write_all(&self.pck_crl)?;
        writer.write_all(&self.tcb_info_issuer_chain.len().to_le_bytes())?;
        writer.write_all(&self.tcb_info_issuer_chain)?;
        writer.write_all(&self.tcb_info.len().to_le_bytes())?;
        writer.write_all(&self.tcb_info)?;
        writer.write_all(&self.qe_identity_issuer_chain.len().to_le_bytes())?;
        writer.write_all(&self.qe_identity_issuer_chain)?;
        writer.write_all(&self.qe_identity.len().to_le_bytes())?;
        writer.write_all(&self.qe_identity)?;
        Ok(())
    }
}

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

pub fn get_collateral(for_production: bool) -> Result<Vec<Collateral>> {
    let mut collaterals = Vec::new();
    let qe_identity = fetch_qe_identity(true)?;
    let pck_crl = fetch_pck_crl(for_production)?;
    let platform_tcb_list = get_platform_tcb_list(for_production)?;
    let root_ca_crl_url = get_root_ca_crl(qe_identity.1.as_str())?;
    let root_ca_crl = fetch_data_from_url(&root_ca_crl_url)?.data;

    for platform_tcb in platform_tcb_list {
        collaterals.push(Collateral::new(
            platform_tcb.fmspc,
            pck_crl.1.as_bytes().to_vec(),
            root_ca_crl.clone(),
            pck_crl.0.clone(),
            platform_tcb.tcb_issuer_chain.as_bytes().to_vec(),
            platform_tcb.tcb,
            qe_identity.1.as_bytes().to_vec(),
            qe_identity.0.clone(),
        )?);
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
