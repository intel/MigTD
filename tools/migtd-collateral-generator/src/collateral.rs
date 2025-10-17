// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

use crate::pcs_client::{
    fetch_data_from_url, fetch_pck_crl, fetch_qe_identity, fetch_root_ca, get_platform_tcb_list,
    PlatformTcbRaw,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collaterals {
    major_version: u16,
    minor_version: u16,
    tee_type: u32,
    root_ca: String,
    pck_crl_issuer_chain: String,
    root_ca_crl: String,
    pck_crl: String,
    platforms: Vec<Platform>,
    qe_identity_issuer_chain: String,
    qe_identity: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    fmspc: String,
    tcb_info_issuer_chain: String,
    tcb_info: String,
}

impl Collaterals {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root_ca: Vec<u8>,
        pck_crl_issuer_chain: String,
        root_ca_crl: Vec<u8>,
        pck_crl: Vec<u8>,
        qe_identity_issuer_chain: String,
        qe_identity: Vec<u8>,
    ) -> Result<Self> {
        // Convert root_ca and root_ca_crl from DER to PEM format
        let root_ca = der_to_pem(&root_ca, "CERTIFICATE");
        let root_ca_crl = der_to_pem(&root_ca_crl, "X509 CRL");

        let pck_crl =
            String::from_utf8(pck_crl).map_err(|e| anyhow!("Invalid UTF-8 in PCK CRL: {}", e))?;
        let qe_identity = String::from_utf8(qe_identity)
            .map_err(|e| anyhow!("Invalid UTF-8 in QE identity: {}", e))?;

        Ok(Collaterals {
            major_version: 1,
            minor_version: 0,
            tee_type: 0x81,
            root_ca,
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            platforms: Vec::new(),
            qe_identity_issuer_chain,
            qe_identity,
        })
    }

    pub fn add_platform(&mut self, platform: PlatformTcbRaw) -> Result<()> {
        let platform = Platform {
            fmspc: platform.fmspc,
            tcb_info_issuer_chain: platform.tcb_issuer_chain,
            tcb_info: String::from_utf8(platform.tcb)
                .map_err(|e| anyhow!("Invalid UTF-8 in PCK CRL: {}", e))?,
        };
        self.platforms.push(platform);

        Ok(())
    }
}

pub fn get_collateral(for_production: bool) -> Result<Collaterals> {
    let (qe_identity, qe_identity_issuer_chain) = fetch_qe_identity(for_production)?;
    let root_ca_crl_url = get_root_ca_crl_url(qe_identity_issuer_chain.as_str())?;
    let root_ca_crl = fetch_data_from_url(&root_ca_crl_url)?.data;
    let root_ca = fetch_root_ca(for_production)?;
    let (pck_crl, pck_crl_issuer_chain) = fetch_pck_crl(for_production)?;
    let platform_tcb_list = get_platform_tcb_list(for_production)?;
    let mut collaterals = Collaterals::new(
        root_ca,
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        qe_identity_issuer_chain,
        qe_identity,
    )?;

    for platform_tcb in platform_tcb_list {
        collaterals.add_platform(platform_tcb)?;
    }

    Ok(collaterals)
}

fn get_root_ca_crl_url(qe_identity_issuer_chain: &str) -> Result<String> {
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

    // The second certificate in the issuer chain is root CA, get the root CA CRL URL from the
    // extension of the root CA (i.e., X509v3 CRL Distribution Points)
    let cert = certs
        .get(1)
        .ok_or_else(|| anyhow!("Issuer chain does not contain root cert"))?
        .clone();
    let urls = crl_urls_from_pem(&cert)?;

    // RFC 5280 allows multiple distribution points for redundancy, in practice the SGX root
    // certificate exposes one CRL DP:
    // ```
    // X509v3 CRL Distribution Points:
    //     Full Name:
    //         URI: <URL>
    // ```
    let url = urls
        .first()
        .ok_or_else(|| anyhow!("No CRL URL found in root cert"))?
        .to_string();

    Ok(url)
}

fn crl_urls(cert_der: &[u8]) -> Result<Vec<String>> {
    let mut urls = Vec::new();

    // Parse the X.509 certificate
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| anyhow!("Invalid DER: {:?}", e))?;

    // Look for CRL Distribution Points extension
    for ext in cert.extensions() {
        if ext.oid == x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
            // Parse the CRL Distribution Points extension
            let (_remaining, crl_dist_points) = CRLDistributionPoints::from_der(ext.value)
                .map_err(|e| anyhow!("Invalid DER: {:?}", e))?;

            // Iterate through each distribution point
            for dist_point in crl_dist_points.iter() {
                if let Some(distribution_point) = &dist_point.distribution_point {
                    match distribution_point {
                        // Full name (type 0 in C code)
                        DistributionPointName::FullName(general_names) => {
                            for general_name in general_names.iter() {
                                if let GeneralName::URI(uri) = general_name {
                                    urls.push(uri.to_string());
                                }
                            }
                        }
                        // Relative name (type 1 in C code)
                        DistributionPointName::NameRelativeToCRLIssuer(relative_name) => {
                            // Convert relative distinguished name to string
                            let rdn_string = format!("{:?}", relative_name);
                            if !rdn_string.is_empty() {
                                urls.push(rdn_string);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(urls)
}

// Extract CRL distribution point URLs from a PEM certificate
fn crl_urls_from_pem(pem_cert: &str) -> Result<Vec<String>> {
    // Parse PEM certificate
    let (_, pem) = parse_x509_pem(pem_cert.as_bytes())?;

    // Extract DER content and get CRL URLs
    crl_urls(&pem.contents)
}

// Convert DER bytes to PEM format string
fn der_to_pem(der_bytes: &[u8], label: &str) -> String {
    let base64_encoded = base64_encode(der_bytes);

    // Split into 64-character lines as per PEM standard
    let mut lines = Vec::new();
    for chunk in base64_encoded.chars().collect::<Vec<char>>().chunks(64) {
        lines.push(chunk.iter().collect::<String>());
    }

    format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----",
        label,
        lines.join("\n"),
        label
    )
}

// Base64 encoding implementation (RFC 4648)
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < input.len() {
        let b1 = input[i];
        let b2 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b3 = if i + 2 < input.len() { input[i + 2] } else { 0 };

        // Combine 3 bytes into 24-bit bitmap
        let bitmap = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

        // Extract 6-bit chunks and convert to base64 characters
        result.push(CHARS[((bitmap >> 18) & 63) as usize] as char);
        result.push(CHARS[((bitmap >> 12) & 63) as usize] as char);

        if i + 1 < input.len() {
            result.push(CHARS[((bitmap >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < input.len() {
            result.push(CHARS[(bitmap & 63) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}
