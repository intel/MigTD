// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use curl::easy::Easy;
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use std::collections::HashMap;

const PCK_CRL_ISSUER_CHAIN: &str = "SGX-PCK-CRL-Issuer-Chain";
const QE_IDENTITY_ISSUER_CHAIN: &str = "SGX-Enclave-Identity-Issuer-Chain";
const TCB_INFO_ISSUER_CHAIN: &str = "TCB-Info-Issuer-Chain";

struct PcsRequest {
    url: String,
}

impl PcsRequest {
    fn new(base_url: &str, path: &str) -> Self {
        Self {
            url: format!("{}/{}", base_url, path),
        }
    }

    fn add_param(&mut self, key: &str, value: &str) {
        if self.url.contains('?') {
            self.url.push('&');
        } else {
            self.url.push('?');
        }
        self.url.push_str(&format!("{}={}", key, value));
    }

    fn as_str(&self) -> &str {
        &self.url
    }
}

pub fn fetch_pck_crl(config: &dyn crate::PcsConfig) -> Result<(Vec<u8>, String)> {
    let base_url = config.get_base_url_pck_crl();
    let mut req = PcsRequest::new(&base_url, "sgx/certification/v4/pckcrl");
    req.add_param("ca", "platform");
    // Intel returns PEM encoded data by default. THIM only supports DER encoding.
    // Request DER format for max compatibility and conversion is done later if needed.
    req.add_param("encoding", "der");
    let mut pcs_response = fetch_data_from_url(req.as_str())?;
    match pcs_response.response_code {
        200 => {
            println!("Got PCK CRL");
            let issuer_chain =
                remove_header_case_insensitive(&mut pcs_response.header_map, PCK_CRL_ISSUER_CHAIN)
                    .ok_or_else(|| anyhow!("Missing PCK CRL issuer chain header"))?;
            Ok((
                pcs_response.data,
                percent_decode_str(&issuer_chain).decode_utf8()?.to_string(),
            ))
        }
        _ => {
            eprintln!("Error fetching PCK CRL - {:?}", pcs_response.response_code);
            Err(anyhow!("AccessException"))
        }
    }
}

pub fn fetch_root_ca(config: &dyn crate::PcsConfig) -> Result<Vec<u8>> {
    let url = config.get_root_ca_url();

    let pcs_response = fetch_data_from_url(url)?;
    match pcs_response.response_code {
        200 => Ok(pcs_response.data),
        _ => {
            eprintln!("Error fetching root CA - {:?}", pcs_response.response_code);
            Err(anyhow!("AccessException"))
        }
    }
}

pub fn fetch_root_ca_crl(root_ca_url: &str) -> Result<Vec<u8>> {
    let pcs_response = fetch_data_from_url(root_ca_url)?;
    match pcs_response.response_code {
        200 => Ok(pcs_response.data),
        _ => {
            eprintln!(
                "Error fetching root CA CRL - {:?}",
                pcs_response.response_code
            );
            Err(anyhow!("AccessException"))
        }
    }
}

pub fn fetch_qe_identity(config: &dyn crate::PcsConfig) -> Result<(Vec<u8>, String)> {
    let base_url = config.get_base_url();

    let req = PcsRequest::new(&base_url, "tdx/certification/v4/qe/identity");
    let mut pcs_response = fetch_data_from_url(req.as_str())?;
    match pcs_response.response_code {
        200 => {
            println!("Got enclave identity");
            let issuer_chain = remove_header_case_insensitive(
                &mut pcs_response.header_map,
                QE_IDENTITY_ISSUER_CHAIN,
            )
            .ok_or_else(|| anyhow!("Missing QE identity issuer chain header"))?;
            Ok((
                pcs_response.data,
                percent_decode_str(&issuer_chain).decode_utf8()?.to_string(),
            ))
        }
        _ => {
            eprintln!(
                "Error fetching enclave identity - {:?}",
                pcs_response.response_code
            );
            Err(anyhow!("AccessException"))
        }
    }
}

pub struct PlatformTcbRaw {
    pub fmspc: String,
    pub tcb: Vec<u8>,
    pub tcb_issuer_chain: String,
}

pub fn get_platform_tcb_list(config: &dyn crate::PcsConfig) -> Result<Vec<PlatformTcbRaw>> {
    // Always fetch FMSPC list from Intel PCS (THIM doesn't cache it)
    let fmspc_list = fetch_fmspc_list(config)?;

    let mut platform_tcb_list = Vec::new();
    for platform in get_tdx_supported_platforms(&fmspc_list) {
        if let Some(raw_tcb) = fetch_platform_tcb(config, &platform.fmspc)? {
            platform_tcb_list.push(PlatformTcbRaw {
                fmspc: platform.fmspc.clone(),
                tcb: raw_tcb.0,
                tcb_issuer_chain: raw_tcb.1,
            });
        }
    }
    Ok(platform_tcb_list)
}

pub fn fetch_platform_tcb(
    config: &dyn crate::PcsConfig,
    fmspc: &str,
) -> Result<Option<(Vec<u8>, String)>> {
    let base_url = config.get_base_url();

    let mut req = PcsRequest::new(&base_url, "tdx/certification/v4/tcb");
    req.add_param("fmspc", fmspc);
    let mut pcs_response = fetch_data_from_url(req.as_str())?;

    let result = if pcs_response.response_code == 200 {
        println!("Got TCB info of fmspc - {}", fmspc,);
        let issuer_chain =
            remove_header_case_insensitive(&mut pcs_response.header_map, TCB_INFO_ISSUER_CHAIN)
                .ok_or_else(|| anyhow!("Missing TCB info issuer chain header"))?;
        Some((
            pcs_response.data,
            percent_decode_str(&issuer_chain).decode_utf8()?.to_string(),
        ))
    } else if pcs_response.response_code == 404 {
        // Ignore 404 errors
        None
    } else {
        eprintln!(
            "Error fetching details for fmspc {}: {:?}",
            fmspc, pcs_response.response_code
        );
        None
    };

    Ok(result)
}

pub struct PcsResponse {
    pub response_code: u32,
    pub header_map: HashMap<String, String>,
    pub data: Vec<u8>,
}

pub fn fetch_data_from_url(url: &str) -> Result<PcsResponse> {
    let mut handle = Easy::new();
    let mut data = Vec::new();
    let mut http_header = Vec::new();

    handle.url(url)?;
    {
        let mut transfer = handle.transfer();
        transfer.header_function(|header_bytes| {
            http_header.extend_from_slice(header_bytes);
            true
        })?;
        transfer.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }

    Ok(PcsResponse {
        response_code: handle.response_code()?,
        header_map: parse_http_headers(http_header)?,
        data,
    })
}

// Converts raw HTTP header bytes to a key-value map.
fn parse_http_headers(header_bytes: Vec<u8>) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();
    let header_str = String::from_utf8(header_bytes)?;

    for line in header_str.lines() {
        if let Some((key, value)) = line.split_once(": ") {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Ok(headers)
}

/// Remove a header from the header map using case-insensitive comparison
/// Returns the value if found, None otherwise
fn remove_header_case_insensitive(
    headers: &mut HashMap<String, String>,
    target_key: &str,
) -> Option<String> {
    // Find the actual key that matches case-insensitively
    let actual_key = headers
        .keys()
        .find(|key| key.to_lowercase() == target_key.to_lowercase())
        .cloned();

    // Remove using the actual key if found
    actual_key.and_then(|key| headers.remove(&key))
}

pub fn fetch_fmspc_list(config: &dyn crate::PcsConfig) -> Result<Vec<Fmspc>> {
    let base_url = config.get_base_url_fmspc_list();
    let req = PcsRequest::new(&base_url, "sgx/certification/v4/fmspcs");
    let pcs_response = fetch_data_from_url(req.as_str())?;
    match pcs_response.response_code {
        200 => Ok(serde_json::from_slice::<Vec<Fmspc>>(&pcs_response.data)?),
        _ => {
            eprintln!(
                "Error fetching fmspc list - {:?}",
                pcs_response.response_code
            );
            Err(anyhow!("AccessException"))
        }
    }
}

pub fn get_tdx_supported_platforms(list: &[Fmspc]) -> Vec<&Fmspc> {
    list.iter().filter(|p| p.is_tdx_supported()).collect()
}

#[derive(Debug, Deserialize)]
pub struct Fmspc {
    pub fmspc: String,
    platform: String,
}

impl Fmspc {
    pub fn is_tdx_supported(&self) -> bool {
        // only E5 support TDX at this moment.
        self.platform.as_str() == "E5"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_insensitive_header_removal() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert(
            "sgx-pck-crl-issuer-chain".to_string(),
            "test-value".to_string(),
        );
        headers.insert("Authorization".to_string(), "Bearer token".to_string());

        // Test removing with different case
        let result = remove_header_case_insensitive(&mut headers, "SGX-PCK-CRL-ISSUER-CHAIN");
        assert_eq!(result, Some("test-value".to_string()));

        // Verify the header was actually removed
        assert!(!headers.contains_key("sgx-pck-crl-issuer-chain"));

        // Test non-existent header
        let result = remove_header_case_insensitive(&mut headers, "Non-Existent-Header");
        assert_eq!(result, None);

        // Verify other headers are still there
        assert_eq!(
            headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(
            headers.get("Authorization"),
            Some(&"Bearer token".to_string())
        );
    }
}
