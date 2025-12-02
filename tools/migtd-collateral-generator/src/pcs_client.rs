// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use futures::future::try_join_all;
use percent_encoding::percent_decode_str;
use reqwest::Client;
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

pub async fn fetch_pck_crl(config: &dyn crate::PcsConfig) -> Result<(Vec<u8>, String)> {
    let base_url = config.get_base_url_pck_crl();
    let mut req = PcsRequest::new(&base_url, "sgx/certification/v4/pckcrl");
    req.add_param("ca", "platform");
    // Intel returns PEM encoded data by default. THIM only supports DER encoding.
    // Request DER format for max compatibility and conversion is done later if needed.
    req.add_param("encoding", "der");
    let mut pcs_response = fetch_data_from_url(req.as_str()).await?;
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

pub async fn fetch_root_ca(config: &dyn crate::PcsConfig) -> Result<Vec<u8>> {
    let url = config.get_root_ca_url();

    let pcs_response = fetch_data_from_url(url).await?;
    match pcs_response.response_code {
        200 => Ok(pcs_response.data),
        _ => {
            eprintln!("Error fetching root CA - {:?}", pcs_response.response_code);
            Err(anyhow!("AccessException"))
        }
    }
}

pub async fn fetch_root_ca_crl(root_ca_url: &str) -> Result<Vec<u8>> {
    let pcs_response = fetch_data_from_url(root_ca_url).await?;
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

pub async fn fetch_qe_identity(config: &dyn crate::PcsConfig) -> Result<(Vec<u8>, String)> {
    let base_url = config.get_base_url();

    let req = PcsRequest::new(&base_url, "tdx/certification/v4/qe/identity");
    let mut pcs_response = fetch_data_from_url(req.as_str()).await?;
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
pub async fn get_platform_tcb_list(config: &dyn crate::PcsConfig) -> Result<Vec<PlatformTcbRaw>> {
    // Always fetch FMSPC list from Intel PCS (THIM doesn't cache it)
    let fmspc_list = fetch_fmspc_list(config).await?;

    let tasks = get_tdx_supported_platforms(&fmspc_list)
        .into_iter()
        .map(|platform| {
            let fmspc = platform.fmspc.clone();
            async move {
                fetch_platform_tcb(config, &fmspc).await.map(|opt| {
                    opt.map(|(tcb, tcb_issuer_chain)| PlatformTcbRaw {
                        fmspc,
                        tcb,
                        tcb_issuer_chain,
                    })
                })
            }
        });

    let results = try_join_all(tasks).await?;
    Ok(results.into_iter().filter_map(|entry| entry).collect())
}

pub async fn fetch_platform_tcb(
    config: &dyn crate::PcsConfig,
    fmspc: &str,
) -> Result<Option<(Vec<u8>, String)>> {
    let base_url = config.get_base_url();

    let mut req = PcsRequest::new(&base_url, "tdx/certification/v4/tcb");
    req.add_param("fmspc", fmspc);
    let mut pcs_response = fetch_data_from_url(req.as_str()).await?;

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

pub async fn fetch_data_from_url(url: &str) -> Result<PcsResponse> {
    let client = Client::new();
    let response = client.get(url).send().await?;
    let status = response.status().as_u16() as u32;

    let mut header_map = HashMap::new();
    for (key, value) in response.headers() {
        header_map.insert(
            key.as_str().to_string(),
            value
                .to_str()
                .map_err(|_| anyhow!("Error parsing http header"))?
                .to_string(),
        );
    }

    let data = response.bytes().await?.to_vec();

    Ok(PcsResponse {
        response_code: status,
        header_map,
        data,
    })
}

pub async fn fetch_fmspc_list(config: &dyn crate::PcsConfig) -> Result<Vec<Fmspc>> {
    let base_url = config.get_base_url_fmspc_list();
    let req = PcsRequest::new(&base_url, "sgx/certification/v4/fmspcs");
    let pcs_response = fetch_data_from_url(req.as_str()).await?;
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

    /// Test to check what headers Azure THIM actually returns
    /// This will help us verify the correct header names for THIM vs Intel PCS
    ///
    /// Run with: cargo test test_thim_headers -- --nocapture
    /// Set AZURE_REGION environment variable or it defaults to "useast"
    /// Ignored in CI because it requires network access to Azure THIM.
    #[tokio::test]
    #[ignore]
    async fn test_thim_headers() {
        // Get region from environment variable, default to "useast"
        let region = std::env::var("AZURE_REGION").unwrap_or_else(|_| "useast".to_string());

        println!("=== Testing Azure THIM headers for region: {} ===", region);
        println!("💡 Tip: Set AZURE_REGION environment variable to test different regions");

        // Test PCK CRL endpoint with both v3 and v4
        let base_url = format!("https://{}.thim.azure.net", region);

        let mut req_v4 = PcsRequest::new(&base_url, "sgx/certification/v4/pckcrl");
        req_v4.add_param("ca", "platform");
        println!("\nTesting PCK CRL endpoint v4: {}", req_v4.as_str());
        match fetch_data_from_url(req_v4.as_str()).await {
            Ok(response) => {
                println!("PCK CRL v4 Response code: {}", response.response_code);
                assert_eq!(
                    response.response_code, 200,
                    "PCK CRL v4 should return 200 OK"
                );

                println!("✅ v4 works for PCK CRL");
                println!("PCK CRL v4 Headers:");

                let mut found_issuer_chain = false;
                for (key, value) in &response.header_map {
                    if key.to_lowercase().contains("issuer") || key.to_lowercase().contains("chain")
                    {
                        println!("  {}: {}", key, value);
                        if key.to_lowercase() == "sgx-pck-crl-issuer-chain" {
                            found_issuer_chain = true;
                            assert!(
                                !value.is_empty(),
                                "PCK CRL issuer chain should not be empty"
                            );
                        }
                    }
                }
                assert!(
                    found_issuer_chain,
                    "PCK CRL response should contain sgx-pck-crl-issuer-chain header"
                );
            }
            Err(e) => panic!("PCK CRL v4 request failed: {}", e),
        }

        // Test QE Identity endpoint
        let req = PcsRequest::new(&base_url, "tdx/certification/v4/qe/identity");
        println!("\nTesting QE Identity endpoint: {}", req.as_str());
        match fetch_data_from_url(req.as_str()).await {
            Ok(response) => {
                println!("QE Identity Response code: {}", response.response_code);
                assert_eq!(
                    response.response_code, 200,
                    "QE Identity should return 200 OK"
                );

                println!("QE Identity Headers:");
                let mut found_issuer_chain = false;
                for (key, value) in &response.header_map {
                    if key.to_lowercase().contains("issuer") || key.to_lowercase().contains("chain")
                    {
                        println!("  {}: {}", key, value);
                        if key.to_lowercase() == "sgx-enclave-identity-issuer-chain" {
                            found_issuer_chain = true;
                            assert!(
                                !value.is_empty(),
                                "QE Identity issuer chain should not be empty"
                            );
                        }
                    }
                }
                assert!(
                    found_issuer_chain,
                    "QE Identity response should contain sgx-enclave-identity-issuer-chain header"
                );
            }
            Err(e) => panic!("QE Identity request failed: {}", e),
        }

        // Test TCB info endpoint with a known FMSPC
        let mut req = PcsRequest::new(&base_url, "tdx/certification/v4/tcb");
        req.add_param("fmspc", "90C06F000000"); // Common E5 FMSPC
        println!("\nTesting TCB Info endpoint: {}", req.as_str());
        match fetch_data_from_url(req.as_str()).await {
            Ok(response) => {
                println!("TCB Info Response code: {}", response.response_code);
                // TCB Info might return 404 for some FMSPCs, so we'll allow both 200 and 404
                assert!(
                    response.response_code == 200 || response.response_code == 404,
                    "TCB Info should return 200 OK or 404 Not Found, got: {}",
                    response.response_code
                );

                if response.response_code == 200 {
                    println!("TCB Info Headers:");
                    let mut found_issuer_chain = false;
                    for (key, value) in &response.header_map {
                        if key.to_lowercase().contains("issuer")
                            || key.to_lowercase().contains("chain")
                        {
                            println!("  {}: {}", key, value);
                            if key.to_lowercase() == "tcb-info-issuer-chain" {
                                found_issuer_chain = true;
                                assert!(
                                    !value.is_empty(),
                                    "TCB Info issuer chain should not be empty"
                                );
                            }
                        }
                    }
                    assert!(
                        found_issuer_chain,
                        "TCB Info 200 response should contain tcb-info-issuer-chain header"
                    );
                } else {
                    println!("TCB Info returned 404 (expected for some FMSPCs)");
                }
            }
            Err(e) => panic!("TCB Info request failed: {}", e),
        }

        println!("✅ All THIM header tests passed!");
    }

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
