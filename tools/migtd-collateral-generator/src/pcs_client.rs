// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use curl::easy::Easy;
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use std::collections::HashMap;

const PCS_PROD_URL: &str = "https://api.trustedservices.intel.com/";
const PCS_SBX_URL: &str = "https://sbx.api.trustedservices.intel.com/";
const PCK_CRL_ISSUER_CHAIN: &str = "SGX-PCK-CRL-Issuer-Chain";
const QE_IDENTITY_ISSUER_CHAIN: &str = "SGX-Enclave-Identity-Issuer-Chain";
const TCB_INFO_ISSUER_CHAIN: &str = "TCB-Info-Issuer-Chain";

struct PcsRequest {
    url: String,
}

impl PcsRequest {
    fn new(for_production: bool, path: &str) -> Self {
        let base = if for_production {
            PCS_PROD_URL
        } else {
            PCS_SBX_URL
        };
        Self {
            url: format!("{}/{}", base, path),
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

pub fn fetch_pck_crl(for_production: bool) -> Result<(Vec<u8>, String)> {
    let mut req = PcsRequest::new(for_production, "sgx/certification/v4/pckcrl");
    req.add_param("ca", "platform");
    req.add_param("encoding", "pem");
    let mut pcs_response = fetch_data_from_url(req.as_str())?;
    match pcs_response.response_code {
        200 => {
            println!("Got PCK CRL");
            let issuer_chain = pcs_response
                .header_map
                .remove(PCK_CRL_ISSUER_CHAIN)
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

pub fn fetch_qe_identity(for_production: bool) -> Result<(Vec<u8>, String)> {
    let req = PcsRequest::new(for_production, "tdx/certification/v4/qe/identity");
    let mut pcs_response = fetch_data_from_url(req.as_str())?;
    match pcs_response.response_code {
        200 => {
            println!("Got enclave identity");
            let issuer_chain = pcs_response
                .header_map
                .remove(QE_IDENTITY_ISSUER_CHAIN)
                .ok_or_else(|| anyhow!("Missing PCK CRL issuer chain header"))?;
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

pub fn get_platform_tcb_list(for_production: bool) -> Result<Vec<PlatformTcbRaw>> {
    let fmspc_list = fetch_fmspc_list(for_production)?;
    let mut platform_tcb_list = Vec::new();
    for platform in get_tdx_supported_platforms(&fmspc_list) {
        let _ = fetch_platform_tcb(for_production, &platform.fmspc)?.map(|raw_tcb| {
            platform_tcb_list.push(PlatformTcbRaw {
                fmspc: platform.fmspc.clone(),
                tcb: raw_tcb.0,
                tcb_issuer_chain: raw_tcb.1,
            });
        });
    }
    Ok(platform_tcb_list)
}

pub fn fetch_platform_tcb(for_production: bool, fmspc: &str) -> Result<Option<(Vec<u8>, String)>> {
    let mut req = PcsRequest::new(for_production, "tdx/certification/v4/tcb");
    req.add_param("fmspc", fmspc);
    let mut pcs_response = fetch_data_from_url(req.as_str())?;

    let result = if pcs_response.response_code == 200 {
        println!("Got TCB info of fmspc - {}", fmspc,);
        let issuer_chain = pcs_response
            .header_map
            .remove(TCB_INFO_ISSUER_CHAIN)
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

pub fn fetch_fmspc_list(for_production: bool) -> Result<Vec<Fmspc>> {
    let req = PcsRequest::new(for_production, "sgx/certification/v4/fmspcs");
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
