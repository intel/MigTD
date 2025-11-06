// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "attest-lib-ext")]
use crate::binding::verify_quote_integrity_ex;
use crate::{
    binding::{init_heap, verify_quote_integrity, AttestLibError, QveCollateral},
    root_ca::ROOT_CA_PUBLIC_KEY,
    Error, TD_VERIFIED_REPORT_SIZE,
};
use alloc::{ffi::CString, vec, vec::Vec};
use core::{alloc::Layout, ffi::c_void, ops::Range};

use crate::ghci::ghci_get_quote;

const TD_QUOTE_SIZE: usize = 0x2000;
const TD_REPORT_VERIFY_SIZE: usize = 1024;
const ATTEST_HEAP_SIZE: usize = 0x80000;

// TDX GHCI GetQuote status codes
const GET_QUOTE_SUCCESS: u64 = 0x0;
const GET_QUOTE_IN_FLIGHT: u64 = 0xFFFFFFFF_FFFFFFFF;
const GET_QUOTE_ERROR: u64 = 0x80000000_00000000;
const GET_QUOTE_SERVICE_UNAVAILABLE: u64 = 0x80000000_00000001;

#[repr(C)]
#[allow(dead_code)]
struct ServtdTdxQuoteHdr {
    /* Quote version, filled by TD */
    version: u64,
    /* Status code of Quote request, filled by VMM */
    status: u64,
    /* Length of TDREPORT, filled by TD */
    in_len: u32,
    /* Length of Quote, filled by VMM */
    out_len: u32,
    /* Actual Quote data or TDREPORT on input */
    data: [u8; 0],
}

/// C-compatible version of Collateral with null-terminated strings
#[derive(Debug)]
pub struct Collateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: CString,
    pub root_ca_crl: CString,
    pub pck_crl: CString,
    pub tcb_info_issuer_chain: CString,
    pub tcb_info: CString,
    pub qe_identity_issuer_chain: CString,
    pub qe_identity: CString,
}

impl From<&Collateral> for QveCollateral {
    fn from(val: &Collateral) -> Self {
        QveCollateral {
            major_version: val.major_version,
            minor_version: val.minor_version,
            tee_type: val.tee_type,
            pck_crl_issuer_chain: val.pck_crl_issuer_chain.as_ptr(),
            pck_crl_issuer_chain_size: val.pck_crl_issuer_chain.as_bytes_with_nul().len() as u32,
            root_ca_crl: val.root_ca_crl.as_ptr(),
            root_ca_crl_size: val.root_ca_crl.as_bytes_with_nul().len() as u32,
            pck_crl: val.pck_crl.as_ptr(),
            pck_crl_size: val.pck_crl.as_bytes_with_nul().len() as u32,
            tcb_info_issuer_chain: val.tcb_info_issuer_chain.as_ptr(),
            tcb_info_issuer_chain_size: val.tcb_info_issuer_chain.as_bytes_with_nul().len() as u32,
            tcb_info: val.tcb_info.as_ptr(),
            tcb_info_size: val.tcb_info.as_bytes_with_nul().len() as u32,
            qe_identity_issuer_chain: val.qe_identity_issuer_chain.as_ptr(),
            qe_identity_issuer_chain_size: val.qe_identity_issuer_chain.as_bytes_with_nul().len()
                as u32,
            qe_identity: val.qe_identity.as_ptr(),
            qe_identity_size: val.qe_identity.as_bytes_with_nul().len() as u32,
        }
    }
}

pub fn attest_init_heap() -> Option<usize> {
    unsafe {
        let heap_base =
            alloc::alloc::alloc_zeroed(Layout::from_size_align(ATTEST_HEAP_SIZE, 0x1000).ok()?);

        init_heap(heap_base as *mut c_void, ATTEST_HEAP_SIZE as u32);
    }

    Some(ATTEST_HEAP_SIZE)
}

pub fn get_quote(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    // Create a GetQuote buffer following TDX GHCI format
    // Header is 20 bytes (version:u64 + status:u64 + in_len:u32 + out_len:u32)
    let tdreport_length = td_report.len();
    let header_size = core::mem::size_of::<ServtdTdxQuoteHdr>();
    let buffer_size = header_size + tdreport_length + TD_QUOTE_SIZE; // Header + TDReport + space for quote
    let mut buffer = vec![0u8; buffer_size];

    // Fill GetQuote buffer header using the struct
    let hdr = ServtdTdxQuoteHdr {
        version: 1,
        status: 0,
        in_len: td_report.len() as u32,
        out_len: TD_QUOTE_SIZE as u32,
        data: [],
    };

    let header_size = core::mem::size_of::<ServtdTdxQuoteHdr>();
    let hdr_bytes =
        unsafe { core::slice::from_raw_parts(&hdr as *const _ as *const u8, header_size) };
    buffer[..header_size].copy_from_slice(hdr_bytes);

    // Copy TDREPORT data immediately after header (offset 20)
    buffer[header_size..header_size + tdreport_length].copy_from_slice(td_report);

    // Call ghci_get_quote
    let result = ghci_get_quote(buffer.as_mut_ptr() as *mut c_void, buffer.len() as u64);
    if result != AttestLibError::Success as i32 {
        return Err(Error::GetQuote);
    }

    // Read header response
    let buffer_ptr = buffer.as_ptr() as *const ServtdTdxQuoteHdr;
    let (status, quote_length) = unsafe {
        let hdr = &*buffer_ptr;
        (hdr.status, hdr.out_len as usize)
    };

    if status != GET_QUOTE_SUCCESS {
        return Err(Error::GetQuote);
    }

    if quote_length > TD_QUOTE_SIZE {
        return Err(Error::GetQuote);
    }

    // Extract quote data
    let quote_start = header_size + tdreport_length;
    if buffer.len() < quote_start + quote_length {
        return Err(Error::GetQuote);
    }

    let quote = buffer[quote_start..quote_start + quote_length].to_vec();
    Ok(quote)
}
pub fn verify_quote(quote: &[u8]) -> Result<Vec<u8>, Error> {
    let mut td_report_verify = vec![0u8; TD_REPORT_VERIFY_SIZE];
    let mut report_verify_size = TD_REPORT_VERIFY_SIZE as u32;

    // Safety:
    // ROOT_CA must have been set and checked at this moment.
    let public_key = ROOT_CA_PUBLIC_KEY.get().unwrap().as_slice();

    unsafe {
        let result = verify_quote_integrity(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            public_key.as_ptr() as *const c_void,
            public_key.len() as u32,
            td_report_verify.as_mut_ptr() as *mut c_void,
            &mut report_verify_size as *mut u32,
        );
        if result != AttestLibError::Success {
            return Err(Error::VerifyQuote);
        }
    }

    if report_verify_size as usize != TD_VERIFIED_REPORT_SIZE {
        return Err(Error::InvalidOutput);
    }

    mask_verified_report_values(&mut td_report_verify[..report_verify_size as usize]);
    Ok(td_report_verify[..report_verify_size as usize].to_vec())
}

#[cfg(feature = "attest-lib-ext")]
pub fn verify_quote_with_collaterals(
    quote: &[u8],
    collateral: Collateral,
) -> Result<Vec<u8>, Error> {
    let mut td_report_verify = vec![0u8; TD_REPORT_VERIFY_SIZE];
    let mut report_verify_size = TD_REPORT_VERIFY_SIZE as u32;

    // Safety:
    // ROOT_CA must have been set and checked at this moment.
    let public_key = ROOT_CA_PUBLIC_KEY.get().unwrap().as_slice();

    let qve_collateral: QveCollateral = (&collateral).into();
    unsafe {
        let result = verify_quote_integrity_ex(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            public_key.as_ptr() as *const c_void,
            public_key.len() as u32,
            &qve_collateral as *const QveCollateral,
            td_report_verify.as_mut_ptr() as *mut c_void,
            &mut report_verify_size as *mut u32,
        );
        if result != AttestLibError::Success {
            return Err(Error::VerifyQuote);
        }
    }

    mask_verified_report_values(&mut td_report_verify[..report_verify_size as usize]);
    Ok(td_report_verify[..report_verify_size as usize].to_vec())
}

fn mask_verified_report_values(report: &mut [u8]) {
    const R_MISC_SELECT: Range<usize> = 626..630;
    const R_MISC_SELECT_MASK: Range<usize> = 630..634;
    const R_ATTRIBUTES: Range<usize> = 634..650;
    const R_ATTRIBUTES_MASK: Range<usize> = 650..666;

    for (i, j) in R_MISC_SELECT.zip(R_MISC_SELECT_MASK) {
        report[i] &= report[j]
    }
    for (i, j) in R_ATTRIBUTES.zip(R_ATTRIBUTES_MASK) {
        report[i] &= report[j]
    }
}
