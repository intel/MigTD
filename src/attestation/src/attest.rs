// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{
    binding::{
        get_quote as get_quote_inner, init_heap, verify_quote_integrity, AttestLibError,
        TeeQuoteCollateral,
    },
    root_ca::ROOT_CA,
    Error, TD_VERIFIED_REPORT_SIZE,
};
use alloc::{vec, vec::Vec};
use core::{alloc::Layout, ffi::c_void, ops::Range, ptr::null};
use policy::v2::collateral::Collateral;
use tdx_tdcall::tdreport::*;

const TD_QUOTE_SIZE: usize = 0x2000;
const TD_REPORT_VERIFY_SIZE: usize = 1024;
const ATTEST_HEAP_SIZE: usize = 0x80000;

pub fn attest_init_heap() -> Option<usize> {
    unsafe {
        let heap_base =
            alloc::alloc::alloc_zeroed(Layout::from_size_align(ATTEST_HEAP_SIZE, 0x1000).ok()?);

        init_heap(heap_base as *mut c_void, ATTEST_HEAP_SIZE as u32);
    }

    Some(ATTEST_HEAP_SIZE)
}

pub fn get_quote(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    let mut quote = vec![0u8; TD_QUOTE_SIZE];
    let mut quote_size = TD_QUOTE_SIZE as u32;
    unsafe {
        let result = get_quote_inner(
            td_report.as_ptr() as *const c_void,
            TD_REPORT_SIZE as u32,
            quote.as_mut_ptr() as *mut c_void,
            &mut quote_size as *mut u32,
        );
        if result != AttestLibError::Success {
            return Err(Error::GetQuote);
        }
    }
    quote.truncate(quote_size as usize);
    Ok(quote)
}

pub fn verify_quote(quote: &[u8]) -> Result<Vec<u8>, Error> {
    let mut td_report_verify = vec![0u8; TD_REPORT_VERIFY_SIZE];
    let mut report_verify_size = TD_REPORT_VERIFY_SIZE as u32;

    // Safety:
    // ROOT_CA must have been set and checked at this moment.
    let public_key = ROOT_CA
        .get()
        .unwrap()
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap();

    unsafe {
        let result = verify_quote_integrity(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            null(),
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

pub fn verify_quote_with_collaterals(
    quote: &[u8],
    collateral: &Collateral<'static>,
) -> Result<Vec<u8>, Error> {
    let mut td_report_verify = vec![0u8; TD_REPORT_VERIFY_SIZE];
    let mut report_verify_size = TD_REPORT_VERIFY_SIZE as u32;

    // Safety:
    // ROOT_CA must have been set and checked at this moment.
    let public_key = ROOT_CA
        .get()
        .unwrap()
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap();

    let collateral = TeeQuoteCollateral::from(collateral);

    unsafe {
        let result = verify_quote_integrity(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            &collateral as *const TeeQuoteCollateral,
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

// Implement conversion from a static reference to Collateral
impl From<&Collateral<'static>> for TeeQuoteCollateral {
    fn from(collateral: &Collateral) -> Self {
        // Direct conversion is safe since the static reference guarantees
        // the data will live for the entire program execution
        TeeQuoteCollateral {
            tee_type: collateral.tee_type,

            // Safe conversion since the underlying memory won't be freed
            pck_crl_issuer_chain: collateral.pck_crl_issuer_chain.as_ptr()
                as *mut ::core::ffi::c_char,
            pck_crl_issuer_chain_size: collateral.pck_crl_issuer_chain.len() as u32,

            root_ca_crl: collateral.root_ca_crl.as_ptr() as *mut ::core::ffi::c_char,
            root_ca_crl_size: collateral.root_ca_crl.len() as u32,

            pck_crl: collateral.pck_crl.as_ptr() as *mut ::core::ffi::c_char,
            pck_crl_size: collateral.pck_crl.len() as u32,

            tcb_info_issuer_chain: collateral.tcb_info_issuer_chain.as_ptr()
                as *mut ::core::ffi::c_char,
            tcb_info_issuer_chain_size: collateral.tcb_info_issuer_chain.len() as u32,

            tcb_info: collateral.tcb_info.as_ptr() as *mut ::core::ffi::c_char,
            tcb_info_size: collateral.tcb_info.len() as u32,

            qe_identity_issuer_chain: collateral.qe_identity_issuer_chain.as_ptr()
                as *mut ::core::ffi::c_char,
            qe_identity_issuer_chain_size: collateral.qe_identity_issuer_chain.len() as u32,

            qe_identity: collateral.qe_identity.as_ptr() as *mut ::core::ffi::c_char,
            qe_identity_size: collateral.qe_identity.len() as u32,
        }
    }
}
