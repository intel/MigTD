// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{
    binding::get_quote as get_quote_inner, binding::init_heap, binding::verify_quote_integrity,
    binding::AttestLibError, root_ca::ROOT_CA, Error,
};
use alloc::{vec, vec::Vec};
use core::{alloc::Layout, ffi::c_void};
use tdx_tdcall::tdreport::*;

const TD_QUOTE_SIZE: usize = 0x2000;
const TD_REPORT_VERIFY_SIZE: usize = 1024;
const ATTEST_HEAP_SIZE: usize = 0x80000;
const TD_VERIFIED_REPORT_SIZE: usize = 584;

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
        if result != AttestLibError::MigtdAttestSuccess {
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
            public_key.as_ptr() as *const c_void,
            public_key.len() as u32,
            td_report_verify.as_mut_ptr() as *mut c_void,
            &mut report_verify_size as *mut u32,
        );
        if result != AttestLibError::MigtdAttestSuccess {
            return Err(Error::VerifyQuote);
        }
    }

    if report_verify_size as usize != TD_VERIFIED_REPORT_SIZE {
        return Err(Error::InvalidOutput);
    }

    Ok(wrap_verified_report(td_report_verify))
}

// The verified report returned from `verify_quote_integrity` is not in the
// format of the raw TD report. To simplify the use of returned report, wrap
// the result into the raw format.
// {
//      // TEE_TCB_INFO
//      tee_tcb_svn: [u8; 16],
//      mrseam: [u8; 48],
//      mrsigner_seam: [u8; 48],
//      seam_attributes: [u8; 8],
//     // TD_INFO
//     td_attributes: [u8; 8],
//     xfam: [u8; 8],
//     mrtd: [u8; 48],
//     mrconfig_id: [u8; 48],
//     mrowner: [u8; 48],
//     mrownerconfig: [u8; 48],
//     rtmr0: [u8; 48],
//     rtmr1: [u8; 48],
//     rtmr2: [u8; 48],
//     rtmr3: [u8; 48],
//     // ADDITIONAL_REPORT_DATA
//     report_data: [u8; 64],
// }
fn wrap_verified_report(verified_report: Vec<u8>) -> Vec<u8> {
    let mut report = vec![0u8; TD_REPORT_SIZE];
    // REPORT_DATA
    report[128..192].copy_from_slice(&verified_report[520..584]);
    // TEE_TCB_INFO
    report[264..384].copy_from_slice(&verified_report[0..120]);
    // TD_INFO
    report[512..912].copy_from_slice(&verified_report[120..520]);

    report
}
