// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "attest-lib-ext")]
use crate::binding::verify_quote_integrity_ex;
use crate::{
    binding::{
        get_quote as get_quote_inner, init_heap, verify_quote_integrity, AttestLibError,
        QveCollateral,
    },
    root_ca::ROOT_CA_PUBLIC_KEY,
    Error, TD_VERIFIED_REPORT_SIZE,
};
use alloc::{ffi::CString, vec, vec::Vec};
use core::{alloc::Layout, ffi::c_void, ops::Range};
use tdx_tdcall::tdreport::*;

const TD_QUOTE_SIZE: usize = 0x2000;
const TD_REPORT_VERIFY_SIZE: usize = 1024;
const ATTEST_HEAP_SIZE: usize = 0x80000;

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
