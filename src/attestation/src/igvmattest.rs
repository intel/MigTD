// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{attest::TD_QUOTE_SIZE, Error};
#[cfg(feature = "igvm-attest")]
use alloc::{vec, vec::Vec};
use core::ffi::c_void;

extern "C" {
    pub fn servtd_get_quote(tdquote_req_buf: *mut core::ffi::c_void, len: u64) -> i32;
}

#[repr(C)]
#[derive(Debug)]
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
    _data: [u64; 0],
}

const SERVTD_REQ_BUF_SIZE: usize = 16 * 4 * 1024; // 16 pages

pub fn get_quote_igvm(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    let mut quote = vec![0u8; TD_QUOTE_SIZE];
    let mut quote_size = TD_QUOTE_SIZE as u32;
    let mut get_quote_blob = vec![0u8; SERVTD_REQ_BUF_SIZE];

    // Copy the header to get_quote_blob
    let hdr = ServtdTdxQuoteHdr {
        version: 1,
        status: 0,
        in_len: td_report.len() as u32,
        out_len: quote_size as u32,
        _data: [],
    };

    let header_size = core::mem::size_of::<ServtdTdxQuoteHdr>();

    // Validate buffer size
    if header_size + td_report.len() > SERVTD_REQ_BUF_SIZE {
        log::error!(
            "Buffer too small: need {} bytes, have {} bytes\n",
            header_size + td_report.len(),
            SERVTD_REQ_BUF_SIZE
        );
        return Err(Error::GetQuote);
    }

    let hdr_bytes =
        unsafe { core::slice::from_raw_parts(&hdr as *const _ as *const u8, header_size) };
    get_quote_blob[..header_size].copy_from_slice(hdr_bytes);

    log::debug!(
        "Header size: {}, TD report size: {}\n",
        header_size,
        td_report.len()
    );
    log::debug!(
        "ServtdTdxQuoteHdr values before calling servtd_get_quote: \n{:?}\n",
        hdr
    );
    // Copy TD report at data offset (after header)
    get_quote_blob[header_size..header_size + td_report.len()].copy_from_slice(td_report);

    // Dump the first 64 bytes of the blob for debugging
    let dump_len = core::cmp::min(64, get_quote_blob.len());
    log::debug!(
        "First {} bytes of get_quote_blob: {:02x?}\n",
        dump_len,
        &get_quote_blob[..dump_len]
    );

    // send the request to VMM via ghci
    let get_quote_blob_ptr = get_quote_blob.as_mut_ptr() as *mut c_void;
    let servtd_get_quote_ret =
        unsafe { servtd_get_quote(get_quote_blob_ptr, SERVTD_REQ_BUF_SIZE as u64) };

    if servtd_get_quote_ret != 0 {
        unsafe {
            let hdr = get_quote_blob_ptr as *mut ServtdTdxQuoteHdr;
            log::error!(
                "servtd_get_quote failed with error code: {} with header values:\n{:?}\n",
                servtd_get_quote_ret,
                (*hdr)
            );
        }
        return Err(Error::GetQuote);
    }

    let hdr = get_quote_blob_ptr as *mut ServtdTdxQuoteHdr;

    // Additional validation: ensure we can safely read the header
    if (hdr as usize) < (get_quote_blob.as_ptr() as usize)
        || (hdr as usize + header_size) > (get_quote_blob.as_ptr() as usize + get_quote_blob.len())
    {
        log::error!("Header pointer is outside of allocated buffer\n");
        return Err(Error::GetQuote);
    }

    unsafe {
        log::debug!(
            "ServtdTdxQuoteHdr values after calling servtd_get_quote:\n {:?}\n",
            (*hdr)
        );
    }

    // Validate quote_size bounds
    unsafe {
        quote_size = (*hdr).out_len;
    }
    if quote_size > TD_QUOTE_SIZE as u32 {
        log::error!(
            "Quote size {} exceeds buffer size {}\n",
            quote_size,
            TD_QUOTE_SIZE
        );
        return Err(Error::GetQuote);
    }

    // Validate we have enough data in the buffer
    if header_size + quote_size as usize > get_quote_blob.len() {
        log::error!(
            "Quote data extends beyond buffer: need {} bytes, have {} bytes\n",
            header_size + quote_size as usize,
            get_quote_blob.len()
        );
        return Err(Error::GetQuote);
    }

    // Validate output buffer size
    if quote_size as usize > quote.len() {
        log::error!(
            "Quote size {} exceeds output buffer size {}\n",
            quote_size,
            quote.len()
        );
        return Err(Error::GetQuote);
    }

    quote[..quote_size as usize]
        .copy_from_slice(&get_quote_blob[header_size..header_size + quote_size as usize]);

    log::info!("get_quote_igvm returned quote_size = {}\n", quote_size);

    log::debug!("quote = {:?}\n", &quote[..quote_size as usize]);

    quote.truncate(quote_size as usize);
    Ok(quote)
}
