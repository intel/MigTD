// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;
use core::ops::Range;

use crate::PolicyError;

/// Returns the TD Report 1.5 body of a v5 quote, or `None` for a v4 quote.
///
/// The DCAP TDQE (`determine_quote_version()` in `quoting_enclave_tdqe.cpp`)
/// emits v5 quotes only with a TD Report 1.5 body, so any other v5 body type
/// or quote version is rejected.
pub(crate) fn get_td_report_15_body(quote: &[u8]) -> Result<Option<&[u8]>, PolicyError> {
    const QUOTE_HEADER_SIZE: usize = 48;
    const QUOTE_V5_BODY_HEADER_SIZE: usize = 6;
    const TD_REPORT_15_BODY_TYPE: u16 = 3;
    const TD_REPORT_15_BODY_SIZE: usize = 648;

    let version = quote
        .get(..2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(PolicyError::InvalidQuote)?;
    match version {
        4 => return Ok(None),
        5 => {}
        _ => return Err(PolicyError::InvalidQuote),
    }

    let body_type = quote
        .get(QUOTE_HEADER_SIZE..QUOTE_HEADER_SIZE + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(PolicyError::InvalidQuote)?;
    if body_type != TD_REPORT_15_BODY_TYPE {
        return Err(PolicyError::InvalidQuote);
    }

    let body_size = quote
        .get(QUOTE_HEADER_SIZE + 2..QUOTE_HEADER_SIZE + QUOTE_V5_BODY_HEADER_SIZE)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .map(|value| value as usize)
        .ok_or(PolicyError::InvalidQuote)?;
    if body_size != TD_REPORT_15_BODY_SIZE {
        return Err(PolicyError::InvalidQuote);
    }

    let body_offset = QUOTE_HEADER_SIZE + QUOTE_V5_BODY_HEADER_SIZE;
    quote
        .get(body_offset..body_offset + TD_REPORT_15_BODY_SIZE)
        .map(Some)
        .ok_or(PolicyError::InvalidQuote)
}

/// MigTD must be relaunched after a TD-preserving TDX module update, so its
/// TEE_TCB_SVN2 must equal TEE_TCB_SVN (MigTD Design Guide, "Some rules" 1).
///
/// The DCAP TDQE emits a v4 quote only when TEE_TCB_SVN2 is not reported
/// (TEE_TCB_INFO.VALID == 0x1FF) or equals TEE_TCB_SVN; otherwise it emits a
/// v5 quote with a TD Report 1.5 body. When VALID == 0x1FF in a v5 quote, the
/// TDQE fills both SVN fields from the same source, so they compare equal.
pub fn verify_migtd_tee_tcb_svn2(quote: &[u8]) -> Result<(), PolicyError> {
    const TEE_TCB_SVN: Range<usize> = 0..16;
    const TEE_TCB_SVN2: Range<usize> = 584..600;

    let Some(body) = get_td_report_15_body(quote)? else {
        return Ok(());
    };
    if body[TEE_TCB_SVN] != body[TEE_TCB_SVN2] {
        return Err(PolicyError::SvnMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    const BODY_OFFSET: usize = 54;
    const TEE_TCB_SVN2_OFFSET: usize = 584;

    fn td_report_15_quote() -> Vec<u8> {
        let mut quote = vec![0u8; BODY_OFFSET + 648];
        quote[..2].copy_from_slice(&5u16.to_le_bytes());
        quote[48..50].copy_from_slice(&3u16.to_le_bytes());
        quote[50..54].copy_from_slice(&648u32.to_le_bytes());
        quote
    }

    #[test]
    fn reject_migtd_tee_tcb_svn2_mismatch() {
        let mut quote = td_report_15_quote();
        quote[BODY_OFFSET..BODY_OFFSET + 16].fill(0x07);
        quote[BODY_OFFSET + TEE_TCB_SVN2_OFFSET..BODY_OFFSET + TEE_TCB_SVN2_OFFSET + 16].fill(0x07);
        assert!(verify_migtd_tee_tcb_svn2(&quote).is_ok());

        quote[BODY_OFFSET + TEE_TCB_SVN2_OFFSET] = 0x06;
        assert!(matches!(
            verify_migtd_tee_tcb_svn2(&quote),
            Err(PolicyError::SvnMismatch)
        ));

        // v4 quotes carry no TEE_TCB_SVN2.
        quote[..2].copy_from_slice(&4u16.to_le_bytes());
        assert!(verify_migtd_tee_tcb_svn2(&quote).is_ok());
    }

    #[test]
    fn reject_unexpected_quote_format() {
        let mut quote = td_report_15_quote();
        quote[48..50].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            verify_migtd_tee_tcb_svn2(&quote),
            Err(PolicyError::InvalidQuote)
        ));

        let mut quote = td_report_15_quote();
        quote[..2].copy_from_slice(&3u16.to_le_bytes());
        assert!(matches!(
            verify_migtd_tee_tcb_svn2(&quote),
            Err(PolicyError::InvalidQuote)
        ));
    }
}
