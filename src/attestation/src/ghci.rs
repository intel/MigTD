// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::ops::Range;
use core::sync::atomic::{AtomicU8, Ordering};
use core::{ffi::c_void, slice::from_raw_parts_mut};
use td_payload::arch::apic::{disable, enable_and_hlt};
use td_payload::arch::idt::{register_interrupt_callback, InterruptCallback, InterruptStack};
use td_payload::mm::shared::SharedMemory;
use tdx_tdcall::tdx::tdvmcall_get_quote;

use crate::binding::AttestLibError;

pub const NOTIFY_VALUE: u8 = 1;
const NOTIFY_VECTOR: u8 = 0x51;
const GET_QUOTE_MAX_SIZE: u64 = 32 * 0x1000;
const GET_QUOTE_STATUS_FIELD: Range<usize> = 8..16;
const GET_QUOTE_STATUS_SUCCESS: u64 = 0;
const GET_QUOTE_STATUS_IN_FLIGHT: u64 = 0xFFFFFFFF_FFFFFFFF;

pub static NOTIFIER: AtomicU8 = AtomicU8::new(0);

#[no_mangle]
pub extern "C" fn servtd_get_quote(tdquote_req_buf: *mut c_void, len: u64) -> i32 {
    if tdquote_req_buf.is_null() || len > GET_QUOTE_MAX_SIZE {
        log::error!(
            "Invalid parameters: tdquote_req_buf.is_null() is {} or len is {}\n",
            tdquote_req_buf.is_null(),
            len
        );
        return AttestLibError::InvalidParameter as i32;
    }

    let input = unsafe { from_raw_parts_mut(tdquote_req_buf as *mut u8, len as usize) };

    let mut shared = if let Some(shared) = SharedMemory::new(len as usize / 0x1000) {
        shared
    } else {
        log::error!("Failed to allocate shared memory of size {}\n", len);
        return AttestLibError::OutOfMemory as i32;
    };
    shared.as_mut_bytes()[..len as usize].copy_from_slice(input);

    let notify_registered = set_vmm_notification();

    if let Err(e) = tdvmcall_get_quote(shared.as_mut_bytes()) {
        log::error!("tdvmcall_get_quote failed with error: {:?}\n", e);
        return AttestLibError::QuoteFailure as i32;
    }

    if let Err(err) = wait_for_quote_completion(notify_registered, shared.as_bytes()) {
        log::error!("wait_for_quote_completion failed: {:?}\n", err);
        return err as i32;
    }
    input.copy_from_slice(&shared.as_bytes()[..len as usize]);

    // Success
    0
}

fn vmm_notification(_: &mut InterruptStack) {
    NOTIFIER.store(NOTIFY_VALUE, Ordering::SeqCst);
}

fn set_vmm_notification() -> bool {
    // Setup interrupt handler
    if register_interrupt_callback(
        NOTIFY_VECTOR as usize,
        InterruptCallback::new(vmm_notification),
    )
    .is_err()
    {
        log::error!("Fail to setup interrupt callback for VMM notify\n");
        return false;
    }

    // Setup event notifier
    _ = tdx_tdcall::tdx::tdvmcall_setup_event_notify(NOTIFY_VECTOR as u64).map_err(|e| {
        log::error!("Fail to setup event notify for VMM: {:?}\n", e);
        false
    });

    true
}

fn wait_for_quote_completion(notify_registered: bool, buffer: &[u8]) -> Result<(), AttestLibError> {
    // If the VMM notification is successfully registered, wait for VMM injecting the interrupt.
    if notify_registered {
        wait_for_vmm_notification();
        return Ok(());
    }

    let mut status_code = GET_QUOTE_STATUS_IN_FLIGHT;
    while status_code == GET_QUOTE_STATUS_IN_FLIGHT {
        status_code = match buffer.get(GET_QUOTE_STATUS_FIELD) {
            Some(bytes) => u64::from_le_bytes(bytes.try_into().unwrap()),
            None => {
                log::error!("Failed to get quote status from buffer\n");
                return Err(AttestLibError::InvalidParameter);
            }
        };
    }

    if status_code == GET_QUOTE_STATUS_SUCCESS {
        Ok(())
    } else {
        log::error!("Quote status indicates failure: {:#x}\n", status_code);
        Err(AttestLibError::QuoteFailure)
    }
}

fn wait_for_vmm_notification() {
    while NOTIFIER.load(Ordering::SeqCst) == 0 {
        // Halt to wait until interrupt comming
        enable_and_hlt();
        if NOTIFIER.load(Ordering::SeqCst) == 1 {
            break;
        }
    }

    // Reset the value of NOTIFIER
    NOTIFIER.store(0, Ordering::SeqCst);
    disable();
}
