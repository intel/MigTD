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
        return AttestLibError::InvalidParameter as i32;
    }

    let input = unsafe { from_raw_parts_mut(tdquote_req_buf as *mut u8, len as usize) };

    let mut shared = if let Some(shared) = SharedMemory::new(len as usize / 0x1000) {
        shared
    } else {
        return AttestLibError::OutOfMemory as i32;
    };
    shared.as_mut_bytes()[..len as usize].copy_from_slice(input);

    let notify_registered = set_vmm_notification();

    if tdvmcall_get_quote(shared.as_mut_bytes()).is_err() {
        return AttestLibError::QuoteFailure as i32;
    }

    if let Err(err) = wait_for_quote_completion(notify_registered, shared.as_bytes()) {
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
        panic!("Fail to setup interrupt callback for VMM notify\n");
    }

    // Setup event notifier
    tdx_tdcall::tdx::tdvmcall_setup_event_notify(NOTIFY_VECTOR as u64).is_ok()
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
            None => return Err(AttestLibError::InvalidParameter),
        };
    }

    if status_code == GET_QUOTE_STATUS_SUCCESS {
        Ok(())
    } else {
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
