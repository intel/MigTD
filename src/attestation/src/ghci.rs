// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::sync::atomic::{AtomicU8, Ordering};
use core::{ffi::c_void, ptr::null_mut, slice::from_raw_parts_mut};
use td_payload::arch::apic::{disable, enable_and_hlt};
use td_payload::arch::idt::register;
use td_payload::{interrupt_handler_template, mm::dma::DmaMemory};
use tdx_tdcall::{td_vmcall, tdx, TdVmcallArgs, TdVmcallError};

use crate::binding::AttestLibError;

pub const NOTIFY_VALUE: u8 = 1;
const NOTIFY_VECTOR: u8 = 0x51;
const GET_QUOTE_MAX_SIZE: u64 = 32 * 0x1000;
const TDVMCALL_GETQUOTE: u64 = 0x10002;

pub static NOTIFIER: AtomicU8 = AtomicU8::new(0);

#[no_mangle]
pub extern "C" fn migtd_get_quote(tdquote_req_buf: *mut c_void, len: u64) -> i32 {
    if tdquote_req_buf == null_mut() || len > GET_QUOTE_MAX_SIZE {
        return AttestLibError::MigtdAttestErrorInvalidParameter as i32;
    }

    let input = unsafe { from_raw_parts_mut(tdquote_req_buf as *mut u8, len as usize) };

    let mut shared = if let Some(shared) = DmaMemory::new(len as usize / 0x1000) {
        shared
    } else {
        return AttestLibError::MigtdAttestErrorOutOfMemory as i32;
    };
    shared.as_mut_bytes()[..len as usize].copy_from_slice(input);

    set_vmm_notification();

    if tdvmcall_get_quote(shared.as_mut_bytes()).is_err() {
        return AttestLibError::MigtdAttestErrorQuoteFailure as i32;
    }

    wait_for_vmm_notification();

    input.copy_from_slice(&shared.as_bytes()[..len as usize]);

    // Success
    0
}

// TODO: remove this after next version of `td-shim` is released
fn tdvmcall_get_quote(buffer: &mut [u8]) -> Result<(), TdVmcallError> {
    let addr = buffer.as_mut_ptr() as u64 | tdx::td_shared_mask().unwrap();

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_GETQUOTE,
        r12: addr,
        r13: buffer.len() as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != 0 {
        return Err(ret.into());
    }

    Ok(())
}

interrupt_handler_template!(vmm_notification, _stack, {
    NOTIFIER.store(NOTIFY_VALUE, Ordering::SeqCst);
});

pub fn set_vmm_notification() {
    // Setup interrupt handler
    register(NOTIFY_VECTOR, vmm_notification);

    // Setup event notifier
    if tdx_tdcall::tdx::tdvmcall_setup_event_notify(NOTIFY_VECTOR as u64).is_err() {
        panic!("Fail to setup VMM event notifier\n");
    }
}

pub fn wait_for_vmm_notification() {
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
