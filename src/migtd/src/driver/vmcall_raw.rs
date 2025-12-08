// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::alloc::string::ToString;
#[cfg(not(test))]
#[cfg(feature = "vmcall-raw")]
use crate::driver::crash::update_guest_crash_reg_report;
#[cfg(not(test))]
#[cfg(feature = "vmcall-raw")]
use alloc::format;

#[cfg(feature = "vmcall-raw")]
pub fn vmcall_raw_device_init() {
    // Initialize the transport
    vmcall_raw::transport::vmcall_raw_transport_init().expect("Failed to initialize vmcall-raw");
}

#[track_caller]
pub fn panic_with_guest_crash_reg_report(errorcode: u64, msg: &[u8]) {
    #[cfg(not(feature = "vmcall-raw"))]
    let _ = errorcode;
    let location = core::panic::Location::caller();
    let file = location.file();
    let line = location.line();
    let panic_message = if let Ok(s) = core::str::from_utf8(msg) {
        s.to_string()
    } else {
        " non-UTF8 message".to_string()
    };

    #[cfg(not(test))]
    #[cfg(feature = "vmcall-raw")]
    {
        let crash_message = format!(
            "Panic: msg: {} at location: {} line: {}",
            panic_message, file, line
        )
        .into_bytes();
        update_guest_crash_reg_report(errorcode, crash_message);
    }
    panic!("{} (at {}:{})", panic_message, file, line);
}
