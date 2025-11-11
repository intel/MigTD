// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg(feature = "vmcall-raw")]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use raw_cpuid::{CpuId, CpuIdReader, CpuIdReaderNative, CpuIdResult};
use td_payload::mm::shared::alloc_shared_pages;
use x86_64::registers::model_specific::Msr;
const CPUID_HYPERV_VENDOR_MAX_FUNCTION: u32 = 0x40000000;
const CPUID_HYPERV_FEATURE_ID: u32 = 0x40000003;
const GUEST_CRASH_MSR_SUPPORT_BIT: u32 = 1 << 10;
const CRASH_NOTIFY_BIT: u64 = 1;
const CRASH_MESSAGE_BIT: u64 = 1 << 1;
const MSR_CRASH_P0: u32 = 0x40000100;
const MSR_CRASH_P3: u32 = 0x40000103;
const MSR_CRASH_P4: u32 = 0x40000104;
const MSR_CRASH_CTL: u32 = 0x40000105;
static GUEST_CRASH_MSR_SUPPORTED: AtomicBool = AtomicBool::new(false);
const PAGE_SIZE: usize = 0x1_000;
use alloc::format;

pub fn guest_crash_reg_supported() -> bool {
    GUEST_CRASH_MSR_SUPPORTED.load(Ordering::SeqCst)
}

pub fn initialize_crash_msr_support() {
    let reader = CpuIdReaderNative;
    let reader_1 = CpuIdReaderNative;
    let cpuid = CpuId::new();
    if let Some(feature_info) = cpuid.get_feature_info() {
        let hypervisorpresent: bool = feature_info.has_hypervisor();
        if hypervisorpresent {
            let cpuid_result: CpuIdResult = reader.cpuid2(CPUID_HYPERV_VENDOR_MAX_FUNCTION, 0);
            if CPUID_HYPERV_FEATURE_ID < cpuid_result.eax {
                let cpuid_result_1: CpuIdResult = reader_1.cpuid2(CPUID_HYPERV_FEATURE_ID, 0);
                if cpuid_result_1.edx & GUEST_CRASH_MSR_SUPPORT_BIT != 0 {
                    GUEST_CRASH_MSR_SUPPORTED.store(true, Ordering::SeqCst);
                }
            }
        }
    }
}

pub fn update_guest_crash_reg_report(errorcode: u64, crash_message: Vec<u8>) {
    if guest_crash_reg_supported() {
        // Guest crash MSR
        let mut msr_crash_p0 = Msr::new(MSR_CRASH_P0);
        let mut msr_crash_p3 = Msr::new(MSR_CRASH_P3);
        let mut msr_crash_p4 = Msr::new(MSR_CRASH_P4);
        let mut msr_crash_ctl = Msr::new(MSR_CRASH_CTL);

        let mut crash_ctl_bits: u64 = 0;

        crash_ctl_bits |= CRASH_NOTIFY_BIT;
        unsafe {
            // Error Code
            msr_crash_p0.write(errorcode);
            if crash_message.len() > 0 && crash_message.len() < PAGE_SIZE {
                let data_buffer = match alloc_shared_pages(1) {
                    Some(addr) => addr,
                    None => {
                        // CrashNotify
                        msr_crash_ctl.write(crash_ctl_bits);
                        return;
                    }
                };
                let data_buffer =
                    core::slice::from_raw_parts_mut(data_buffer as *mut u8, PAGE_SIZE);
                let data_buffer_as_u64 = data_buffer.as_ptr() as u64;

                data_buffer[0..crash_message.len()]
                    .copy_from_slice(&crash_message[0..crash_message.len()]);

                // GPA of the message
                msr_crash_p3.write(data_buffer_as_u64);
                // Message size
                msr_crash_p4.write(crash_message.len() as u64);
                crash_ctl_bits |= CRASH_MESSAGE_BIT;
            }
            msr_crash_ctl.write(crash_ctl_bits);
        }
    }
}
