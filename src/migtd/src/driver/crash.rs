// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg(feature = "vmcall-raw")]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use raw_cpuid::{CpuId, CpuIdReader, CpuIdReaderNative, CpuIdResult};
#[cfg(not(test))]
use td_payload::mm::shared::alloc_shared_pages;
#[cfg(not(test))]
use x86_64::registers::model_specific::Msr;
const CPUID_HYPERV_VENDOR_MAX_FUNCTION: u32 = 0x40000000;
const CPUID_HYPERV_FEATURE_ID: u32 = 0x40000003;
const GUEST_CRASH_MSR_SUPPORT_BIT: u32 = 1 << 10;
#[cfg(not(test))]
const CRASH_NOTIFY_BIT: u64 = 1;
#[cfg(not(test))]
const CRASH_MESSAGE_BIT: u64 = 1 << 1;
#[cfg(not(test))]
const MSR_CRASH_P0: u32 = 0x40000100;
#[cfg(not(test))]
const MSR_CRASH_P3: u32 = 0x40000103;
#[cfg(not(test))]
const MSR_CRASH_P4: u32 = 0x40000104;
#[cfg(not(test))]
const MSR_CRASH_CTL: u32 = 0x40000105;
static GUEST_CRASH_MSR_SUPPORTED: AtomicBool = AtomicBool::new(false);
#[cfg(not(test))]
const PAGE_SIZE: usize = 0x1_000;

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

pub fn update_guest_crash_reg_report(
    errorcode: u64,
    crash_message: Vec<u8>,
    #[cfg(test)] msr_crash_p0: &mut u64,
) {
    if guest_crash_reg_supported() {
        #[cfg(not(test))]
        {
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
        #[cfg(test)]
        {
            *msr_crash_p0 = errorcode;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_crash_msr_support_enabling() {
        GUEST_CRASH_MSR_SUPPORTED.store(false, Ordering::SeqCst);
        assert_eq!(guest_crash_reg_supported(), false);

        // Test enabling it
        GUEST_CRASH_MSR_SUPPORTED.store(true, Ordering::SeqCst);
        assert_eq!(guest_crash_reg_supported(), true);
    }

    #[test]
    fn test_crash_msr_support_update_without_enabling() {
        GUEST_CRASH_MSR_SUPPORTED.store(false, Ordering::SeqCst);
        let mut msr_crash_p0: u64 = 0;
        let test_message = Vec::new();
        update_guest_crash_reg_report(0x123, test_message, &mut msr_crash_p0);
        assert_eq!(msr_crash_p0, 0);
    }

    #[test]
    fn test_crash_msr_support_update_with_enabling() {
        GUEST_CRASH_MSR_SUPPORTED.store(false, Ordering::SeqCst);
        let mut msr_crash_p0: u64 = 0;
        let test_message = Vec::new();

        GUEST_CRASH_MSR_SUPPORTED.store(true, Ordering::SeqCst);
        update_guest_crash_reg_report(0x123, test_message, &mut msr_crash_p0);
        assert_eq!(msr_crash_p0, 0x123);
    }
}
