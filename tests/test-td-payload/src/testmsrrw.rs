// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use alloc::string::String;
use core::ffi::c_void;
use td_payload::print;
use test_td_payload::{TestCase, TestResult};

use serde::{Deserialize, Serialize};

/**
 * Test tdvmcall read/write MSR
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct Tdmsrrw {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

impl Tdmsrrw {
    fn test(&mut self) -> TestResult {
        // Enable the local APIC by setting bit 8 of the APIC spurious vector region (SVR)
        // Ref: Intel SDM Vol3. 8.4.4.1
        // In x2APIC mode, SVR is mapped to MSR address 0x80f.
        // Since SVR(SIVR) is not virtualized, before we implement the handling in #VE of MSRRD/WR,
        // use tdvmcall instead direct read/write operation.
        let read1 = if let Ok(val) = tdx_tdcall::tdx::tdvmcall_rdmsr(0x80f) {
            val
        } else {
            return TestResult::Fail;
        };

        tdx_tdcall::tdx::tdvmcall_wrmsr(0x80f, read1 + 1);

        let read2 = if let Ok(val) = tdx_tdcall::tdx::tdvmcall_rdmsr(0x80f) {
            val
        } else {
            return TestResult::Fail;
        };

        if (read1 + 1 != read2) {
            print!(
                "Second time value is not equal with the first time value + 1 - Expected {:?}: Actual {:?}\n",
                read1 + 1,
                read2
            );
            return TestResult::Fail;
        }
        TestResult::Pass
    }
}

/**
 * Implement the TestCase trait for Tdmsrrw
 */
impl TestCase for Tdmsrrw {
    /**
     * set up the Test case of Tdmsrrw
     */
    fn setup(&mut self) {
        self.result = TestResult::Fail;
    }

    /**
     * run the test case
     * mmio read/write vsock device
     */
    fn run(&mut self) {
        self.result = self.test();
    }

    /**
     * Tear down the test case.
     */
    fn teardown(&mut self) {}

    /**
     * get the name of the test case.
     */
    fn get_name(&mut self) -> String {
        String::from(&self.name)
    }

    /**
     * get the result of the test case.
     */
    fn get_result(&mut self) -> TestResult {
        self.result
    }
}
