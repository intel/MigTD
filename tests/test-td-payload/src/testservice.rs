// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use alloc::string::String;
use core::ffi::c_void;
use td_payload::print;
use test_td_payload::{TestCase, TestResult};

use migtd::migration::session::MigrationSession;

use serde::{Deserialize, Serialize};

/**
 * Test tdvmcall service
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct Tdservice {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

impl Tdservice {
    fn test_query(&mut self) -> TestResult {
        // Query the capability of VMM
        if MigrationSession::query().is_err() {
            print!("Migration is not supported by VMM");
            return TestResult::Fail;
        }
        TestResult::Pass
    }
}

/**
 * Implement the TestCase trait for Tdservice
 */
impl TestCase for Tdservice {
    /**
     * set up the Test case of Tdservice
     */
    fn setup(&mut self) {
        self.result = TestResult::Fail;
    }

    /**
     * run the test case
     * mmio read/write vsock device
     */
    fn run(&mut self) {
        self.result = self.test_query();
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
