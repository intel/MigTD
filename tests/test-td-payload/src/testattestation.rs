// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use migtd::config;
use serde::{Deserialize, Serialize};
use td_layout::memslice;
use td_payload::print;
use td_uefi_pi::fv as fv_lib;
use td_uefi_pi::hob as hob_lib;
use td_uefi_pi::pi::fv;
use test_td_payload::{TestCase, TestResult};

pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
pub const VIRTIO_PCI_DEVICE_ID: u16 = 0x1053;

/**
 * Test tdvmcall mmio read/write
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct TdQa {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

pub struct TestTdQa {
    pub case: TdQa,
}

/**
 * Implement the TestCase trait for Tdmmiorw
 */
impl TestCase for TestTdQa {
    /**
     * set up the Test case of Tdmmiorw
     */
    fn setup(&mut self) {
        self.case.result = TestResult::Fail;
    }

    /**
     * run the test case
     * mmio read/write vsock device
     */
    fn run(&mut self) {
        // Get root certificate from CFV
        let root_ca = if let Some(root_ca) = config::get_root_ca() {
            root_ca
        } else {
            print!("Fail to get root certificate from CFV\n");
            return;
        };

        if attestation::root_ca::set_ca(root_ca).is_err() {
            print!("Invalid root certificate\n");
            return;
        }

        let td_report =
            tdx_tdcall::tdreport::tdcall_report(&[0u8; 64]).expect("Fail to get td report");
        if let Ok(quote) = attestation::get_quote(td_report.as_bytes()) {
            if attestation::verify_quote(quote.as_slice()).is_err() {
                print!("QuoteAttestation: fail to verify quote\n");
                return;
            }
            self.case.result = TestResult::Pass;
        } else {
            print!("QuoteAttestation: fail to get quote\n");
        }
    }

    /**
     * Tear down the test case.
     */
    fn teardown(&mut self) {}

    /**
     * get the name of the test case.
     */
    fn get_name(&mut self) -> String {
        String::from(&self.case.name)
    }

    /**
     * get the result of the test case.
     */
    fn get_result(&mut self) -> TestResult {
        self.case.result
    }
}
