// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![no_main]
#![allow(unused)]
#![feature(alloc_error_handler)]
#[macro_use]

mod testattestation;
mod testmmiorw;
mod testmsrrw;
mod testservice;

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;
use migtd as _;
use td_layout::memslice;
use testattestation::TdQa;

use crate::testattestation::TestTdQa;
use crate::testmmiorw::Tdmmiorw;
use crate::testmsrrw::Tdmsrrw;
use crate::testservice::Tdservice;
use test_td_payload::{TestResult, TestSuite};

use r_efi::efi::Guid;
use serde::{Deserialize, Serialize};
use serde_json::{Result, Value};
use td_payload::print;
use td_shim::e820::{E820Entry, E820Type};
use td_shim::TD_E820_TABLE_HOB_GUID;
use td_uefi_pi::{fv, hob as hob_lib, pi};
use zerocopy::FromBytes;

const E820_TABLE_SIZE: usize = 128;
const PAYLOAD_HEAP_SIZE: usize = 0x100_0000;
const HEAP_SIZE: usize = 0x2000000;

#[derive(Debug, Serialize, Deserialize)]
// The test cases' data structure corresponds to the test config json data structure
pub struct TestCases {
    pub tcs001: Tdmmiorw,
    pub tcs002: Tdservice,
    pub tcs003: Tdmsrrw,
    pub tcs004: TdQa,
}

pub const CFV_FFS_HEADER_TEST_CONFIG_GUID: Guid = Guid::from_fields(
    0xf10e684e,
    0x3abd,
    0x20e4,
    0x59,
    0x32,
    &[0x8f, 0x97, 0x3c, 0x35, 0x5e, 0x57],
); // {F10E684E-3ABD-20E4-5932-8F973C355E57}

#[cfg(not(test))]
fn build_testcases() -> TestCases {
    print!("Starting get test data from cfv and parse json data\n");
    let cfv = memslice::get_mem_slice(memslice::SliceType::Config);
    let json_data = fv::get_file_from_fv(
        cfv,
        pi::fv::FV_FILETYPE_RAW,
        CFV_FFS_HEADER_TEST_CONFIG_GUID,
    )
    .unwrap();
    let json_string = String::from_utf8_lossy(json_data).to_string();
    // trim zero in json string
    let json_config = json_string.trim_matches(char::from(0));

    serde_json::from_str(json_config).unwrap()
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main() {
    // create TestSuite to hold the test cases
    let mut ts = TestSuite {
        testsuite: Vec::new(),
        passed_cases: 0,
        failed_cases: 0,
    };

    // build test cases with test configuration data in CFV
    let mut tcs = build_testcases();

    if tcs.tcs004.run {
        let test_qa = TestTdQa { case: tcs.tcs004 };
        ts.testsuite.push(Box::new(test_qa));
    }

    // Add test cases in ts.testsuite
    if tcs.tcs001.run {
        ts.testsuite.push(Box::new(tcs.tcs001));
    }

    if tcs.tcs002.run {
        ts.testsuite.push(Box::new(tcs.tcs002));
    }

    if tcs.tcs003.run {
        ts.testsuite.push(Box::new(tcs.tcs003));
    }

    // run the TestSuite which contains the test cases
    print!("---------------------------------------------\n");
    print!("Start to run tests.\n");
    print!("---------------------------------------------\n");
    ts.run();
    print!(
        "Test Result: Total run {0} tests; {1} passed; {2} failed\n",
        ts.testsuite.len(),
        ts.passed_cases,
        ts.failed_cases
    );

    #[cfg(all(feature = "coverage", feature = "tdx"))]
    {
        const MAX_COVERAGE_DATA_PAGE_COUNT: usize = 0x200;
        let mut dma = td_payload::mm::dma::DmaMemory::new(MAX_COVERAGE_DATA_PAGE_COUNT)
            .expect("New dma fail.");
        let buffer = dma.as_mut_bytes();
        let coverage_len = minicov::get_coverage_data_size();
        assert!(coverage_len < MAX_COVERAGE_DATA_PAGE_COUNT * td_paging::PAGE_SIZE);
        minicov::capture_coverage_to_buffer(&mut buffer[0..coverage_len]);
        print!(
            "coverage addr: {:x}, coverage len: {}",
            buffer.as_ptr() as u64,
            coverage_len
        );

        loop {}
    }

    panic!("deadloop");
}

#[cfg(test)]
fn main() {}
// FIXME: remove when https://github.com/Amanieu/minicov/issues/12 is fixed.
#[cfg(all(feature = "coverage", feature = "tdx", target_os = "none"))]
#[no_mangle]
static __llvm_profile_runtime: u32 = 0;
