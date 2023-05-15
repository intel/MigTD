// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![no_main]

extern crate alloc;

use migtd::migration::{session::MigrationSession, MigrationResult};
use migtd::{config, event_log, migration};
use td_payload::println;

const MIGTD_VERSION: &str = env!("CARGO_PKG_VERSION");

const TAGGED_EVENT_ID_POLICY: u32 = 0x1;
const TAGGED_EVENT_ID_ROOT_CA: u32 = 0x2;

#[no_mangle]
pub extern "C" fn main() {
    #[cfg(feature = "test_stack_size")]
    {
        td_benchmark::StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0xd000);
    }
    runtime_main()
}

pub fn runtime_main() {
    let _ = td_logger::init();

    // Dump basic information of MigTD
    basic_info();

    // Get the event log recorded by firmware
    let event_log = event_log::get_event_log_mut().expect("Failed to get the event log");

    // Get migration td policy from CFV and measure it into RMTR
    get_policy_and_measure(event_log);

    // Get root certificate from CFV and measure it into RMTR
    get_ca_and_measure(event_log);

    // Handle the migration request from VMM
    handle_pre_mig();
}

fn basic_info() {
    println!("MigTD Version - {}", MIGTD_VERSION);
}

fn get_policy_and_measure(event_log: &mut [u8]) {
    // Read migration policy from CFV
    let policy = config::get_policy().expect("Fail to get policy from CFV\n");

    // Measure and extend the migration policy to RTMR
    event_log::write_tagged_event_log(event_log, TAGGED_EVENT_ID_POLICY, policy)
        .expect("Failed to log migration policy");
}

fn get_ca_and_measure(event_log: &mut [u8]) {
    let root_ca = config::get_root_ca().expect("Fail to get root certificate from CFV\n");

    // Measure and extend the root certificate to RTMR
    event_log::write_tagged_event_log(event_log, TAGGED_EVENT_ID_ROOT_CA, root_ca)
        .expect("Failed to log SGX root CA\n");

    attestation::root_ca::set_ca(root_ca).expect("Invalid root certificate\n");
}

fn handle_pre_mig() {
    migration::event::register_callback();
    // Query the capability of VMM
    if MigrationSession::query().is_err() {
        panic!("Migration is not supported by VMM");
    }
    // Loop to wait for request
    println!("Loop to wait for request");
    loop {
        let mut session = MigrationSession::new();
        if session.wait_for_request().is_ok() {
            #[cfg(feature = "vmcall-vsock")]
            {
                // Safe to unwrap because we have got the request information
                let info = session.info().unwrap();
                migtd::driver::vsock::vmcall_vsock_device_init(
                    info.mig_info.mig_request_id,
                    info.mig_socket_info.mig_td_cid,
                );
            }

            let status = session
                .op()
                .map(|_| MigrationResult::Success)
                .unwrap_or_else(|e| e);
            let _ = session.report_status(status as u8);
            #[cfg(all(feature = "coverage", feature = "tdx"))]
            {
                const MAX_COVERAGE_DATA_PAGE_COUNT: usize = 0x200;
                let mut dma = td_payload::mm::dma::DmaMemory::new(MAX_COVERAGE_DATA_PAGE_COUNT)
                    .expect("New dma fail.");
                let buffer = dma.as_mut_bytes();
                let coverage_len = minicov::get_coverage_data_size();
                assert!(coverage_len < MAX_COVERAGE_DATA_PAGE_COUNT * td_paging::PAGE_SIZE);
                minicov::capture_coverage_to_buffer(&mut buffer[0..coverage_len]);
                println!(
                    "coverage addr: {:x}, coverage len: {}",
                    buffer.as_ptr() as u64,
                    coverage_len
                );

                loop {}
            }
            #[cfg(any(feature = "test_stack_size", feature = "test_heap_size"))]
            test_memory()
        };
    }
}

#[cfg(test)]
fn main() {}
// FIXME: remove when https://github.com/Amanieu/minicov/issues/12 is fixed.
#[cfg(all(feature = "coverage", feature = "tdx", target_os = "none"))]
#[no_mangle]
static __llvm_profile_runtime: u32 = 0;

#[cfg(any(feature = "test_stack_size", feature = "test_heap_size"))]
fn test_memory() {
    #[cfg(feature = "test_stack_size")]
    {
        let value = td_benchmark::StackProfiling::stack_usage().unwrap();
        println!("max stack usage: {}", value);
    }
    #[cfg(feature = "test_heap_size")]
    {
        let value = td_benchmark::HeapProfiling::heap_usage().unwrap();
        println!("max heap usage: {}", value);
    }
}
