// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(feature = "AzCVMEmu"), no_std)]
#![cfg_attr(not(feature = "AzCVMEmu"), no_main)]

extern crate alloc;

use core::future::poll_fn;
use core::task::Poll;

#[cfg(feature = "vmcall-raw")]
use alloc::format;
#[cfg(feature = "policy_v2")]
use alloc::string::String;
#[cfg(feature = "vmcall-raw")]
use alloc::vec::Vec;
use log::info;
#[cfg(feature = "vmcall-raw")]
use log::Level;
use migtd::event_log::*;
#[cfg(not(feature = "vmcall-raw"))]
use migtd::migration::data::MigrationInformation;
#[cfg(feature = "vmcall-raw")]
use migtd::migration::data::WaitForRequestResponse;
#[cfg(feature = "vmcall-raw")]
use migtd::migration::logging::*;
use migtd::migration::session::*;
use migtd::migration::MigrationResult;
use migtd::{config, event_log, migration};
use spin::Mutex;

#[cfg(feature = "AzCVMEmu")]
mod cvmemu;

const MIGTD_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(not(feature = "AzCVMEmu"))]
#[no_mangle]
pub extern "C" fn main() {
    #[cfg(feature = "test_stack_size")]
    {
        use migtd::STACK_SIZE;

        td_benchmark::StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, STACK_SIZE - 0x40000);
    }
    runtime_main()
}

// AzCVMEmu entry point - standard Rust main function
#[cfg(feature = "AzCVMEmu")]
fn main() {
    cvmemu::main();
}

pub fn runtime_main() {
    let _ = td_logger::init();

    // Create LogArea per vCPU
    #[cfg(feature = "vmcall-raw")]
    {
        let _ = create_logarea();
    }

    // Dump basic information of MigTD
    basic_info();

    // Measure the input data
    do_measurements();

    migration::event::register_callback();

    // Query the capability of VMM
    #[cfg(not(feature = "vmcall-raw"))]
    {
        if query().is_err() {
            panic!("Migration is not supported by VMM");
        }
    }

    // Handle the migration request from VMM
    handle_pre_mig();
}

fn basic_info() {
    info!("MigTD Version - {}\n", MIGTD_VERSION);
}

fn do_measurements() {
    // Get the event log recorded by firmware
    let event_log = event_log::get_event_log_mut().expect("Failed to get the event log");

    if cfg!(feature = "test_disable_ra_and_accept_all") {
        measure_test_feature(event_log);
        return;
    }

    #[cfg(feature = "policy_v2")]
    get_policy_issuer_chain_and_measure(event_log);

    // Get migration td policy from CFV and measure it into RMTR
    get_policy_and_measure(event_log);

    // Get root certificate from CFV and measure it into RMTR
    #[cfg(not(feature = "policy_v2"))]
    get_ca_and_measure(event_log);
}

fn measure_test_feature(event_log: &mut [u8]) {
    // Measure and extend the migtd test feature to RTMR
    event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_TEST_FEATURE,
        TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
        TAGGED_EVENT_ID_TEST,
        TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
    )
    .expect("Failed to log migtd test feature");
}

fn get_policy_and_measure(event_log: &mut [u8]) {
    // Read migration policy from CFV
    let policy = config::get_policy().expect("Fail to get policy from CFV\n");

    #[cfg(feature = "policy_v2")]
    let version = initialize_policy();

    #[cfg(feature = "policy_v2")]
    let event_data = version.as_bytes();

    #[cfg(not(feature = "policy_v2"))]
    let event_data = policy;

    // Measure and extend the migration policy to RTMR
    event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_POLICY,
        policy,
        TAGGED_EVENT_ID_POLICY,
        event_data,
    )
    .expect("Failed to log migration policy");
}

#[cfg(feature = "policy_v2")]
fn get_policy_issuer_chain_and_measure(event_log: &mut [u8]) {
    // Read policy issuer chain from CFV
    let policy_issuer_chain =
        config::get_policy_issuer_chain().expect("Fail to get policy issuer chain from CFV\n");

    // Measure and extend the policy issuer chain to RTMR
    event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_POLICY_ISSUER_CHAIN,
        policy_issuer_chain,
        TAGGED_EVENT_ID_POLICY_ISSUER_CHAIN,
        policy_issuer_chain,
    )
    .expect("Failed to log policy issuer chain");
}

#[cfg(not(feature = "policy_v2"))]
fn get_ca_and_measure(event_log: &mut [u8]) {
    let root_ca = config::get_root_ca().expect("Fail to get root certificate from CFV\n");

    // Measure and extend the root certificate to RTMR
    event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_ROOT_CA,
        root_ca,
        TAGGED_EVENT_ID_ROOT_CA,
        root_ca,
    )
    .expect("Failed to log SGX root CA\n");

    attestation::root_ca::set_ca(root_ca).expect("Invalid root certificate\n");
}

#[cfg(feature = "policy_v2")]
fn initialize_policy() -> String {
    use migtd::mig_policy;

    let policy = config::get_policy().expect("Fail to get policy from CFV\n");
    let policy_issuer_chain =
        config::get_policy_issuer_chain().expect("Fail to get policy issuer chain from CFV\n");
    // Initialize and verify the migration policy
    let version = mig_policy::init_policy(policy, policy_issuer_chain)
        .expect("Failed to initialize migration policy");
    // Initialize and verify the migration policy
    mig_policy::init_tcb_info().expect("Failed to initialize migration policy");

    version
}

fn handle_pre_mig() {
    const MAX_CONCURRENCY_REQUESTS: usize = 12;

    #[cfg(not(feature = "vmcall-raw"))]
    // Set by `wait_for_request` async task when getting new request from VMM.
    static PENDING_REQUEST: Mutex<Option<MigrationInformation>> = Mutex::new(None);
    #[cfg(feature = "vmcall-raw")]
    // Set by `wait_for_request` async task when getting new request from VMM.
    static PENDING_REQUEST: Mutex<Option<WaitForRequestResponse>> = Mutex::new(None);

    async_runtime::add_task(async move {
        loop {
            poll_fn(|_cx| {
                // Wait until both conditions are met:
                // 1. The pending request is taken by a new task
                // 2. We haven't reached the maximum concurrency limit
                if PENDING_REQUEST.lock().is_none() {
                    let current_requests = REQUESTS.lock().len();
                    if current_requests < MAX_CONCURRENCY_REQUESTS {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                } else {
                    Poll::Pending
                }
            })
            .await;

            if let Ok(request) = wait_for_request().await {
                *PENDING_REQUEST.lock() = Some(request);
            }
        }
    });

    loop {
        // Poll the async runtime to execute tasks
        let _ = async_runtime::poll_tasks();

        // The async task waiting for VMM response is always in the queue
        let new_request = PENDING_REQUEST.lock().take();

        if let Some(request) = new_request {
            async_runtime::add_task(async move {
                #[cfg(not(feature = "vmcall-raw"))]
                {
                    let status = exchange_msk(&request)
                        .await
                        .map(|_| MigrationResult::Success)
                        .unwrap_or_else(|e| e);

                    let _ = report_status(status as u8, request.mig_info.mig_request_id);
                    REQUESTS.lock().remove(&request.mig_info.mig_request_id);
                }
                #[cfg(feature = "vmcall-raw")]
                {
                    let mut data: Vec<u8> = Vec::new();
                    match request {
                        WaitForRequestResponse::StartMigration(wfr_info) => {
                            let status = exchange_msk(&wfr_info)
                                .await
                                .map(|_| MigrationResult::Success)
                                .unwrap_or_else(|e| e);
                            if status == MigrationResult::Success {
                                entrylog(
                                    &format!("Successfully completed key exchange\n").into_bytes(),
                                    Level::Trace,
                                    wfr_info.mig_info.mig_request_id,
                                );
                            } else {
                                entrylog(
                                    &format!(
                                        "Failure during key exchange, status code: {:x}\n",
                                        status.clone() as u8
                                    )
                                    .into_bytes(),
                                    Level::Error,
                                    wfr_info.mig_info.mig_request_id,
                                );
                            }
                            let _ = report_status(
                                status as u8,
                                wfr_info.mig_info.mig_request_id,
                                &data,
                            )
                            .await;
                            entrylog(
                                &format!("ReportStatus for key exchange completed\n").into_bytes(),
                                Level::Trace,
                                wfr_info.mig_info.mig_request_id,
                            );
                            REQUESTS.lock().remove(&wfr_info.mig_info.mig_request_id);
                        }
                        WaitForRequestResponse::GetTdReport(wfr_info) => {
                            let status = get_tdreport(
                                &wfr_info.reportdata,
                                &mut data,
                                wfr_info.mig_request_id,
                            )
                            .await
                            .map(|_| MigrationResult::Success)
                            .unwrap_or_else(|e| e);
                            if status == MigrationResult::Success {
                                entrylog(
                                    &format!("Successfully completed get TDREPORT\n").into_bytes(),
                                    Level::Trace,
                                    wfr_info.mig_request_id,
                                );
                            } else {
                                entrylog(
                                    &format!(
                                        "Failure during get TDREPORT, status code: {:x}\n",
                                        status.clone() as u8
                                    )
                                    .into_bytes(),
                                    Level::Error,
                                    wfr_info.mig_request_id,
                                );
                            }
                            let _ =
                                report_status(status as u8, wfr_info.mig_request_id, &data).await;
                            entrylog(
                                &format!("ReportStatus for get TDREPORT completed\n").into_bytes(),
                                Level::Trace,
                                wfr_info.mig_request_id,
                            );
                            REQUESTS.lock().remove(&wfr_info.mig_request_id);
                        }
                        WaitForRequestResponse::EnableLogArea(wfr_info) => {
                            let status = enable_logarea(
                                wfr_info.log_max_level,
                                wfr_info.mig_request_id,
                                &mut data,
                            )
                            .await
                            .map(|_| MigrationResult::Success)
                            .unwrap_or_else(|e| e);
                            if status == MigrationResult::Success {
                                entrylog(
                                    &format!("Successfully completed Enable LogArea\n")
                                        .into_bytes(),
                                    Level::Trace,
                                    wfr_info.mig_request_id,
                                );
                            } else {
                                entrylog(
                                    &format!(
                                        "Failure during Enable LogArea, status code: {:x}\n",
                                        status.clone() as u8
                                    )
                                    .into_bytes(),
                                    Level::Error,
                                    wfr_info.mig_request_id,
                                );
                            }
                            let _ =
                                report_status(status as u8, wfr_info.mig_request_id, &data).await;
                            entrylog(
                                &format!("ReportStatus for Enable LogArea completed\n")
                                    .into_bytes(),
                                Level::Trace,
                                wfr_info.mig_request_id,
                            );
                            REQUESTS.lock().remove(&wfr_info.mig_request_id);
                        }
                    }
                }
                #[cfg(any(feature = "test_stack_size", feature = "test_heap_size"))]
                test_memory();
            });
        }
        sleep();
    }
}

fn sleep() {
    use td_payload::arch::apic::{disable, enable_and_hlt};
    enable_and_hlt();
    disable();
}

#[cfg(test)]
fn main() {}
// FIXME: remove when https://github.com/Amanieu/minicov/issues/12 is fixed.
#[cfg(all(feature = "coverage", target_os = "none"))]
#[no_mangle]
static __llvm_profile_runtime: u32 = 0;

#[cfg(any(feature = "test_stack_size", feature = "test_heap_size"))]
fn test_memory() {
    #[cfg(feature = "test_stack_size")]
    {
        let value = td_benchmark::StackProfiling::stack_usage().unwrap();
        td_payload::println!("max stack usage: {:2x}", value);
    }
    #[cfg(feature = "test_heap_size")]
    {
        let value = td_benchmark::HeapProfiling::heap_usage().unwrap();
        td_payload::println!("max heap usage: {:2x}", value);
    }
}
