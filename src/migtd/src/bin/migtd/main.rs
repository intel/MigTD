// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(feature = "AzCVMEmu"), no_std)]
#![cfg_attr(not(feature = "AzCVMEmu"), no_main)]

extern crate alloc;

use core::future::poll_fn;
use core::task::Poll;

#[cfg(feature = "policy_v2")]
use alloc::string::String;
use alloc::vec::Vec;
use log::info;
#[cfg(feature = "vmcall-raw")]
use log::{debug, Level};
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
#[cfg(feature = "vmcall-raw")]
use sha2::{Digest, Sha384};
use spin::Mutex;
#[cfg(feature = "vmcall-raw")]
use tdx_tdcall::tdreport;

#[cfg(feature = "AzCVMEmu")]
mod cvmemu;

// Local trait to convert TdInfo to bytes without external dependency
#[cfg(feature = "vmcall-raw")]
trait TdInfoAsBytes {
    fn as_bytes(&self) -> &[u8];
}
#[cfg(feature = "vmcall-raw")]
impl TdInfoAsBytes for tdreport::TdInfo {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<tdreport::TdInfo>(),
            )
        }
    }
}

#[cfg(feature = "vmcall-raw")]
fn dump_td_info_and_hash() {
    let td_report =
        match tdx_tdcall::tdreport::tdcall_report(&[0u8; tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE])
        {
            Ok(report) => report,
            Err(e) => {
                debug!("Failed to get TD report: {:?}\n", e);
                return;
            }
        };
    debug!(
        "td_report length in bytes: {}\n",
        td_report.as_bytes().len()
    );

    debug!("td_info: {:?}\n", td_report.td_info);
    let mut hasher = Sha384::new();
    hasher.update(td_report.td_info.as_bytes());

    let hash = hasher.finalize();
    debug!("TD Info Hash: {:x}\n", hash);
}

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
    #[cfg(not(feature = "vmcall-raw"))]
    {
        // Initialize logging with level filter. The actual log level is determined by
        // compile-time feature flags.
        let _ = td_logger::init(log::LevelFilter::Trace);
    }

    // Create LogArea per vCPU
    #[cfg(feature = "vmcall-raw")]
    {
        let result = init_vmm_logger();
        if result.is_err() {
            panic!("Failed to initialize VMM logger");
        }
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

    #[cfg(feature = "vmcall-raw")]
    {
        log::info!("log::max_level() = {}\n", log::max_level());
        if log::max_level() >= Level::Debug {
            dump_td_info_and_hash();
        }
    }

    // Handle the migration request from VMM
    handle_pre_mig();
}

fn basic_info() {
    info!("MigTD Version - {}\n", MIGTD_VERSION);
}

#[cfg(not(feature = "policy_v2"))]
fn do_measurements() {
    // Get the event log recorded by firmware
    let event_log = match event_log::get_event_log_mut() {
        Some(log) => log,
        None => {
            log::error!(
                "Failed to get the event log - firmware did not allocate event log buffer\n"
            );
            panic!("Failed to get the event log");
        }
    };

    if cfg!(feature = "test_disable_ra_and_accept_all") {
        measure_test_feature(event_log);
        return;
    }

    // Get migration td policy from CFV and measure it into RTMR
    get_policy_and_measure(event_log);

    // Get root certificate from CFV and measure it into RTMR
    get_ca_and_measure(event_log);
}

#[cfg(feature = "policy_v2")]
fn do_measurements() {
    // Get the event log recorded by firmware
    let event_log = match event_log::get_event_log_mut() {
        Some(log) => log,
        None => {
            log::error!(
                "Failed to get the event log - firmware did not allocate event log buffer\n"
            );
            panic!("Failed to get the event log");
        }
    };

    if cfg!(feature = "test_disable_ra_and_accept_all") {
        measure_test_feature(event_log);
        return;
    }

    get_policy_issuer_chain_and_measure(event_log);

    // Get migration td policy from CFV and measure it into RTMR
    get_policy_and_measure(event_log);
}

fn measure_test_feature(event_log: &mut [u8]) {
    // Measure and extend the migtd test feature to RTMR
    let _ = event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_TEST_FEATURE,
        TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
        TAGGED_EVENT_ID_TEST,
        TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
    )
    .map_err(|e| {
        log::error!("Failed to log migtd test feature: {:?}\n", e);
        panic!("Failed to log migtd test feature");
    });
}

#[cfg(not(feature = "policy_v2"))]
fn get_policy_and_measure(event_log: &mut [u8]) {
    // Read migration policy from CFV
    let policy = match config::get_policy() {
        Some(policy) => policy,
        None => {
            log::error!("Fail to get policy from CFV\n");
            panic!("Fail to get policy from CFV");
        }
    };

    let event_data = policy;

    // Measure and extend the migration policy to RTMR
    let _ = event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_POLICY,
        policy,
        TAGGED_EVENT_ID_POLICY,
        event_data,
    )
    .map_err(|e| {
        log::error!("Failed to log migration policy: {:?}\n", e);
        panic!("Failed to log migration policy");
    });
}

#[cfg(feature = "policy_v2")]
fn get_policy_and_measure(event_log: &mut [u8]) {
    // Read migration policy from CFV
    let policy = match config::get_policy() {
        Some(policy) => policy,
        None => {
            log::error!("Fail to get policy from CFV\n");
            panic!("Fail to get policy from CFV");
        }
    };

    let version = initialize_policy();

    let event_data = version.as_bytes();

    // Measure and extend the migration policy to RTMR
    let _ = event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_POLICY,
        policy,
        TAGGED_EVENT_ID_POLICY,
        event_data,
    )
    .map_err(|e| {
        log::error!("Failed to log migration policy: {:?}\n", e);
        panic!("Failed to log migration policy");
    });
}

#[cfg(feature = "policy_v2")]
fn get_policy_issuer_chain_and_measure(event_log: &mut [u8]) {
    // Read policy issuer chain from CFV
    let policy_issuer_chain = match config::get_policy_issuer_chain() {
        Some(policy_issuer_chain) => policy_issuer_chain,
        None => {
            log::error!("Fail to get policy issuer chain from CFV\n");
            panic!("Fail to get policy issuer chain from CFV");
        }
    };

    // Measure and extend the policy issuer chain to RTMR
    let _ = event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_POLICY_ISSUER_CHAIN,
        policy_issuer_chain,
        TAGGED_EVENT_ID_POLICY_ISSUER_CHAIN,
        policy_issuer_chain,
    )
    .map_err(|e| {
        log::error!("Failed to log policy issuer chain: {:?}\n", e);
        panic!("Failed to log policy issuer chain");
    });
}

#[cfg(not(feature = "policy_v2"))]
fn get_ca_and_measure(event_log: &mut [u8]) {
    let root_ca = match config::get_root_ca() {
        Some(policy_issuer_chain) => policy_issuer_chain,
        None => {
            log::error!("Fail to get root certificate chain from CFV\n");
            panic!("Fail to get root certificate chain from CFV");
        }
    };

    // Measure and extend the root certificate to RTMR
    let _ = event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_ROOT_CA,
        root_ca,
        TAGGED_EVENT_ID_ROOT_CA,
        root_ca,
    )
    .map_err(|e| {
        log::error!("Failed to log SGX root CA: {:?}\n", e);
        panic!("Failed to log SGX root CA");
    });

    match attestation::root_ca::set_ca(root_ca) {
        Ok(_) => (),
        Err(e) => {
            log::error!("Invalid root certificate: {:?}\n", e);
            panic!("Invalid root certificate");
        }
    }
}

#[cfg(feature = "policy_v2")]
fn initialize_policy() -> String {
    use migtd::mig_policy;

    let policy = match config::get_policy() {
        Some(policy) => policy,
        None => {
            log::error!("Fail to get policy from CFV\n");
            panic!("Fail to get policy from CFV");
        }
    };
    let policy_issuer_chain = match config::get_policy_issuer_chain() {
        Some(chain) => chain,
        None => {
            log::error!("Fail to get policy issuer chain from CFV\n");
            panic!("Fail to get policy issuer chain from CFV");
        }
    };
    // Initialize and verify the migration policy
    let version = mig_policy::init_policy(policy, policy_issuer_chain).map_err(|e| {
        log::error!("Failed to initialize migration policy: {:?}\n", e);
        panic!("Failed to initialize migration policy");
    });

    // Initialize and verify the migration policy
    let _ = mig_policy::init_tcb_info().map_err(|e| {
        log::error!("Failed to initialize migration TCB info: {:?}\n", e);
        panic!("Failed to initialize migration TCB info");
    });

    version.expect("Failed to initialize migration policy")
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
        let mut data: Vec<u8> = Vec::new();

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

                    let _ =
                        report_status(status as u8, request.mig_info.mig_request_id).map_err(|e| {
                            log::error!(
                                "Failed to report status for mig_request_id {}: {:?}\n",
                                request.mig_info.mig_request_id,
                                e
                            );
                        });
                    REQUESTS.lock().remove(&request.mig_info.mig_request_id);
                }
                #[cfg(feature = "vmcall-raw")]
                {
                    match request {
                        WaitForRequestResponse::StartMigration(wfr_info) => {
                            log::trace!(migration_request_id = wfr_info.mig_info.mig_request_id; "Processing StartMigration request\n");
                            let status = exchange_msk(&wfr_info)
                                .await
                                .map(|_| MigrationResult::Success)
                                .unwrap_or_else(|e| e);
                            if status == MigrationResult::Success {
                                log::trace!(migration_request_id = wfr_info.mig_info.mig_request_id; "Successfully completed key exchange\n");
                            } else {
                                log::error!(migration_request_id = wfr_info.mig_info.mig_request_id; "Failure during key exchange status code: {:x}\n", status.clone() as u8);
                            }
                            let _ = report_status(
                                status as u8,
                                wfr_info.mig_info.mig_request_id,
                                &data,
                            )
                            .await
                            .map_err(|e| {
                                log::error!( migration_request_id = wfr_info.mig_info.mig_request_id;
                                    "Failed to report status {:?}\n",
                                    e
                                );
                            });
                            log::trace!(migration_request_id = wfr_info.mig_info.mig_request_id; "ReportStatus for key exchange completed\n");
                            REQUESTS.lock().remove(&wfr_info.mig_info.mig_request_id);
                        }
                        #[cfg(feature = "policy_v2")]
                        WaitForRequestResponse::StartRebinding(rebinding_info) => {
                            use migtd::migration::rebinding::start_rebinding;

                            log::trace!(migration_request_id = rebinding_info.mig_request_id; "Processing StartRebinding request\n");
                            let status = start_rebinding(&rebinding_info, &mut data)
                                .await
                                .map(|_| MigrationResult::Success)
                                .unwrap_or_else(|e| e);
                            if status == MigrationResult::Success {
                                log::trace!("Successfully completed key exchange\n");
                                log::trace!(
                                    migration_request_id = rebinding_info.mig_request_id; "Successfully completed rebinding\n",
                                );
                            } else {
                                log::error!(
                                    migration_request_id = rebinding_info.mig_request_id; "Failure during rebinding status code: {:x}\n", status.clone() as u8);
                            }
                            let _ =
                                report_status(status as u8, rebinding_info.mig_request_id, &data)
                                    .await
                                    .map_err(|e| {
                                        log::error!(
                                            migration_request_id = rebinding_info.mig_request_id;
                                            "Failed to report status for StartRebinding: {:?}\n",
                                            e
                                        );
                                    });
                            log::trace!(
                                migration_request_id = rebinding_info.mig_request_id;
                                "ReportStatus for rebinding completed\n"
                            );
                            REQUESTS.lock().remove(&rebinding_info.mig_request_id);
                        }
                        WaitForRequestResponse::GetTdReport(wfr_info) => {
                            log::trace!(migration_request_id = wfr_info.mig_request_id; "Processing GetTdReport request\n");
                            let status = get_tdreport(
                                &wfr_info.reportdata,
                                &mut data,
                                wfr_info.mig_request_id,
                            )
                            .await
                            .map(|_| MigrationResult::Success)
                            .unwrap_or_else(|e| e);
                            if status == MigrationResult::Success {
                                log::trace!(migration_request_id = wfr_info.mig_request_id; "Successfully completed get TDREPORT\n");
                            } else {
                                log::error!(migration_request_id = wfr_info.mig_request_id; "Failure during get TDREPORT status code: {:x}\n", status.clone() as u8);
                            }
                            let _ =
                                report_status(status as u8, wfr_info.mig_request_id, &data).await;
                            log::trace!(migration_request_id = wfr_info.mig_request_id; "ReportStatus for get TDREPORT completed.\n");
                            REQUESTS.lock().remove(&wfr_info.mig_request_id);
                        }
                        WaitForRequestResponse::EnableLogArea(wfr_info) => {
                            log::trace!(migration_request_id = wfr_info.mig_request_id; "Processing EnableLogArea request\n");
                            let status = enable_logarea(
                                wfr_info.log_max_level,
                                wfr_info.mig_request_id,
                                &mut data,
                            )
                            .await
                            .map(|_| MigrationResult::Success)
                            .unwrap_or_else(|e| e);

                            log::info!( migration_request_id = wfr_info.mig_request_id;
                                "Setting log level to {}\n",
                                wfr_info.log_max_level
                            );
                            log::set_max_level(u8_to_levelfilter(wfr_info.log_max_level));

                            if status == MigrationResult::Success {
                                log::trace!(migration_request_id = wfr_info.mig_request_id; "Successfully completed Enable LogArea\n");
                            } else {
                                log::error!(migration_request_id = wfr_info.mig_request_id; "Failure during Enable LogArea status code: {:x}\n", status.clone() as u8);
                            }
                            let _ = report_status(status as u8, wfr_info.mig_request_id, &data)
                                .await
                                .map_err(|e| {
                                    log::error!( migration_request_id = wfr_info.mig_request_id;
                                        "Failed to report status for Enable LogArea {:?}\n",
                                        e
                                    );
                                });
                            log::trace!(migration_request_id = wfr_info.mig_request_id; "ReportStatus for Enable LogArea completed\n");
                            REQUESTS.lock().remove(&wfr_info.mig_request_id);
                        }
                        #[cfg(feature = "policy_v2")]
                        WaitForRequestResponse::GetMigtdData(wfr_info) => {
                            log::trace!(migration_request_id = wfr_info.mig_request_id; "Processing GetMigtdData request\n");
                            let status = get_migtd_data(
                                &wfr_info.reportdata,
                                &mut data,
                                wfr_info.mig_request_id,
                            )
                            .await
                            .map(|_| MigrationResult::Success)
                            .unwrap_or_else(|e| e);
                            if status == MigrationResult::Success {
                                log::trace!(migration_request_id = wfr_info.mig_request_id; "Successfully completed get migtd data\n");
                            } else {
                                log::error!(migration_request_id = wfr_info.mig_request_id; "Failure during get migtd data status code: {:x}\n", status.clone() as u8);
                            }
                            let _ =
                                report_status(status as u8, wfr_info.mig_request_id, &data).await;
                            log::trace!(migration_request_id = wfr_info.mig_request_id; "ReportStatus for get migtd data completed.\n");
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
