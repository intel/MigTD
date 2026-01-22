// Copyright (c) 2022-2025 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! AzCVMEmu-specific code for running MigTD in a standard Rust environment

#![cfg(feature = "AzCVMEmu")]

use std::env;
use std::process;

use alloc::vec::Vec;
use migtd;
use migtd::migration::event;
use migtd::migration::logging::{create_logarea, enable_logarea, init_vmm_logger};
use migtd::migration::session::{exchange_msk, report_status};
use migtd::migration::{MigrationResult, MigtdMigrationInformation};

use tdx_tdcall_emu::tdreport_emu::tdcall_report_emulated;
use tdx_tdcall_emu::tdx_emu::{set_emulated_get_report_data, set_emulated_start_migration};
use tdx_tdcall_emu::{init_tcp_emulation_with_mode, start_tcp_server_sync, TcpEmulationMode};

// Import shared functions from main.rs
use crate::{basic_info, do_measurements};

/// AzCVMEmu entry point - standard Rust main function
pub fn main() {
    // Initialize VMM logger (outputs to console via td-logger-emu in AzCVMEmu mode)
    let result = init_vmm_logger();
    if result.is_err() {
        panic!("Failed to initialize VMM logger");
    }

    // Init internal heap
    #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
    attestation::attest_init_heap();

    // Initialize event log emulation
    td_shim_emu::event_log::init_event_log();
    // Parse command line arguments first so `-h` works without env vars/files
    parse_commandline_args();
    // Initialize emulation layer (requires env vars/files); skipped if `-h` exited
    initialize_emulation();

    // Continue with the main runtime flow and exit with the returned code
    let exit_code = runtime_main_emu();
    process::exit(exit_code);
}

/// Initialize emulation layer
fn initialize_emulation() {
    // Get file paths from environment variables
    let policy_file_path = match env::var("MIGTD_POLICY_FILE") {
        Ok(path) => {
            log::info!("MIGTD_POLICY_FILE set to: {}\n", path);
            path
        }
        Err(_) => {
            println!("MIGTD_POLICY_FILE environment variable not set");
            print_usage();
            process::exit(1);
        }
    };

    let root_ca_file_path = match env::var("MIGTD_ROOT_CA_FILE") {
        Ok(path) => {
            log::info!("MIGTD_ROOT_CA_FILE set to: {}\n", path);
            path
        }
        Err(_) => {
            println!("MIGTD_ROOT_CA_FILE environment variable not set");
            print_usage();
            process::exit(1);
        }
    };

    // Check if files exist before attempting to initialize
    if !std::path::Path::new(&policy_file_path).exists() {
        println!("Policy file not found: {}", policy_file_path);
        print_usage();
        process::exit(1);
    }

    if !std::path::Path::new(&root_ca_file_path).exists() {
        println!("Root CA file not found: {}", root_ca_file_path);
        print_usage();
        process::exit(1);
    }

    // Initialize file-based emulation with real file access
    // Convert strings to static references by leaking them (required by the API)
    let policy_path: &'static str = Box::leak(policy_file_path.clone().into_boxed_str());
    let root_ca_path: &'static str = Box::leak(root_ca_file_path.clone().into_boxed_str());

    #[cfg(feature = "policy_v2")]
    let result = {
        let policy_issuer_chain_file_path = env::var("MIGTD_POLICY_ISSUER_CHAIN_FILE")
            .map_err(|_| {
                log::error!("Policy v2 requires a policy issuer chain file but MIGTD_POLICY_ISSUER_CHAIN_FILE was not set\n");
            })
            .unwrap_or_else(|_| process::exit(1));

        log::info!(
            "MIGTD_POLICY_ISSUER_CHAIN_FILE set to: {}\n",
            policy_issuer_chain_file_path
        );

        // Verify chain file exists
        if !std::path::Path::new(&policy_issuer_chain_file_path).exists() {
            println!(
                "Policy issuer chain file not found: {}",
                policy_issuer_chain_file_path
            );
            print_usage();
            process::exit(1);
        }

        // Initialize with policy chain
        let chain_path_static: &'static str =
            Box::leak(policy_issuer_chain_file_path.into_boxed_str());
        td_shim_interface_emu::init_file_based_emulation_with_policy_chain(
            policy_path,
            root_ca_path,
            chain_path_static,
        )
    };

    #[cfg(not(feature = "policy_v2"))]
    let result = {
        td_shim_interface_emu::init_file_based_emulation_with_real_files(policy_path, root_ca_path)
    };

    if result {
        log::info!("File-based emulation initialized with real file access. Files will be loaded on demand from:\n");
        log::info!("  Policy: {}\n", policy_file_path);
        log::info!("  Root CA: {}\n", root_ca_file_path);

        #[cfg(feature = "policy_v2")]
        {
            let chain_file = env::var("MIGTD_POLICY_ISSUER_CHAIN_FILE").ok();
            log::info!("  Policy Issuer Chain: {:?}\n", chain_file);
        }
    } else {
        log::error!("Failed to initialize file-based emulation\n");
        std::process::exit(1);
    }
}

/// Main runtime function for AzCVMEmu mode
fn runtime_main_emu() -> i32 {
    // Create LogArea per vCPU
    match create_logarea() {
        Ok(_) => log::info!("LogArea created successfully\n"),
        Err(e) => log::error!("Failed to create logarea: {}\n", e as u8),
    }

    // Dump basic information of MigTD (reusing from main.rs)
    basic_info();

    // Perform measurements (reusing from main.rs)
    do_measurements();

    // Register callback
    event::register_callback();

    // Handle pre-migration for emulation mode and return exit code
    handle_pre_mig_emu()
}

fn parse_commandline_args() {
    let args: Vec<String> = env::args().collect();

    // Default values
    let mut mig_request_id = 1;
    let mut is_source = true;
    let mut target_td_uuid = [1, 2, 3, 4];
    let mut binding_handle = 0x1234;
    let mut destination_ip: Option<String> = None;
    let mut destination_port: Option<u16> = None;
    let mut help_requested = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--request-id" | "-r" if i + 1 < args.len() => {
                if let Ok(id) = args[i + 1].parse::<u64>() {
                    mig_request_id = id;
                    i += 2;
                } else {
                    println!("Invalid request ID value: {}", args[i + 1]);
                    print_usage();
                    process::exit(1);
                }
            }
            "--role" | "-m" if i + 1 < args.len() => match args[i + 1].to_lowercase().as_str() {
                "source" | "src" => {
                    is_source = true;
                    i += 2;
                }
                "destination" | "dst" | "target" => {
                    is_source = false;
                    i += 2;
                }
                _ => {
                    println!(
                        "Invalid role value: {}. Use 'source' or 'destination'",
                        args[i + 1]
                    );
                    print_usage();
                    process::exit(1);
                }
            },
            "--uuid" | "-u" if i + 4 < args.len() => {
                if let (Ok(u1), Ok(u2), Ok(u3), Ok(u4)) = (
                    args[i + 1].parse::<u32>(),
                    args[i + 2].parse::<u32>(),
                    args[i + 3].parse::<u32>(),
                    args[i + 4].parse::<u32>(),
                ) {
                    target_td_uuid = [u1, u2, u3, u4];
                    i += 5;
                } else {
                    println!("Invalid UUID values. Expected 4 unsigned integers");
                    print_usage();
                    process::exit(1);
                }
            }
            "--binding" | "-b" if i + 1 < args.len() => {
                // Try to parse as hex (with 0x prefix) or decimal
                let handle_result =
                    if args[i + 1].starts_with("0x") || args[i + 1].starts_with("0X") {
                        u64::from_str_radix(&args[i + 1][2..], 16)
                    } else {
                        args[i + 1].parse::<u64>()
                    };

                if let Ok(handle) = handle_result {
                    binding_handle = handle;
                    i += 2;
                } else {
                    println!("Invalid binding handle value: {}", args[i + 1]);
                    print_usage();
                    process::exit(1);
                }
            }
            "--dest-ip" | "-d" if i + 1 < args.len() => {
                destination_ip = Some(args[i + 1].clone());
                i += 2;
            }
            "--dest-port" | "-t" if i + 1 < args.len() => {
                if let Ok(port) = args[i + 1].parse::<u16>() {
                    destination_port = Some(port);
                    i += 2;
                } else {
                    println!("Invalid destination port value: {}", args[i + 1]);
                    print_usage();
                    process::exit(1);
                }
            }
            "--help" | "-h" => {
                help_requested = true;
                i += 1;
            }
            _ => {
                println!("Unknown argument: {}", args[i]);
                help_requested = true;
                i += 1;
            }
        }
    }

    if help_requested {
        print_usage();
        std::process::exit(0);
    }

    // Create migration information using the same pattern as in data.rs
    let mig_info = unsafe {
        // Create a zero-initialized structure and then set the fields
        let mut info: MigtdMigrationInformation = core::mem::zeroed();
        info.mig_request_id = mig_request_id;
        info.migration_source = if is_source { 1 } else { 0 };
        info.target_td_uuid = [
            target_td_uuid[0] as u64,
            target_td_uuid[1] as u64,
            target_td_uuid[2] as u64,
            target_td_uuid[3] as u64,
        ];
        info.binding_handle = binding_handle;
        // Note: mig_policy_id and communication_id don't exist when vmcall-raw feature is enabled
        info
    };

    log::info!("Migration information:\n");
    log::info!("  Request ID: {}\n", mig_request_id);
    log::info!(
        "  Role: {}",
        if is_source { "Source" } else { "Destination" }
    );
    log::info!("  Target TD UUID: {:?}\n", target_td_uuid);
    log::info!("  Binding Handle: {:#x}\n", binding_handle);

    if let Some(ip) = &destination_ip {
        log::info!("  Destination IP: {}\n", ip);
    }
    if let Some(port) = destination_port {
        log::info!("  Destination Port: {}\n", port);
    }

    // Determine IP and port (either from command line or use defaults)
    let tcp_ip = destination_ip.as_deref().unwrap_or("127.0.0.1");
    let tcp_port = destination_port.unwrap_or(8001);

    // Configure TCP emulation mode
    let mode = if is_source {
        TcpEmulationMode::Client
    } else {
        TcpEmulationMode::Server
    };

    // Initialize TCP emulation
    if let Err(e) = init_tcp_emulation_with_mode(tcp_ip, tcp_port, mode) {
        log::error!("Failed to initialize TCP emulation: {}\n", e);
        std::process::exit(1);
    }

    // Handle connection logic based on role
    if !is_source {
        // Destination mode: start TCP server
        let addr = format!("{}:{}", tcp_ip, tcp_port);
        match start_tcp_server_sync(&addr) {
            Ok(_) => {
                log::info!("TCP server started successfully on: {}\n", addr);
            }
            Err(e) => {
                log::error!("Failed to start TCP server: {:?}\n", e);
                std::process::exit(1);
            }
        }
    } else {
        // Source mode: connect to destination server
        let addr = format!("{}:{}", tcp_ip, tcp_port);

        // For source mode, establish the TCP client connection
        use tdx_tdcall_emu::tdx_emu::connect_tcp_client;
        match connect_tcp_client() {
            Ok(_) => {
                log::info!(
                    "Successfully connected to destination server at: {}\n",
                    addr
                );
            }
            Err(e) => {
                log::error!(
                    "Failed to connect to destination server at {}: {:?}\n",
                    addr,
                    e
                );
                std::process::exit(1);
            }
        }
    }

    // Queue all three requests: EnableLogArea → GetReportData → StartMigration
    log::info!("Setting up migration flow (EnableLogArea → GetReportData → StartMigration)\n");
    set_emulated_start_migration(
        mig_info.mig_request_id,
        mig_info.migration_source as u8,
        mig_info.target_td_uuid,
        mig_info.binding_handle,
    );
}

fn print_usage() {
    println!("MigTD AzCVMEmu Mode Usage:");
    println!();
    println!("Required Environment Variables:");
    println!("  MIGTD_POLICY_FILE          Path to the migration policy file");
    println!("  MIGTD_ROOT_CA_FILE         Path to the root CA certificate file");
    println!("  MIGTD_POLICY_ISSUER_CHAIN_FILE Path to the policy issuer certificate chain file");
    println!("  Note: Accessing a vTPM (e.g., /dev/tpmrm0) may require sudo or proper device permissions.");
    println!("        If using TPM2-TSS, you may need to export TSS2_TCTI=device:/dev/tpmrm0");
    println!();
    println!("Command Line Options:");
    println!("  --request-id, -r ID        Set migration request ID (default: 1)");
    println!(
        "  --role, -m ROLE            Set role as 'source' or 'destination' (default: source)"
    );
    println!("  --uuid, -u U1 U2 U3 U4     Set target TD UUID as four integers (default: 1 2 3 4)");
    println!("  --binding, -b HANDLE       Set binding handle as hex or decimal (default: 0x1234)");
    println!("  --dest-ip, -d IP           Set destination IP address for connection (default: 127.0.0.1)");
    println!("  --dest-port, -t PORT       Set destination port for connection (default: 8001)");
    println!("  --help, -h                 Show this help message");
    println!();
    println!("Examples:");
    println!("  export MIGTD_POLICY_FILE=config/policy.json");
    println!("  export MIGTD_ROOT_CA_FILE=config/Intel_SGX_Provisioning_Certification_RootCA.cer");
    println!();
    println!("  # Migration (automatically includes EnableLogArea and GetReportData):");
    println!("  ./migtd --role source --request-id 42");
    println!("  ./migtd -m destination -r 42 -b 0x5678");
    println!("  ./migtd --role source --dest-ip 192.168.1.100 --dest-port 8001");
}

fn handle_pre_mig_emu() -> i32 {
    // For AzCVMEmu, create an async runtime and run the standard flow
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // Process requests in sequence: EnableLogArea → GetReportData → StartMigration
    let exit_code: i32 = rt.block_on(async move {
        loop {
            match migtd::migration::session::wait_for_request().await {
                Ok(response) => {
                    use migtd::migration::data::WaitForRequestResponse;

                    match response {
                        WaitForRequestResponse::EnableLogArea(wfr_info) => {
                            log::info!("Processing EnableLogArea request\n");
                            let mut data = Vec::new();
                            let status = enable_logarea(
                                wfr_info.log_max_level,
                                wfr_info.mig_request_id,
                                &mut data,
                            )
                            .await
                            .map(|_| MigrationResult::Success)
                            .unwrap_or_else(|e| e);

                            if status == MigrationResult::Success {
                                log::info!("Successfully completed Enable LogArea\n");
                            } else {
                                log::error!(
                                    "Failure during Enable LogArea, status code: {:x}\n",
                                    status as u8
                                );
                            }

                            let _ =
                                report_status(status as u8, wfr_info.mig_request_id, &data).await;
                            log::info!("ReportStatus for Enable LogArea completed\n");
                            // Continue to process next request
                        }
                        WaitForRequestResponse::StartMigration(req) => {
                            log::info!("Processing StartMigration request\n");
                            let mut data = Vec::new();

                            // Call exchange_msk() and log its immediate outcome
                            let res = exchange_msk(&req, &mut data).await;
                            match &res {
                                Ok(_) => log::info!("exchange_msk() returned Ok\n"),
                                Err(e) => {
                                    log::error!("exchange_msk() returned error code {}\n", *e as u8)
                                }
                            }
                            let status =
                                res.map(|_| MigrationResult::Success).unwrap_or_else(|e| e);

                            // Derive a numeric code without moving `status`
                            let status_code_u8 = status as u8;

                            // Report status back via vmcall-raw emulation
                            let empty_data = Vec::new();
                            if let Err(e) = report_status(
                                status_code_u8,
                                req.mig_info.mig_request_id,
                                &empty_data,
                            )
                            .await
                            {
                                log::error!("report_status failed with code {}\n", e as u8);
                            } else {
                                log::info!("report_status completed successfully\n");
                            }

                            if status_code_u8 == MigrationResult::Success as u8 {
                                log::info!("Migration key exchange successful!\n");
                                return 0;
                            } else {
                                let status_code = status_code_u8 as i32;
                                log::error!(
                                    "Migration key exchange failed with code: {}\n",
                                    status_code
                                );
                                return status_code;
                            }
                        }
                        WaitForRequestResponse::GetTdReport(report_info) => {
                            log::info!("Processing GetReportData request\n");
                            log::info!("  Request ID: {}\n", report_info.mig_request_id);
                            log::info!(
                                "  ReportData (first 32 bytes): {:02x?}\n",
                                &report_info.reportdata[0..32]
                            );

                            // Generate TD report using the reportdata
                            log::info!("Generating TD report with vTPM interface\n");

                            let (status_code_u8, report_data) =
                                match tdcall_report_emulated(&report_info.reportdata) {
                                    Ok(td_report) => {
                                        log::info!("TD report generated successfully\n");

                                        // Convert the TD report to bytes
                                        let report_bytes = unsafe {
                                            core::slice::from_raw_parts(
                                                &td_report as *const _ as *const u8,
                                                core::mem::size_of_val(&td_report),
                                            )
                                        };

                                        log::info!(
                                            "TD report size: {} bytes\n",
                                            report_bytes.len()
                                        );
                                        log::info!(
                                            "TD report (first 32 bytes): {:02x?}\n",
                                            &report_bytes[0..32]
                                        );

                                        // Return success with the TD report as data
                                        (MigrationResult::Success as u8, report_bytes.to_vec())
                                    }
                                    Err(e) => {
                                        log::error!("Failed to generate TD report: {:?}\n", e);
                                        (MigrationResult::TdxModuleError as u8, Vec::new())
                                    }
                                };

                            if let Err(e) = report_status(
                                status_code_u8,
                                report_info.mig_request_id,
                                &report_data,
                            )
                            .await
                            {
                                log::error!("report_status failed with code {}\n", e as u8);
                            } else {
                                if status_code_u8 == MigrationResult::Success as u8 {
                                    log::info!("GetReportData request completed successfully\n");
                                } else {
                                    log::error!(
                                        "GetReportData request failed with status {}\n",
                                        status_code_u8
                                    );
                                }
                            }
                            // Continue to process next request (migration)
                        }
                    }
                }
                Err(e) => {
                    let status_code = e as u8 as i32;
                    log::error!("wait_for_request failed with code: {}\n", status_code);
                    return status_code;
                }
            }
        }
    });

    exit_code
}
