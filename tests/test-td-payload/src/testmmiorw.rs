// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use alloc::string::String;
use core::ffi::c_void;
use pci::PciCommand;
use td_payload::print;
use test_td_payload::{TestCase, TestResult};

use serde::{Deserialize, Serialize};

pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
pub const VIRTIO_PCI_DEVICE_ID: u16 = 0x1053;

/**
 * Test tdvmcall mmio read/write
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct Tdmmiorw {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Implement the TestCase trait for Tdmmiorw
 */
impl TestCase for Tdmmiorw {
    /**
     * set up the Test case of Tdmmiorw
     */
    fn setup(&mut self) {
        self.result = TestResult::Fail;
    }

    /**
     * run the test case
     * mmio read/write vsock device
     */
    fn run(&mut self) {
        let pci_device = if let Some((bus, device, func)) =
            pci::find_device(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_ID)
        {
            pci::PciDevice::new(bus, device, func)
        } else {
            print!("device not found\n");
            return;
        };

        let mut command = pci_device.read_u16(0x4);
        print!("Frist time read command is: {}\n", command);

        command |= PciCommand::NTERRUPT_DISABLE.bits();
        pci_device.write_u16(0x4, command);

        let command2 = pci_device.read_u16(0x4);
        print!("Second time read command is: {}\n", command2);

        if (command2 != command) {
            print!(
                "Second time value is not equal with the first time value + 1 - Expected {:?}: Actual {:?}\n",
                command,
                command2
            );
            return;
        }
        self.result = TestResult::Pass;
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
