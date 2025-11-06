// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! ACPI emulation for td-shim-interface-emu
//! Provides minimal ACPI types needed by migtd

use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[repr(C, packed)]
#[derive(Default, AsBytes, FromBytes, FromZeroes, Copy, Clone)]
pub struct GenericSdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

impl GenericSdtHeader {
    pub fn new(signature: &[u8; 4], length: u32, revision: u8) -> Self {
        Self {
            signature: *signature,
            length,
            revision,
            checksum: 0,
            oem_id: *b"INTEL ",
            oem_table_id: *b"EMULATED",
            oem_revision: 1,
            creator_id: u32::from_le_bytes(*b"EMUL"),
            creator_revision: 1,
        }
    }

    pub fn set_checksum(&mut self, checksum: u8) {
        self.checksum = checksum;
    }
}

#[repr(C, packed)]
#[derive(Default, AsBytes, FromBytes, FromZeroes, Copy, Clone)]
pub struct Ccel {
    pub header: GenericSdtHeader,
    pub cc_type: u8,
    pub cc_subtype: u8,
    pub reserved: u16,
    pub laml: u64,
    pub lasa: u64,
}

impl Ccel {
    pub fn new(cc_type: u8, cc_subtype: u8, laml: u64, lasa: u64) -> Ccel {
        let mut ccel = Ccel {
            header: GenericSdtHeader::new(b"CCEL", core::mem::size_of::<Ccel>() as u32, 1),
            cc_type,
            cc_subtype,
            reserved: 0,
            laml,
            lasa,
        };
        ccel.checksum();
        ccel
    }

    pub fn checksum(&mut self) {
        self.header.checksum = 0;
        self.header
            .set_checksum(calculate_checksum(self.as_bytes()));
    }
}

pub fn calculate_checksum(data: &[u8]) -> u8 {
    (255 - data.iter().fold(0u8, |acc, x| acc.wrapping_add(*x))).wrapping_add(1)
}
