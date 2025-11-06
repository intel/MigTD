// Copyright © 2019 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Hand-off Block (HOB) emulation for Azure CVM environment
//!
//! When using AzCVMEmu with vmcall-raw, HOB emulation is not required.
//! This module provides minimal stubs that satisfy compilation requirements only.

// These types are kept minimal since they're not actually used in AzCVMEmu+vmcall-raw mode
// but are needed for compilation

/// HOB Header stub
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Header {
    pub r#type: u16,
    pub length: u16,
    pub reserved: u32,
}

/// GUID Extension HOB stub
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct GuidExtension {
    pub header: Header,
    pub name: [u8; 16],
}

// Minimal stubs of constants for HOB functionality
pub const HOB_TYPE_END_OF_HOB_LIST: u16 = 0xffff;
pub const HOB_TYPE_GUID_EXTENSION: u16 = 0x0004;
pub const HOB_TYPE_RESOURCE_DESCRIPTOR: u16 = 0x0003;

// These functions are stubs and aren't actually used in AzCVMEmu+vmcall-raw mode

/// Stub implementation of the align_to_next_hob_offset function
pub fn align_to_next_hob_offset(_cap: usize, _offset: usize, _length: u16) -> Option<usize> {
    None
}

/// Stub implementation of the get_guid_data function
pub fn get_guid_data(_guided_hob: &[u8]) -> Option<&[u8]> {
    None
}
