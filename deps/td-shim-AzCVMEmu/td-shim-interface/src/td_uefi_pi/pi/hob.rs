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

//! Hand-off Block (HOB) minimal stubs for Azure CVM environment
//!
//! When using AzCVMEmu with vmcall-raw, HOB emulation is not required.
//! This module provides minimal stubs that satisfy compilation requirements only.

// Re-export types from parent module
pub use super::super::hob::{GuidExtension, Header};

// Re-export constants from parent module
pub use super::super::hob::{
    HOB_TYPE_END_OF_HOB_LIST, HOB_TYPE_GUID_EXTENSION, HOB_TYPE_RESOURCE_DESCRIPTOR,
};
