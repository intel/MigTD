use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[allow(unused)]
#[derive(Deserialize)]
struct MmioConfig {
    #[serde(rename = "Mmio32Start", deserialize_with = "from_hex_str")]
    mmio32_start: u64,
    #[serde(rename = "Mmio32Size", deserialize_with = "from_hex_str")]
    mmio32_size: u64,
    #[serde(rename = "PcieConfigBaseAddress", deserialize_with = "from_hex_str")]
    pcie_config_base: u64,
    #[serde(rename = "PcieConfigSize", deserialize_with = "from_hex_str")]
    pcie_config_size: u64,
    #[serde(rename = "Mmio64Start", deserialize_with = "from_hex_str")]
    mmio64_start: u64,
    #[serde(rename = "Mmio64Size", deserialize_with = "from_hex_str")]
    mmio64_size: u64,
}

fn from_hex_str<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(serde::de::Error::custom)
}

pub fn generate_mmio_config(json_path: &PathBuf, output_path: &PathBuf) -> Result<()> {
    let json_content = fs::read_to_string(json_path)?;
    let config: MmioConfig = serde_json::from_str(&json_content)?;

    if !is_mmio_config_valid(&config) {
        return Err(anyhow!("Invalid MMIO configuration"));
    }

    let rust_code = format!(
        "// Copyright (c) 2024 Intel Corporation\n\
         //\n\
         // SPDX-License-Identifier: BSD-2-Clause-Patent\n\
         \n\
         pub const MMIO32_START: u32 = 0x{:X};\n\
         pub const MMIO32_SIZE: u32 = 0x{:X};\n\
         pub const PCI_EX_BAR_BASE_ADDRESS: u64 = 0x{:X};\n\
         pub const PCI_EX_BAR_SIZE: u64 = 0x{:X};\n\
         pub const MMIO64_START: u64 = 0x{:X};\n\
         pub const MMIO64_SIZE: u64 = 0x{:X};\n",
        config.mmio32_start,
        config.mmio32_size,
        config.pcie_config_base,
        config.pcie_config_size,
        config.mmio64_start,
        config.mmio64_size,
    );

    let mut file = File::create(output_path)?;
    file.write_all(rust_code.as_bytes())?;
    Ok(())
}

fn is_mmio_config_valid(config: &MmioConfig) -> bool {
    // Checks if the MMIO32 values are valid
    if config.mmio32_size > u32::MAX as u64
        || config
            .mmio32_start
            .checked_add(config.mmio32_size)
            .is_none_or(|sum| sum > u32::MAX as u64)
    {
        return false;
    }

    // Ensure that the PCIe config range does not overlap with the MMIO32 space.
    if config.pcie_config_base < (config.mmio32_start + config.mmio32_size) as u64
        && config.pcie_config_base + config.pcie_config_size > config.mmio32_start as u64
    {
        return false;
    }

    // Ensure that the MMIO64 range does not overlap with the MMIO32 space.
    if config.mmio64_start <= u32::MAX as u64 {
        return false;
    }

    // Ensure that the MMIO64 range does not overlap with the PCIe space.
    if config.mmio64_start < config.pcie_config_base + config.pcie_config_size
        && config.mmio64_start + config.mmio64_size > config.pcie_config_base
    {
        return false;
    }

    true
}
