// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use std::{fs, io::Write, path::PathBuf};

use crate::collateral::Collaterals;

pub mod collateral;
pub mod pcs_client;
pub mod pcs_types;

pub fn generate_collaterals(for_production: bool, output_collateral: &PathBuf) -> Result<()> {
    let collaterals = collateral::get_collateral(for_production)?;
    write_collaterals_file(output_collateral, &collaterals)?;
    Ok(())
}

fn write_collaterals_file(collateral_output: &PathBuf, collaterals: &Collaterals) -> Result<()> {
    let mut file = fs::File::create(collateral_output)?;
    file.write_all(serde_json::to_vec(collaterals)?.as_slice())?;
    Ok(())
}
