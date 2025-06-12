// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::{fs, path::PathBuf};

use anyhow::Result;
use collateral::Collateral;

pub mod collateral;
pub mod pcs_client;
pub mod pcs_types;

pub fn generate_collaterals(for_production: bool, output_collateral: &PathBuf) -> Result<()> {
    let collaterals = collateral::get_collateral(for_production)?;
    write_collaterals_file(output_collateral, &collaterals)?;
    Ok(())
}

fn write_collaterals_file(
    collateral_output: &PathBuf,
    collaterals: &Vec<Collateral>,
) -> Result<()> {
    let mut file = fs::File::create(collateral_output)?;
    for collateral in collaterals {
        collateral.write_to_writer(&mut file)?;
    }
    Ok(())
}
