// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::{fs, path::PathBuf};

use anyhow::Result;
use collateral::Collateral;

pub mod collateral;
pub mod pcs_client;
pub mod pcs_types;
pub mod policy;
pub mod policy_v2;

pub fn generate_policy_v1(for_production: bool, output_policy: &PathBuf) -> Result<()> {
    let policy = policy::generate_policy(for_production)?;
    fs::write(output_policy, &policy)?;
    Ok(())
}

pub fn generate_policy_v2(
    for_production: bool,
    output_policy: &PathBuf,
    output_collateral: &PathBuf,
) -> Result<()> {
    let collaterals = collateral::get_collateral(for_production)?;
    let policy = policy_v2::generate_policy(for_production, &collaterals)?;
    write_collaterals_file(output_collateral, &collaterals)?;
    fs::write(output_policy, &policy)?;
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
