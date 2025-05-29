// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use serde::Serialize;

use super::{Property, Reference};
use crate::pcs_types::QeInfo;

pub fn create_qe_identity_policy(qe_identity: &[u8]) -> Result<QePolicy> {
    let qe_info = serde_json::from_slice::<QeInfo>(qe_identity)?;
    Ok(QePolicy::new(
        qe_info.enclave_identity.miscselect,
        qe_info.enclave_identity.attributes,
        qe_info.enclave_identity.mrsigner,
        qe_info.enclave_identity.isvprodid,
        qe_info.enclave_identity.tcb_levels[0].tcb.isvsvn,
    ))
}

#[derive(Debug, Serialize)]
pub struct QePolicy {
    #[serde(rename = "QE")]
    qe_info: QeInfoPolicy,
}

impl QePolicy {
    pub fn new(
        miscselect: String,
        attributes: String,
        mrsigner: String,
        isvprodid: u64,
        isvsvn: u64,
    ) -> Self {
        Self {
            qe_info: QeInfoPolicy {
                qe_identity: QeIdentityPolicy {
                    miscselect: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Str(miscselect),
                    },
                    attributes: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Str(attributes),
                    },
                    mrsigner: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Str(mrsigner),
                    },
                    isvprodid: Property {
                        operation: "equal".to_string(),
                        reference: Reference::Integer(isvprodid),
                    },
                    isvsvn: Property {
                        operation: "greater-or-equal".to_string(),
                        reference: Reference::Integer(isvsvn),
                    },
                },
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct QeInfoPolicy {
    #[serde(rename = "QeIdentity")]
    qe_identity: QeIdentityPolicy,
}

#[derive(Debug, Serialize)]
pub struct QeIdentityPolicy {
    #[serde(rename = "MISCSELECT")]
    miscselect: Property,
    #[serde(rename = "ATTRIBUTES")]
    attributes: Property,
    #[serde(rename = "MRSIGNER")]
    mrsigner: Property,
    #[serde(rename = "ISVPRODID")]
    isvprodid: Property,
    #[serde(rename = "ISVSVN")]
    isvsvn: Property,
}
