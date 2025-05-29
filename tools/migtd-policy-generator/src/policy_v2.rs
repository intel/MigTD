use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::json;

use crate::{collateral::Collateral, pcs_types::PlatformTcb};

pub(crate) fn generate_policy(for_production: bool, collaterals: &[Collateral]) -> Result<Vec<u8>> {
    let tcb_evaluation_number =
        get_tcb_evaluation_number(collaterals.first().ok_or(anyhow!("Null collateral"))?)?;
    let global = Global {
        global_policy: GlobalPolicy {
            tcb_number: TcbNumberPolicy {
                tcb_evaluation_data_number: PolicyOperation {
                    operation: "greater-or-equal".to_string(),
                    reference: tcb_evaluation_number,
                },
                tcb_status: PolicyOperation {
                    operation: "greater-or-equal".to_string(),
                    reference: "UpToDate;ConfigurationNeeded".to_string(),
                },
            },
        },
    };
    let migtd = MigTd {
        migtd_policy: MigTdPolicy {
            migtd_identity: MigTdIdentityPolicy {
                svn: PolicyOperation {
                    operation: "greater-or-equal".to_string(),
                    reference: 0,
                },
            },
        },
    };
    let mig_policy = MigPolicy {
        id: if for_production {
            "F65CD566-4D67-45EF-88E3-79963901B292".to_string() // Production Policy GUID
        } else {
            "B87BFE45-9CC7-46F9-8F2C-A6CB55BF7101".to_string() // Pre-production Policy GUID
        },
        version: "2.0".to_string(),
        policy: vec![PolicyTypes::Global(global), PolicyTypes::Migtd(migtd)],
    };

    let mut data = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut data, formatter);
    let obj = json!(mig_policy);
    obj.serialize(&mut ser)?;
    Ok(data)
}

fn get_tcb_evaluation_number(collateral: &Collateral) -> Result<u32> {
    let platform_tcb = serde_json::from_slice::<PlatformTcb>(collateral.tcb_info())?;
    Ok(platform_tcb.tcb_info.tcb_evaluation_data_number)
}

#[derive(Debug, Serialize)]
pub struct MigPolicy {
    id: String,
    version: String,
    policy: Vec<PolicyTypes>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PolicyTypes {
    Global(Global),
    Migtd(MigTd),
}

#[derive(Debug, Serialize)]
pub struct Global {
    #[serde(rename = "Global")]
    global_policy: GlobalPolicy,
}

#[derive(Debug, Serialize)]
pub struct GlobalPolicy {
    #[serde(rename = "TcbNumber")]
    pub tcb_number: TcbNumberPolicy,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbNumberPolicy {
    pub tcb_evaluation_data_number: PolicyOperation<u32>,
    pub tcb_status: PolicyOperation<String>,
}

#[derive(Debug, Serialize)]
pub struct MigTd {
    #[serde(rename = "MigTD")]
    pub migtd_policy: MigTdPolicy,
}

#[derive(Debug, Serialize)]
pub struct MigTdPolicy {
    #[serde(rename = "MigTdIdentity")]
    pub migtd_identity: MigTdIdentityPolicy,
}

#[derive(Debug, Serialize)]
pub struct MigTdIdentityPolicy {
    #[serde(rename = "SVN")]
    pub svn: PolicyOperation<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyOperation<T> {
    pub operation: String,
    pub reference: T,
}
