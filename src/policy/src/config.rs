// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{collections::BTreeMap, fmt::Write, string::String, vec::Vec};
use core::{mem::size_of, ops, str::FromStr};
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer,
};
use td_shim_interface::td_uefi_pi::pi::guid::Guid;

#[derive(Debug, Deserialize)]
pub struct MigPolicy {
    #[serde(rename = "id", with = "guid_serde")]
    pub _id: Guid,
    #[serde(rename = "policy")]
    pub blocks: Vec<Policy>,
}

impl MigPolicy {
    pub fn get_platform_info_policy(&self) -> Vec<&PlatformInfo> {
        self.blocks
            .iter()
            .filter_map(|p| match p {
                Policy::Platform(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    pub fn get_qe_info_policy(&self) -> Option<&QeInfo> {
        self.blocks.iter().find_map(|p| match p {
            Policy::Qe(q) => Some(q),
            _ => None,
        })
    }

    pub fn get_migtd_info_policy(&self) -> Option<&MigTdInfo> {
        self.blocks.iter().find_map(|p| match p {
            Policy::Migtd(m) => Some(m),
            _ => None,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Policy {
    Platform(PlatformInfo),
    Qe(QeInfo),
    TdxModule(TdxModuleInfo),
    Migtd(MigTdInfo),
}

#[derive(Debug, Deserialize)]
pub struct PlatformInfo {
    pub(crate) fmspc: String,
    #[serde(rename = "Platform")]
    pub(crate) platform: Platform,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Platform {
    #[serde(rename = "TcbInfo")]
    pub(crate) tcb_info: BTreeMap<String, Property>,
}

#[derive(Debug, Deserialize)]
pub struct QeInfo {
    #[serde(rename = "QE")]
    pub(crate) qe_identity: QeIdentity,
}

#[derive(Debug, Deserialize)]
pub(crate) struct QeIdentity {
    #[serde(rename = "QeIdentity")]
    pub(crate) qe_identity: BTreeMap<String, Property>,
}

#[derive(Debug, Deserialize)]
pub struct TdxModuleInfo {
    #[serde(rename = "TDXModule")]
    pub(crate) tdx_module: TdxModule,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TdxModule {
    #[serde(rename = "TDXModule_Identity")]
    pub(crate) tdx_module_identity: BTreeMap<String, Property>,
}

#[derive(Debug, Deserialize)]
pub struct MigTdInfo {
    #[serde(rename = "MigTD")]
    pub(crate) migtd: TdInfo,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TdInfo {
    #[serde(rename = "TDINFO")]
    pub(crate) td_info: BTreeMap<String, Property>,
    #[serde(rename = "EventLog")]
    pub(crate) event_log: Option<BTreeMap<String, Property>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Property {
    pub(crate) operation: Operation,
    pub(crate) reference: Reference,
}

impl Property {
    pub fn verify(&self, is_src: bool, local: &[u8], peer: &[u8]) -> bool {
        match &self.reference {
            Reference::Integer(i) => {
                if peer.len() > size_of::<usize>() {
                    false
                } else {
                    let mut bytes = [0u8; size_of::<usize>()];
                    bytes[..peer.len()].copy_from_slice(peer);
                    let peer = usize::from_le_bytes(bytes);
                    i.verify(is_src, &self.operation, 0, peer)
                }
            }
            Reference::String(s) => {
                let peer = format_bytes_hex(peer);
                s.verify(is_src, &self.operation, "", &peer)
            }
            Reference::Local(selfr) => selfr.verify(is_src, &self.operation, local, peer),
            Reference::IntegerRange(r) => {
                if peer.len() > size_of::<usize>() {
                    false
                } else {
                    let mut bytes = [0u8; size_of::<usize>()];
                    bytes[..peer.len()].copy_from_slice(peer);
                    let peer = usize::from_le_bytes(bytes);
                    r.verify(is_src, &self.operation, 0, peer)
                }
            }
            Reference::Array(a) => a.verify(is_src, &self.operation, &[], peer),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Reference {
    Integer(Integer),
    String(RefString),
    Local(RefLocal),
    IntegerRange(IntegerRange),
    Array(Array), // TimeRange(ops::Range<usize>),
}

impl<'de> Deserialize<'de> for Reference {
    fn deserialize<D>(deserializer: D) -> Result<Reference, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReferenceVisitor;

        fn parse_str(s: &str) -> Option<Reference> {
            if s == "self" {
                Some(Reference::Local(RefLocal))
            } else if let Some(range) = parse_range(s) {
                Some(Reference::IntegerRange(IntegerRange(range)))
            } else {
                Some(Reference::String(RefString(String::from_str(s).ok()?)))
            }
        }

        impl<'de> Visitor<'de> for ReferenceVisitor {
            type Value = Reference;

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                parse_str(v).ok_or(E::custom("Invalid string value"))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(Reference::Integer(Integer(v as usize)))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(val) = seq.next_element()? {
                    items.push(val);
                }
                Ok(Reference::Array(Array(items)))
            }

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("Expect a sequence of map or a string value")
            }
        }

        deserializer.deserialize_any(ReferenceVisitor)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum Operation {
    Equal,
    GreaterOrEqual,
    Subset,
    InRange,
    InTimeRange,
    ArrayEqual,
    ArrayGreaterOrEqual,
}

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D>(deserializer: D) -> Result<Operation, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        match s {
            "equal" => Ok(Operation::Equal),
            "greater-or-equal" => Ok(Operation::GreaterOrEqual),
            "subset" => Ok(Operation::Subset),
            "in-range" => Ok(Operation::InRange),
            "in-time-range" => Ok(Operation::InTimeRange),
            "array-equal" => Ok(Operation::ArrayEqual),
            "array-greater-or-equal" => Ok(Operation::ArrayGreaterOrEqual),
            _ => Err(D::Error::custom("Unknown operation")),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Integer(usize);

impl Integer {
    fn verify(&self, _is_src: bool, op: &Operation, _local: usize, peer: usize) -> bool {
        match op {
            Operation::Equal => peer == self.0,
            Operation::GreaterOrEqual => peer >= self.0,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RefString(pub(crate) String);

impl RefString {
    pub(crate) fn verify(&self, _is_src: bool, op: &Operation, _local: &str, peer: &str) -> bool {
        match op {
            Operation::Equal => *peer == self.0,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RefLocal;

impl RefLocal {
    fn verify(&self, is_src: bool, op: &Operation, local: &[u8], peer: &[u8]) -> bool {
        if local.len() != peer.len() {
            return false;
        }
        match op {
            Operation::Equal => peer == local,
            Operation::GreaterOrEqual => {
                if let Some(l) = slice_to_u64(local) {
                    if let Some(p) = slice_to_u64(peer) {
                        return if is_src { p >= l } else { l >= p };
                    }
                }
                false
            }
            Operation::ArrayEqual => local == peer,
            Operation::ArrayGreaterOrEqual => {
                local
                    .iter()
                    .zip(peer.iter())
                    .all(|(l, p)| if is_src { p >= l } else { l >= p })
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct IntegerRange(ops::Range<usize>);

impl IntegerRange {
    fn verify(&self, _is_src: bool, op: &Operation, _local: usize, peer: usize) -> bool {
        match op {
            Operation::InRange => self.0.contains(&peer),
            Operation::InTimeRange => self.0.contains(&peer),
            _ => false,
        }
    }
}

fn parse_range(input: &str) -> Option<ops::Range<usize>> {
    let parts: Vec<&str> = input.split("..").collect();

    if parts.len() != 2 {
        return None;
    }

    let start = if parts[0].is_empty() {
        usize::MIN
    } else {
        usize::from_str(parts[0]).ok()?
    };

    let end: usize = if parts[1].is_empty() {
        usize::MAX
    } else {
        usize::from_str(parts[1]).ok()?
    };

    Some(start..end)
}

#[derive(Debug, Clone)]
pub(crate) struct Array(Vec<u8>);

impl Array {
    fn verify(&self, _is_src: bool, op: &Operation, _local: &[u8], peer: &[u8]) -> bool {
        if peer.len() != self.0.len() {
            return false;
        }

        match op {
            Operation::ArrayEqual => self.0.as_slice() == peer,
            Operation::ArrayGreaterOrEqual => self.0.iter().zip(peer.iter()).all(|(r, p)| p >= r),
            _ => false,
        }
    }
}

mod guid_serde {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Guid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        Guid::from_str(s).map_err(|_| Error::custom("Invalid GUID"))
    }
}

pub(crate) fn slice_to_u64(input: &[u8]) -> Option<u64> {
    if input.len() > size_of::<u64>() {
        return None;
    }
    let mut bytes = [0u8; 8];
    bytes[..input.len()].copy_from_slice(input);
    Some(u64::from_le_bytes(bytes))
}

pub(crate) fn format_bytes_hex(input: &[u8]) -> String {
    input.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02X}");
        acc
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_policy_data() {
        use super::*;
        use serde_json;

        let result = serde_json::from_str::<MigPolicy>(include_str!("../test/policy.json"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_policy_data_with_invalid_guid() {
        use super::*;
        use serde_json;

        let result =
            serde_json::from_str::<MigPolicy>(include_str!("../test/policy_invalid_guid.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_policy_data() {
        use super::*;
        use serde_json;

        let result = serde_json::from_str::<MigPolicy>(include_str!("../test/policy_005.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_interger_equal() {
        let equal: usize = 1;
        let not_equal: usize = 0;
        let op = Operation::Equal;

        assert!(
            Integer(1).verify(true, &op, 0, equal) && !Integer(1).verify(true, &op, 0, not_equal)
        );
    }

    #[test]
    fn test_interger_greater_or_equal() {
        let less: usize = 0;
        let equal: usize = 1;
        let greater: usize = 2;

        let op = Operation::GreaterOrEqual;

        assert!(
            !Integer(1).verify(true, &op, 0, less)
                && Integer(1).verify(true, &op, 0, equal)
                && Integer(1).verify(true, &op, 0, greater)
        );
    }

    #[test]
    fn test_string_equal() {
        let local = String::from("abc");
        let equal = String::from("abc");
        let not_equal = String::from("aaa");
        let op = Operation::Equal;

        assert!(
            RefString(String::from("abc")).verify(true, &op, &local, &equal)
                && !RefString(String::from("abc")).verify(true, &op, &local, &not_equal)
        );
    }

    #[test]
    fn test_self_equal() {
        let local = [1, 2, 3, 4];
        let equal = [1, 2, 3, 4];
        let not_equal = [1, 2, 3, 4, 5];

        let op = Operation::Equal;

        assert!(
            !RefLocal.verify(true, &op, &local, &not_equal)
                && RefLocal.verify(true, &op, &local, &equal)
        );
    }

    #[test]
    fn test_self_greater_or_equal() {
        let src = [1, 2, 3, 4];
        let less = [1, 5, 3, 3];
        let equal = [1, 2, 3, 4];
        let greater = [1, 1, 3, 5];

        let op = Operation::GreaterOrEqual;

        assert!(
            !RefLocal.verify(true, &op, &src, &less)
                && RefLocal.verify(true, &op, &src, &equal)
                && RefLocal.verify(true, &op, &src, &greater)
        );

        let dst = src;
        assert!(
            RefLocal.verify(false, &op, &dst, &less)
                && RefLocal.verify(false, &op, &dst, &equal)
                && !RefLocal.verify(false, &op, &dst, &greater)
        );
    }

    #[test]
    fn test_self_array_equal() {
        let src = [1, 2, 3, 4];
        let equal = [1, 2, 3, 4];
        let unequal = [1, 2, 3, 5];

        let op = Operation::ArrayEqual;

        assert!(
            !RefLocal.verify(true, &op, &src, &unequal) && RefLocal.verify(true, &op, &src, &equal)
        );
    }

    #[test]
    fn test_self_array_greater_or_equal() {
        let src = [1, 2, 3, 4];
        let less1 = [1, 3, 3, 3];
        let less2 = [1, 1, 3, 3];
        let equal = [1, 2, 3, 4];
        let greater = [1, 2, 3, 5];

        let op = Operation::ArrayGreaterOrEqual;

        assert!(
            !RefLocal.verify(true, &op, &src, &less1)
                && !RefLocal.verify(true, &op, &src, &less2)
                && RefLocal.verify(true, &op, &src, &equal)
                && RefLocal.verify(true, &op, &src, &greater)
        );

        let dst = src;
        assert!(
            !RefLocal.verify(false, &op, &dst, &less1)
                && RefLocal.verify(false, &op, &dst, &less2)
                && RefLocal.verify(false, &op, &dst, &equal)
                && !RefLocal.verify(false, &op, &dst, &greater)
        );
    }

    #[test]
    fn test_interrange_inrange() {
        let inrange = 2;
        let not_inrange = 3;

        let op = Operation::InRange;

        assert!(
            !IntegerRange(0..3).verify(true, &op, 0, not_inrange)
                && IntegerRange(0..3).verify(true, &op, 0, inrange)
        );
    }

    #[test]
    fn test_array_equal() {
        let reference = vec![0x2, 0x60, 0x6a];
        let local = &[];
        let equal = &[0x2, 0x60, 0x6a];
        let greater = &[0x2, 0x60, 0x6c];
        let smaller = &[0x2, 0x5f, 0x6a];
        let invalid = &[0x2, 0x60, 0x6a, 0x1];
        let op = Operation::ArrayEqual;

        assert!(
            Array(reference.clone()).verify(true, &op, local, equal)
                && !Array(reference.clone()).verify(true, &op, local, greater)
                && !Array(reference.clone()).verify(true, &op, local, smaller)
                && !Array(reference.clone()).verify(true, &op, local, invalid)
        );
    }

    #[test]
    fn test_array_greater_or_equal() {
        let reference = vec![0x2, 0x60, 0x6a];
        let local = &[];
        let equal = &[0x2, 0x60, 0x6a];
        let greater = &[0x2, 0x61, 0x6a];
        let smaller = &[0x3, 0x60, 0x60];
        let op = Operation::ArrayGreaterOrEqual;

        assert!(
            Array(reference.clone()).verify(true, &op, local, equal)
                && Array(reference.clone()).verify(true, &op, local, greater)
                && !Array(reference.clone()).verify(true, &op, local, smaller)
        );
    }
}
