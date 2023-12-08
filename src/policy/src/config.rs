// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::{mem::size_of, ops, str::FromStr};
use lexical_core::parse;
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer,
};
use td_uefi_pi::pi::guid::Guid;

#[derive(Debug, Deserialize)]
pub struct MigPolicy {
    #[serde(rename = "id", with = "guid_serde")]
    pub _id: Guid,
    #[serde(rename = "MigTd")]
    pub migtd: Policy,
}

#[derive(Debug, Deserialize)]
pub struct Policy {
    #[serde(rename = "TEE_TCB_INFO")]
    pub tee_tcb_info: Option<BTreeMap<String, Property>>,
    #[serde(rename = "TDINFO")]
    pub td_info: Option<BTreeMap<String, Property>>,
    #[serde(rename = "EventLog")]
    pub event_log: Option<BTreeMap<String, Property>>,
}

#[derive(Debug, Deserialize)]
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
                    let mut bytes = [0u8; 8];
                    bytes[..peer.len()].copy_from_slice(peer);
                    let peer = usize::from_le_bytes(bytes);
                    i.verify(is_src, &self.operation, 0, peer)
                }
            }
            Reference::String(s) => {
                let peer: String = peer.iter().map(|b| format!("{:02x}", b)).collect();
                s.verify(is_src, &self.operation, "", &peer)
            }
            Reference::Local(selfr) => selfr.verify(is_src, &self.operation, local, peer),
            Reference::IntegerRange(r) => {
                if peer.len() > size_of::<usize>() {
                    false
                } else {
                    let mut bytes = [0u8; 8];
                    bytes[..peer.len()].copy_from_slice(peer);
                    let peer = usize::from_le_bytes(bytes);
                    r.verify(is_src, &self.operation, 0, peer)
                }
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
pub(crate) enum Reference {
    Integer(Integer),
    String(RefString),
    Local(RefLocal),
    IntegerRange(IntegerRange),
    Custom(Vec<BTreeMap<String, String>>), // TimeRange(ops::Range<usize>),
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
            } else if let Ok(num) = parse::<usize>(s.as_bytes()) {
                Some(Reference::Integer(Integer(num)))
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

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(val) = seq.next_element()? {
                    items.push(val);
                }
                Ok(Reference::Custom(items))
            }

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("Expect a sequence of map or a string value")
            }
        }

        deserializer.deserialize_any(ReferenceVisitor)
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Operation {
    Equal,
    GreaterOrEqual,
    Subset,
    InRange,
    InTimeRange,
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
            _ => Err(D::Error::custom("Unknown operation")),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Integer(usize);

impl Integer {
    fn verify(&self, _is_src: bool, op: &Operation, _local: usize, peer: usize) -> bool {
        match op {
            Operation::Equal => peer == self.0,
            Operation::GreaterOrEqual => peer >= self.0,
            Operation::Subset => false,
            Operation::InRange => false,
            Operation::InTimeRange => false,
        }
    }
}

#[derive(Debug)]
pub(crate) struct RefString(pub(crate) String);

impl RefString {
    pub(crate) fn verify(&self, _is_src: bool, op: &Operation, _local: &str, peer: &str) -> bool {
        match op {
            Operation::Equal => *peer == self.0,
            Operation::GreaterOrEqual => {
                if peer.len() != self.0.len() {
                    false
                } else {
                    compare_array_in_string(peer, self.0.as_str())
                }
            }
            Operation::Subset => false,
            Operation::InRange => false,
            Operation::InTimeRange => false,
        }
    }
}

fn compare_array_in_string(str1: &str, str2: &str) -> bool {
    if str1.len() != str2.len() || str1.len() % 2 != 0 {
        false
    } else {
        for idx in 0..str1.len() / 2 {
            if let Ok(v1) = u8::from_str_radix(&str1[idx..idx + 2], 16) {
                if let Ok(v2) = u8::from_str_radix(&str2[idx..idx + 2], 16) {
                    if v1 >= v2 {
                        continue;
                    }
                }
            }
            return false;
        }
        true
    }
}

#[derive(Debug)]
pub(crate) struct RefLocal;

impl RefLocal {
    fn verify(&self, is_src: bool, op: &Operation, local: &[u8], peer: &[u8]) -> bool {
        match op {
            Operation::Equal => peer == local,
            Operation::GreaterOrEqual => {
                if is_src {
                    peer >= local
                } else {
                    local >= peer
                }
            }
            Operation::Subset => false,
            Operation::InRange => false,
            Operation::InTimeRange => false,
        }
    }
}

#[derive(Debug)]
pub(crate) struct IntegerRange(ops::Range<usize>);

impl IntegerRange {
    fn verify(&self, _is_src: bool, op: &Operation, _local: usize, peer: usize) -> bool {
        match op {
            Operation::Equal => false,
            Operation::GreaterOrEqual => false,
            Operation::Subset => false,
            Operation::InRange => self.0.contains(&peer),
            Operation::InTimeRange => self.0.contains(&peer),
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
        parse::<usize>(parts[0].as_bytes()).ok()?
    };

    let end: usize = if parts[1].is_empty() {
        usize::MAX
    } else {
        parse::<usize>(parts[1].as_bytes()).ok()?
    };

    Some(start..end)
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

#[cfg(test)]
mod test {
    use super::*;

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
    fn test_string_greater_or_equal() {
        let reference = String::from("02606a");
        let local = String::from("");
        let equal = String::from("02606a");
        let greater = String::from("02616b");
        let smaller = String::from("025a6a");
        let invalid = String::from("02606a1");
        let op = Operation::GreaterOrEqual;

        assert!(
            RefString(reference.clone()).verify(true, &op, &local, &equal)
                && RefString(reference.clone()).verify(true, &op, &local, &greater)
                && !RefString(reference.clone()).verify(true, &op, &local, &smaller)
                && !RefString(reference.clone()).verify(true, &op, &local, &invalid)
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
        let less = [1, 2, 3];
        let equal = [1, 2, 3, 4];
        let greater = [1, 2, 3, 4, 5];

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
    fn test_complex_options() {
        use super::*;
        use serde_json;

        let result = serde_json::from_str::<MigPolicy>(include_str!("../test/policy.json"));
        assert!(result.is_ok());
    }
}
