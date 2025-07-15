// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{CcEvent, EventName, PolicyError};
use alloc::{collections::btree_map::BTreeMap, format, string::String, vec::Vec};

mod servtd_collateral;
pub use servtd_collateral::*;
mod collaterals;
pub use collaterals::*;

// Verify the hash of a specific event in the event log
fn verify_event_hash(
    events: &BTreeMap<EventName, CcEvent>,
    event_name: &EventName,
    data_to_hash: &[u8],
) -> Result<bool, PolicyError> {
    let event = match events.get(event_name) {
        Some(event) => event,
        None => return Ok(false), // Event not found
    };

    let event_digest = &event
        .header
        .digest
        .digests
        .first()
        .ok_or(PolicyError::InvalidEventLog)?
        .digest
        .sha384;

    let expected_hash =
        crypto::hash::digest_sha384(data_to_hash).map_err(|_| PolicyError::HashCalculation)?;

    // Compare the calculated digest with the expected digest
    Ok(&expected_hash == event_digest)
}

/// Convert a hex string to bytes without using external crates
fn hex_string_to_bytes(hex: &str) -> Result<Vec<u8>, PolicyError> {
    // Ensure even number of characters
    if hex.len() % 2 != 0 {
        return Err(PolicyError::SignatureVerificationFailed);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    // Process two hex digits at a time
    for i in (0..hex.len()).step_by(2) {
        if i + 2 > hex.len() {
            break;
        }

        // Get the hex byte as a string slice
        let byte_str = &hex[i..i + 2];

        // Convert to numeric value
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        bytes.push(byte);
    }

    Ok(bytes)
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_hex_string_to_bytes() {
        // Test valid hex strings
        assert_eq!(
            hex_string_to_bytes("48656c6c6f").unwrap(),
            vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]
        );
        assert_eq!(
            hex_string_to_bytes("ff00ff").unwrap(),
            vec![0xff, 0x00, 0xff]
        );

        // Test invalid hex strings
        assert!(hex_string_to_bytes("123g").is_err());
        assert!(hex_string_to_bytes("123").is_err()); // Odd length
    }
}
