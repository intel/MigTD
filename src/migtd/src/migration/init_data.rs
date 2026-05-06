// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use crypto::SHA384_DIGEST_SIZE;

pub(crate) const MIGTD_DATA_SIGNATURE: &[u8] = b"MIGTDATA";
pub(crate) const MIGTD_DATA_TYPE_TDINFO: u32 = 0;

pub struct InitData {
    /// The TDINFO_STRUCT of the initial MigTD (per GHCI 1.5, MIGTD_DATA type 0).
    pub init_tdinfo: Vec<u8>,
}

impl InitData {
    /// TDINFO_STRUCT field offsets and sizes (per TDX Module ABI).
    const TDINFO_MROWNER_OFFSET: usize = 112; // attributes(8) + xfam(8) + mrtd(48) + mrconfig_id(48)
    const TDINFO_MROWNERCONFIG_OFFSET: usize = 160; // MROWNER_OFFSET + 48
    const TDINFO_FIELD_SIZE: usize = SHA384_DIGEST_SIZE;
    const TDINFO_MIN_SIZE: usize = 512;

    /// Extract mrowner from the TDINFO_STRUCT.
    /// Per GHCI 1.5: VMM puts migpolicy.policy_key in tdinfo.mrowner.
    pub fn mrowner(&self) -> &[u8] {
        &self.init_tdinfo
            [Self::TDINFO_MROWNER_OFFSET..Self::TDINFO_MROWNER_OFFSET + Self::TDINFO_FIELD_SIZE]
    }

    /// Extract mrownerconfig from the TDINFO_STRUCT.
    /// Per GHCI 1.5: VMM puts migpolicy.policy_svn in tdinfo.mrownerconfig.
    pub fn mrownerconfig(&self) -> &[u8] {
        &self.init_tdinfo[Self::TDINFO_MROWNERCONFIG_OFFSET
            ..Self::TDINFO_MROWNERCONFIG_OFFSET + Self::TDINFO_FIELD_SIZE]
    }

    pub fn read_from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 20 || &b[..8] != MIGTD_DATA_SIGNATURE {
            return None;
        }

        let version = u32::from_le_bytes(b[8..12].try_into().unwrap());
        let length = u32::from_le_bytes(b[12..16].try_into().unwrap());
        let num_entries = u32::from_le_bytes(b[16..20].try_into().unwrap());

        // Per GHCI 1.5: version must be 0x00010000, numberOfEntry must be 1 (tdinfo)
        if version != 0x00010000 || b.len() < length as usize || num_entries != 1 {
            return None;
        }

        let entry = MigtdDataEntry::read_from_bytes(&b[20..])?;
        if entry.r#type != MIGTD_DATA_TYPE_TDINFO {
            return None;
        }

        if entry.value.len() < Self::TDINFO_MIN_SIZE {
            return None;
        }

        Some(Self {
            init_tdinfo: entry.value.to_vec(),
        })
    }

    pub fn write_into_bytes(&self, buf: &mut Vec<u8>) {
        let start_len = buf.len();
        buf.extend_from_slice(MIGTD_DATA_SIGNATURE);
        buf.extend_from_slice(&0x00010000u32.to_le_bytes()); // Version

        // Placeholder for length.
        buf.extend_from_slice(&0u32.to_le_bytes());

        // Per GHCI 1.5: numberOfEntry = 1, entry type 0 = tdinfo
        buf.extend_from_slice(&1u32.to_le_bytes()); // num_entries

        buf.extend_from_slice(&MIGTD_DATA_TYPE_TDINFO.to_le_bytes());
        buf.extend_from_slice(&(self.init_tdinfo.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.init_tdinfo);

        let total_size = (buf.len() - start_len) as u32;

        // Update length field
        let length_offset = start_len + 12;
        buf[length_offset..length_offset + 4].copy_from_slice(&total_size.to_le_bytes());
    }

    pub fn get_from_local(report_data: &[u8; 64]) -> Option<Self> {
        let report = tdx_tdcall::tdreport::tdcall_report(report_data).ok()?;
        Some(Self {
            init_tdinfo: report.td_info.as_bytes().to_vec(),
        })
    }
}

pub struct MigtdDataEntry<'a> {
    pub r#type: u32,
    pub length: u32,
    pub value: &'a [u8],
}

impl<'a> MigtdDataEntry<'a> {
    pub fn read_from_bytes(b: &'a [u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }

        let r#type = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let length = u32::from_le_bytes(b[4..8].try_into().unwrap());

        if b.len() < length as usize + 8 {
            return None;
        }

        Some(Self {
            r#type,
            length,
            value: &b[8..8 + length as usize],
        })
    }
}
