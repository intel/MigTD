// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{collections::BTreeMap, vec::Vec};
use anyhow::anyhow;
use anyhow::Result;
use cc_measurement::log::CcEventLogReader;
use cc_measurement::{
    CcEventHeader, TcgPcrEventHeader, TpmlDigestValues, TpmtHa, TpmuHa,
    EV_EFI_PLATFORM_FIRMWARE_BLOB2, EV_PLATFORM_CONFIG_FLAGS, SHA384_DIGEST_SIZE, TPML_ALG_SHA384,
};
use core::mem::size_of;
use crypto::hash::digest_sha384;
use policy::{CcEvent, EventName};
use spin::Once;
use td_payload::acpi::get_acpi_tables;
use td_shim::event_log::{
    PLATFORM_CONFIG_SECURE_AUTHORITY, PLATFORM_CONFIG_SVN, PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
};
use td_shim_interface::acpi::Ccel;
use tdx_tdcall::tdx;
use zerocopy::{AsBytes, FromBytes};

pub const EV_EVENT_TAG: u32 = 0x00000006;
pub const TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT: &[u8] = b"test_disable_ra_and_accept_all";

// Event IDs that will be used to tag the event log
pub const TAGGED_EVENT_ID_POLICY: u32 = 0x1;
pub const TAGGED_EVENT_ID_ROOT_CA: u32 = 0x2;
pub const TAGGED_EVENT_ID_POLICY_ISSUER_CHAIN: u32 = 0x3;
pub const TAGGED_EVENT_ID_TEST: u32 = 0x32;

// MR index the event will be measured into
pub const MR_INDEX_POLICY_ISSUER_CHAIN: u32 = 0x2;
pub const MR_INDEX_POLICY: u32 = 0x3;
pub const MR_INDEX_ROOT_CA: u32 = 0x3;
pub const MR_INDEX_TEST_FEATURE: u32 = 0x3;

const MAX_RTMR_INDEX: usize = 3;

static CCEL: Once<Ccel> = Once::new();

pub struct TaggedEvent {
    event: Vec<u8>,
}

impl TaggedEvent {
    pub fn new(tag_id: u32, data: &[u8]) -> Self {
        let mut event = Vec::new();

        event.extend_from_slice(&tag_id.to_le_bytes());
        event.extend_from_slice(&(data.len() as u32).to_le_bytes());

        event.extend_from_slice(data);

        Self { event }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.event.as_slice()
    }
}

pub fn get_event_log_mut() -> Option<&'static mut [u8]> {
    get_ccel().map(event_log_slice)
}

pub fn get_event_log() -> Option<&'static [u8]> {
    let raw = get_ccel().map(event_log_slice)?;
    event_log_size(raw).map(|size| &raw[..size + 1])
}

fn event_log_size(event_log: &[u8]) -> Option<usize> {
    let reader = CcEventLogReader::new(event_log)?;

    // The first event is TCG_EfiSpecIDEvent with TcgPcrEventHeader
    let mut size = size_of::<TcgPcrEventHeader>() + reader.pcr_event_header.event_size as usize;

    for (header, _) in reader.cc_events {
        size += size_of::<CcEventHeader>() + header.event_size as usize;
    }

    Some(size)
}

fn event_log_slice(ccel: &Ccel) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(ccel.lasa as *mut u8, ccel.laml as usize) }
}

fn get_ccel() -> Option<&'static Ccel> {
    if !CCEL.is_completed() {
        // Parse out ACPI tables handoff from firmware and find the event log location
        let &ccel = get_acpi_tables()
            .and_then(|tables| tables.iter().find(|&&t| t[..4] == *b"CCEL"))
            .expect("Failed to find CCEL");

        if ccel.len() < size_of::<Ccel>() {
            return None;
        }

        let ccel = Ccel::read_from(&ccel[..size_of::<Ccel>()])?;

        Some(CCEL.call_once(|| ccel))
    } else {
        CCEL.get()
    }
}

pub fn write_tagged_event_log(
    event_log: &mut [u8],
    mr_index: u32,
    hash_data: &[u8],
    tagged_event_id: u32,
    tagged_event_data: &[u8],
) -> Result<usize> {
    let mut log_size = event_log_size(event_log).ok_or_else(|| anyhow!("Parsing event log"))?;
    let event = TaggedEvent::new(tagged_event_id, tagged_event_data);

    let digest = calculate_digest(hash_data)?;
    extend_rtmr(&digest, mr_index)?;

    let event_header = CcEventHeader {
        mr_index,
        event_type: EV_EVENT_TAG,
        digest: TpmlDigestValues {
            count: 1,
            digests: [TpmtHa {
                hash_alg: TPML_ALG_SHA384,
                digest: TpmuHa { sha384: digest },
            }],
        },
        event_size: event.as_bytes().len() as u32,
    };

    if event_log.len() < log_size + size_of::<CcEventHeader>() + event.as_bytes().len() {
        return Err(anyhow!("Event log out of memory"));
    }

    event_log[log_size..log_size + size_of::<CcEventHeader>()]
        .copy_from_slice(event_header.as_bytes());
    log_size += size_of::<CcEventHeader>();

    event_log[log_size..log_size + event.as_bytes().len()].copy_from_slice(event.as_bytes());

    Ok(log_size + event.as_bytes().len())
}

pub fn calculate_digest(hash_data: &[u8]) -> Result<[u8; SHA384_DIGEST_SIZE]> {
    let digest = digest_sha384(hash_data).map_err(|_| anyhow!("Calculate digest"))?;

    let mut digest_sha384 = [0u8; SHA384_DIGEST_SIZE];
    digest_sha384.clone_from_slice(digest.as_slice());

    Ok(digest_sha384)
}

pub fn extend_rtmr(digest: &[u8; SHA384_DIGEST_SIZE], mr_index: u32) -> Result<()> {
    let digest = tdx::TdxDigest { data: *digest };

    let rtmr_index = match mr_index {
        1..=4 => mr_index - 1,
        _ => {
            return Err(anyhow!("Invalid mr_index 0x{:x}\n", mr_index));
        }
    };

    tdx::tdcall_extend_rtmr(&digest, rtmr_index).map_err(|e| anyhow!("Extend RTMR: {:?}", e))
}

pub(crate) fn parse_events(event_log: &[u8]) -> Option<BTreeMap<EventName, CcEvent>> {
    let mut map: BTreeMap<EventName, CcEvent> = BTreeMap::new();
    let reader = CcEventLogReader::new(event_log)?;

    for (event_header, event_data) in reader.cc_events {
        match event_header.event_type {
            EV_EFI_PLATFORM_FIRMWARE_BLOB2 => {
                let desc_size = event_data[0] as usize;
                if &event_data[1..1 + desc_size] == PLATFORM_FIRMWARE_BLOB2_PAYLOAD {
                    map.insert(EventName::MigTdCore, CcEvent::new(event_header, None));
                }
            }
            EV_PLATFORM_CONFIG_FLAGS => {
                if event_data.starts_with(PLATFORM_CONFIG_SECURE_AUTHORITY) {
                    map.insert(EventName::SecureBootKey, CcEvent::new(event_header, None));
                } else if event_data.starts_with(PLATFORM_CONFIG_SVN) {
                    if event_data.len() < 20 {
                        return None;
                    }
                    let info_size: usize =
                        u32::from_le_bytes(event_data[16..20].try_into().unwrap()) as usize;
                    if event_data.len() < 20 + info_size {
                        return None;
                    }
                    map.insert(
                        EventName::MigTdCoreSvn,
                        CcEvent::new(event_header, Some(event_data[20..20 + info_size].to_vec())),
                    );
                }
            }
            EV_EVENT_TAG => {
                let tag_id = u32::from_le_bytes(event_data[..4].try_into().ok()?);
                if tag_id == TAGGED_EVENT_ID_POLICY {
                    map.insert(EventName::MigTdPolicy, CcEvent::new(event_header, None));
                } else if tag_id == TAGGED_EVENT_ID_ROOT_CA {
                    map.insert(EventName::SgxRootKey, CcEvent::new(event_header, None));
                } else if tag_id == TAGGED_EVENT_ID_POLICY_ISSUER_CHAIN {
                    map.insert(
                        EventName::MigTdPolicySigner,
                        CcEvent::new(event_header, None),
                    );
                }
            }
            _ => {}
        }
    }

    Some(map)
}

pub fn verify_event_log(
    event_log: &[u8],
    report_rtmrs: &[[u8; SHA384_DIGEST_SIZE]; 4],
) -> Result<()> {
    replay_event_log_with_report(event_log, report_rtmrs)
}

fn replay_event_log_with_report(
    event_log: &[u8],
    report_rtmrs: &[[u8; SHA384_DIGEST_SIZE]; 4],
) -> Result<()> {
    let mut rtmrs: [[u8; 96]; 4] = [[0; 96]; 4];

    let event_log = if let Some(event_log) = CcEventLogReader::new(event_log) {
        event_log
    } else {
        return Err(anyhow!("Invalid event log"));
    };

    for (event_header, _) in event_log.cc_events {
        let rtmr_index = match event_header.mr_index {
            0 => 0xFF,
            1..=4 => event_header.mr_index - 1,
            _ => 0xFF,
        } as usize;

        if rtmr_index <= MAX_RTMR_INDEX {
            rtmrs[rtmr_index][48..].copy_from_slice(&event_header.digest.digests[0].digest.sha384);
            if let Ok(digest) = digest_sha384(&rtmrs[rtmr_index]) {
                rtmrs[rtmr_index][0..48].copy_from_slice(&digest);
            } else {
                return Err(anyhow!("Calculate digest"));
            }
        } else {
            return Err(anyhow!("Invalid event log"));
        }
    }

    if report_rtmrs[0] == rtmrs[0][0..48]
        && report_rtmrs[1] == rtmrs[1][0..48]
        && report_rtmrs[2] == rtmrs[2][0..48]
        && report_rtmrs[3] == rtmrs[3][0..48]
    {
        Ok(())
    } else {
        //In AzCVMEmu mode, RTMR extension is emulated (no-op), RTMR in MigTD QUOTE won't match eventlog.
        //Return OK in this development environment.
        #[cfg(feature = "AzCVMEmu")]
        {
            Ok(())
        }
        #[cfg(not(feature = "AzCVMEmu"))]
        Err(anyhow!("Invalid event log"))
    }
}
