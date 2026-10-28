// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use crate::migration::session::ExchangeInformation;
use core::future::pending;
#[cfg(all(feature = "policy_v2", feature = "vmcall-raw"))]
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use spdmlib::common::{session::SpdmSessionState, INVALID_SESSION_ID};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct WipeCheckingAllocator;

#[global_allocator]
static ALLOCATOR: WipeCheckingAllocator = WipeCheckingAllocator;

std::thread_local! {
    // Observe initialized payload storage before System frees it, never after free.
    static WATCHED_PAYLOAD: Cell<(usize, usize, Option<bool>)> = const { Cell::new((0, 0, None)) };
}

unsafe impl GlobalAlloc for WipeCheckingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        let _ = WATCHED_PAYLOAD.try_with(|watch| {
            let (address, size, observed) = watch.get();
            if address == 0 && size == layout.size() && observed.is_none() {
                watch.set((pointer as usize, size, None));
            }
        });
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = WATCHED_PAYLOAD.try_with(|watch| {
            let (address, size, _) = watch.get();
            if address != 0 && address == pointer as usize {
                let wiped = core::slice::from_raw_parts(pointer, size)
                    .iter()
                    .all(|byte| *byte == 0);
                watch.set((0, 0, Some(wiped)));
            }
        });
        System.dealloc(pointer, layout);
    }
}

fn watch_next_payload() {
    WATCHED_PAYLOAD.with(|watch| {
        watch.set((
            0,
            spdmlib::message::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE,
            None,
        ))
    });
}

fn assert_payload_was_wiped() {
    WATCHED_PAYLOAD.with(|watch| assert_eq!(watch.get().2, Some(true)));
}

#[test]
fn dispatcher_wipes_serialized_msk_on_success_and_encoding_failure() {
    use super::spdm_rsp::ResponderContextExInfo;
    use crate::migration::data::MigrationSessionKey;
    use spdmlib::common::{ManagedVdmBuffer, SpdmCodec};
    use spdmlib::message::*;
    use spdmlib::protocol::{SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmVersion};

    for large_payload in [false, true] {
        for response_size in [0, 1, 2, 4, 8, 16, 32, 128] {
            let (mut responder, _) = spdm_responder(TestTransport { fail_read: false }).unwrap();
            let info = MigtdMigrationInformation::default();
            let exchange = ExchangeInformation {
                key: MigrationSessionKey {
                    fields: [0xa5a5_a5a5_a5a5_a5a5; 4],
                },
                ..Default::default()
            };
            responder.info = ResponderContextExInfo::MigrationInformation {
                mig_info: &info,
                exchange_information: &exchange,
            };
            let context = &mut responder.responder_context;
            context.common.negotiate_info.spdm_version_sel = if large_payload {
                SpdmVersion::SpdmVersion14
            } else {
                SpdmVersion::SpdmVersion12
            };
            if large_payload {
                context.common.negotiate_info.req_capabilities_sel =
                    SpdmRequestCapabilityFlags::LARGE_RESP_CAP;
                context.common.negotiate_info.rsp_capabilities_sel =
                    SpdmResponseCapabilityFlags::LARGE_RESP_CAP;
            }
            let session = &mut context.common.session[0];
            session.setup(1).unwrap();
            session.set_session_state(SpdmSessionState::SpdmSessionEstablished);
            session.runtime_info.vdm_message_transcript_before_finish =
                Some(ManagedVdmBuffer::default());

            let mut payload = [0u8; 64];
            let mut writer = Writer::init(&mut payload);
            VdmMessage {
                major_version: VDM_MESSAGE_MAJOR_VERSION,
                minor_version: VDM_MESSAGE_MINOR_VERSION,
                op_code: VdmMessageOpCode::ExchangeMigrationInfoReq,
                element_count: VDM_MESSAGE_EXCHANGE_MIGRATION_INFO_REQ_ELEMENT_COUNT,
            }
            .encode(&mut writer)
            .unwrap();
            VdmMessageElement {
                element_type: VdmMessageElementType::MigrationExportVersion,
                length: VDM_MESSAGE_MIGRATION_EXPORT_VERSION_SIZE,
            }
            .encode(&mut writer)
            .unwrap();
            1u16.encode(&mut writer).unwrap();
            1u16.encode(&mut writer).unwrap();
            VdmMessageElement {
                element_type: VdmMessageElementType::ForwardMigrationSessionKey,
                length: VDM_MESSAGE_FORWARD_MIGRATION_SESSION_KEY_SIZE,
            }
            .encode(&mut writer)
            .unwrap();
            writer.extend_from_slice(&[0x5a; 32]).unwrap();
            let mut vendor_id = [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN];
            vendor_id[..VDM_MESSAGE_VENDOR_ID_LEN].copy_from_slice(&VDM_MESSAGE_VENDOR_ID);
            let request_payload = SpdmVdmRequestPayload {
                standard_id: RegistryOrStandardsBodyID::IANA,
                vendor_id: VendorIDStruct {
                    len: VDM_MESSAGE_VENDOR_ID_LEN as u8,
                    vendor_id,
                },
                req_length: writer.used() as u32,
                req_payload: writer.used_slice().to_vec().into(),
            };
            let mut request = [0u8; 128];
            let mut writer = Writer::init(&mut request);
            SpdmMessageHeader {
                version: context.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
            }
            .encode(&mut writer)
            .unwrap();
            request_payload
                .spdm_encode(&mut context.common, &mut writer)
                .unwrap();
            let request = writer.used_slice();
            let mut response = [0u8; 128];

            watch_next_payload();
            let (result, _) = migtd_vdm_msg_rsp_dispatcher_ex(
                context,
                Some(1),
                request,
                &mut response[..response_size],
            );
            assert_payload_was_wiped();
            assert_eq!(result.is_ok(), response_size == 128);
            assert!(responder.mig_info_exchanged);
            if result.is_ok() {
                assert!(response.windows(32).any(|bytes| bytes == [0xa5; 32]));
            }
        }
    }
}

#[cfg(all(feature = "policy_v2", feature = "vmcall-raw"))]
#[test]
fn serialized_rebind_payload_is_wiped_on_cancellation_and_receive_error() {
    use spdmlib::protocol::SpdmVersion;

    for fail_read in [false, true] {
        let (mut requester, _) = spdm_requester(TestTransport { fail_read }).unwrap();
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        let info = MigtdMigrationInformation::default();
        watch_next_payload();
        finish_or_cancel(
            super::spdm_req::send_and_receive_sdm_rebind_info(&mut requester, &info, None),
            fail_read,
        );
        assert_payload_was_wiped();
    }
}

struct TestTransport {
    fail_read: bool,
}

impl AsyncRead for TestTransport {
    async fn read(&mut self, _buffer: &mut [u8]) -> async_io::Result<usize> {
        if self.fail_read {
            Err(async_io::ErrorKind::ConnectionAborted.into())
        } else {
            pending().await
        }
    }
}

impl AsyncWrite for TestTransport {
    async fn write(&mut self, buffer: &[u8]) -> async_io::Result<usize> {
        Ok(buffer.len())
    }
}

#[cfg(all(feature = "policy_v2", feature = "vmcall-raw"))]
fn finish_or_cancel<T>(future: impl Future<Output = Result<T, SpdmStatus>>, fail_read: bool) {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    let result = future.as_mut().poll(&mut context);
    if fail_read {
        assert!(matches!(result, Poll::Ready(Err(_))));
    } else {
        assert!(result.is_pending());
    }
}

fn assert_teardown_clears_sessions(context: &mut SpdmContext) {
    for last_session_id in [Some(1), None] {
        for (index, session) in context.session.iter_mut().enumerate() {
            session.setup(u32::try_from(index + 1).unwrap()).unwrap();
            session.set_session_state(if last_session_id.is_some() {
                SpdmSessionState::SpdmSessionHandshaking
            } else {
                SpdmSessionState::SpdmSessionEstablished
            });
            let mut secret = session.get_application_secret();
            secret.request_direction.encryption_key.data.fill(0xa5);
            secret.request_direction.encryption_key.data_size = 32;
            session.set_application_secret(secret);
        }
        // FINISH clears this field without removing the established session.
        context.runtime_info.set_last_session_id(last_session_id);

        for _ in 0..2 {
            teardown_sessions(context);
            for session in &context.session {
                assert_eq!(session.get_session_id(), INVALID_SESSION_ID);
                assert_eq!(
                    session.get_session_state(),
                    SpdmSessionState::SpdmSessionNotStarted
                );
                assert_eq!(session.get_application_secret(), Default::default());
            }
        }
    }
}

#[test]
fn requester_teardown_clears_handshaking_and_established_sessions() {
    let (mut requester, _) = spdm_requester(TestTransport { fail_read: false }).unwrap();
    assert_teardown_clears_sessions(&mut requester.common);
}

#[test]
fn responder_teardown_clears_handshaking_and_established_sessions() {
    let (mut responder, _) = spdm_responder(TestTransport { fail_read: false }).unwrap();
    assert_teardown_clears_sessions(&mut responder.responder_context.common);
}
