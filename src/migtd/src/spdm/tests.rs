// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use spdmlib::common::{session::SpdmSessionState, INVALID_SESSION_ID};

struct TestTransport;

impl AsyncRead for TestTransport {
    async fn read(&mut self, _buffer: &mut [u8]) -> async_io::Result<usize> {
        unreachable!("session teardown must not read from the transport");
    }
}

impl AsyncWrite for TestTransport {
    async fn write(&mut self, _buffer: &[u8]) -> async_io::Result<usize> {
        unreachable!("session teardown must not write to the transport");
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
    let (mut requester, _) = spdm_requester(TestTransport).unwrap();
    assert_teardown_clears_sessions(&mut requester.common);
}

#[test]
fn responder_teardown_clears_handshaking_and_established_sessions() {
    let (mut responder, _) = spdm_responder(TestTransport).unwrap();
    assert_teardown_clears_sessions(&mut responder.responder_context.common);
}

#[test]
fn decode_error_path_status_never_returns_success() {
    // App-code 0 collides with `MigrationResult::Success`'s discriminant.
    // On an error path this must be treated as an undecodable/invalid code,
    // not as a successful result.
    assert_eq!(
        decode_error_path_status(0),
        MigrationResult::SecureSessionError
    );
    // A genuine, non-zero error code still decodes to its real variant.
    assert_eq!(
        decode_error_path_status(MigrationResult::InvalidParameter as u8),
        MigrationResult::InvalidParameter
    );
    // An undecodable value falls back to a generic session error rather
    // than panicking or silently becoming Success.
    assert_eq!(
        decode_error_path_status(0xAA),
        MigrationResult::SecureSessionError
    );
}

#[test]
fn from_spdm_status_vdm_error_never_decodes_to_success() {
    let status = SpdmStatus {
        severity: StatusSeverity::ERROR,
        status_code: StatusCode::VDM(StatusCodeVdmError { vdm_error_code: 0 }),
        error_data: None,
    };
    assert_eq!(
        MigrationResult::from(status),
        MigrationResult::SecureSessionError
    );
}

#[test]
fn decode_spdm_session_err_vendor_defined_zero_app_code_never_decodes_to_success() {
    let mut data = [0u8; spdmlib::error::SPDM_ERROR_MESSAGE_DATA_MAX_LENGTH];
    data[2] = spdmlib::message::SpdmErrorCode::SpdmErrorVendorDefined.get_u8();
    data[3] = MigrationResult::Success as u8;
    let status = SpdmStatus {
        severity: StatusSeverity::ERROR,
        status_code: StatusCode::VDM(StatusCodeVdmError { vdm_error_code: 0 }),
        error_data: Some(spdmlib::error::SpdmErrorMessageData { length: 4, data }),
    };
    assert_eq!(
        decode_spdm_session_err(status),
        MigrationResult::SecureSessionError
    );
}
