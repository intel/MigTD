// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::time::Duration;

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_io::{AsyncRead, AsyncWrite};
use connection::{TlsClientConnection, TlsConnectionError, TlsServerConnection};
use pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384;
use rustls::crypto::ring::default_provider;
use rustls::crypto::ring::kx_group::SECP384R1;
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::time_provider::TimeProvider;
use rustls::version::TLS13;
use rustls::{ClientConfig, ServerConfig};
extern crate alloc;

use crate::{Error, Result};

use super::ecdsa::EcdsaPk;

pub type TlsLibError = rustls::Error;
const TLS_CUSTOM_CALLBACK_ERROR: &str = "TlsCustomCallbackError";

pub struct SecureChannel<T: AsyncRead + AsyncWrite + Unpin> {
    conn: TlsConnection<T>,
}

impl<T> SecureChannel<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn new(conn: TlsConnection<T>) -> Self {
        SecureChannel { conn }
    }

    pub fn transport_mut(&mut self) -> &mut T {
        self.conn.transport_mut()
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.conn.write(data).await
    }

    pub async fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        self.conn.read(data).await
    }
}

enum TlsConnection<T: AsyncRead + AsyncWrite + Unpin> {
    Server(TlsServerConnection<T>),
    Client(TlsClientConnection<T>),
}

impl<T: AsyncRead + AsyncWrite + Unpin> TlsConnection<T> {
    async fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        match self {
            Self::Server(conn) => conn.read(data).await.map_err(Self::handle_stream_error),
            Self::Client(conn) => conn.read(data).await.map_err(Self::handle_stream_error),
        }
    }

    async fn write(&mut self, data: &[u8]) -> Result<usize> {
        match self {
            Self::Server(conn) => conn.write(data).await.map_err(Self::handle_stream_error),
            Self::Client(conn) => conn.write(data).await.map_err(Self::handle_stream_error),
        }
    }

    fn handle_stream_error(e: TlsConnectionError) -> Error {
        match e {
            TlsConnectionError::TlsLib(rustls::Error::General(desc)) => {
                if let Some(index) = desc.find(TLS_CUSTOM_CALLBACK_ERROR) {
                    let start = index + TLS_CUSTOM_CALLBACK_ERROR.len() + 1;
                    let end = match desc[start..].find(')') {
                        Some(index) => start + index,
                        None => return Error::TlsStream,
                    };
                    return Error::TlsVerifyPeerCert(desc[start..end].to_string());
                }
                Error::TlsStream
            }
            _ => Error::TlsStream,
        }
    }

    fn transport_mut(&mut self) -> &mut T {
        match self {
            Self::Server(conn) => &mut conn.transport,
            Self::Client(conn) => &mut conn.transport,
        }
    }
}

pub struct TlsConfig {
    pub(crate) resolver: Resolver,
    pub(crate) verifier: Verifier,
}

impl TlsConfig {
    pub fn new(
        certs_der: Vec<Vec<u8>>,
        signing_key: EcdsaPk,
        verify_callback: fn(&[u8], &[u8]) -> core::result::Result<(), Error>,
        verify_callback_data: Vec<u8>,
    ) -> Result<Self> {
        let mut certs = Vec::new();
        for cert in certs_der {
            let cert = CertificateDer::from(cert);
            certs.push(cert)
        }

        let resolver = Resolver::new(certs, signing_key);
        let verifier = Verifier::new(verify_callback, verify_callback_data);

        Ok(Self { resolver, verifier })
    }

    pub fn set_certs(&mut self, certs_der: Vec<Vec<u8>>, signing_key: EcdsaPk) -> Result<()> {
        let mut certs = Vec::new();
        for cert in certs_der {
            let cert = CertificateDer::from(cert);
            certs.push(cert)
        }

        self.resolver = Resolver::new(certs, signing_key);

        Ok(())
    }

    pub fn set_verify_callback(
        &mut self,
        cb: fn(&[u8], &[u8]) -> core::result::Result<(), Error>,
        data: Vec<u8>,
    ) -> Result<()> {
        self.verifier = Verifier::new(cb, data);

        Ok(())
    }
    pub fn tls_client<T: AsyncRead + AsyncWrite + Unpin>(
        self,
        stream: T,
    ) -> Result<SecureChannel<T>> {
        let client_config = ClientConfig::builder_with_details(
            Arc::new(crypto_provider()),
            Arc::new(TlsTimeProvider {}),
        )
        .with_protocol_versions(&[&TLS13])
        .map_err(Error::SetupTlsContext)?
        // `dangerous()` method of `ClientConfig` allows setting inadvisable options, such as replacing the
        // certificate verification process.
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(self.verifier))
        .with_client_cert_resolver(Arc::new(self.resolver));

        let connection = TlsClientConnection::new(Arc::new(client_config), stream)
            .map_err(|_| Error::TlsConnection)?;

        Ok(SecureChannel::new(TlsConnection::Client(connection)))
    }

    pub fn tls_server<T: AsyncRead + AsyncWrite + Unpin>(
        self,
        stream: T,
    ) -> Result<SecureChannel<T>> {
        let server_config = ServerConfig::builder_with_details(
            Arc::new(crypto_provider()),
            Arc::new(TlsTimeProvider {}),
        )
        .with_protocol_versions(&[&TLS13])
        .map_err(Error::SetupTlsContext)?
        .with_client_cert_verifier(Arc::new(self.verifier))
        .with_cert_resolver(Arc::new(self.resolver));

        let connection = TlsServerConnection::new(Arc::new(server_config), stream)
            .map_err(|_| Error::TlsConnection)?;

        Ok(SecureChannel::new(TlsConnection::Server(connection)))
    }
}

pub(crate) fn crypto_provider() -> CryptoProvider {
    let mut provider = default_provider();
    provider.cipher_suites = vec![TLS13_AES_256_GCM_SHA384];
    provider.kx_groups = vec![SECP384R1];
    provider
}

#[derive(Debug)]
pub(crate) struct Resolver {
    certs: Vec<CertificateDer<'static>>,
    signing_key: EcdsaPk,
}

impl Resolver {
    pub fn new(certs: Vec<CertificateDer<'static>>, signing_key: EcdsaPk) -> Self {
        Self { certs, signing_key }
    }

    fn certified_key(&self) -> Option<Arc<dyn SigningKey>> {
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.signing_key.private_key()));
        any_ecdsa_type(&private_key).ok()
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(Arc::new(CertifiedKey::new(
            self.certs.clone(),
            self.certified_key()?,
        )))
    }
}

impl ResolvesClientCert for Resolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::new(CertifiedKey::new(
            self.certs.clone(),
            self.certified_key()?,
        )))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub(crate) struct Verifier {
    // Function `cb` takes peer's certificates as first parameter and
    // additional data required by `cb` to verify the certs as second
    // parameter.
    cb: fn(&[u8], &[u8]) -> Result<()>,
    data: Vec<u8>,
}

impl Verifier {
    pub fn new(cb: fn(&[u8], &[u8]) -> Result<()>, data: Vec<u8>) -> Self {
        Self { cb, data }
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> core::result::Result<ServerCertVerified, rustls::Error> {
        if let Err(e) = (self.cb)(end_entity.as_ref(), &self.data) {
            match e {
                Error::TlsVerifyPeerCert(e) => Err(rustls::Error::General(format!(
                    "{}({})",
                    TLS_CUSTOM_CALLBACK_ERROR, e
                ))),
                _ => Err(rustls::Error::General("Unexpected".to_string())),
            }
        } else {
            Ok(ServerCertVerified::assertion())
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for Verifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> core::result::Result<ClientCertVerified, rustls::Error> {
        if let Err(e) = (self.cb)(end_entity.as_ref(), &self.data) {
            match e {
                Error::TlsVerifyPeerCert(e) => Err(rustls::Error::General(format!(
                    "{}({})",
                    TLS_CUSTOM_CALLBACK_ERROR, e
                ))),
                _ => Err(rustls::Error::General("Unexpected".to_string())),
            }
        } else {
            Ok(ClientCertVerified::assertion())
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

pub(crate) mod connection {
    use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
    use async_io::{AsyncRead, AsyncWrite};
    use rust_std_stub::io;
    use rustls::{
        client::UnbufferedClientConnection,
        server::UnbufferedServerConnection,
        unbuffered::{
            AppDataRecord, ConnectionState, EncodeError, EncryptError, InsufficientSizeError,
            UnbufferedStatus,
        },
        ClientConfig, ServerConfig,
    };

    pub const PAGE_SIZE: usize = 0x1000;
    pub const TLS_BUFFER_SIZE: usize = 16 * PAGE_SIZE;
    pub const APP_DATA_BUFFER_LIMIT: usize = PAGE_SIZE;

    #[derive(Debug)]
    pub enum TlsConnectionError {
        /// Error occurs during encoding tls data
        Encode,

        /// Error occurs during encrypt tls data
        Encrypt,

        /// Unexpected tls state
        UnexpectedState,

        /// Tls lib error
        TlsLib(rustls::Error),

        /// Failed to read/write transport
        Transport,
    }

    impl From<io::Error> for TlsConnectionError {
        fn from(_: io::Error) -> Self {
            Self::Transport
        }
    }

    impl From<rustls::Error> for TlsConnectionError {
        fn from(value: rustls::Error) -> Self {
            Self::TlsLib(value)
        }
    }

    impl From<rustls::unbuffered::EncodeError> for TlsConnectionError {
        fn from(_: rustls::unbuffered::EncodeError) -> Self {
            Self::Encode
        }
    }

    impl From<rustls::unbuffered::EncryptError> for TlsConnectionError {
        fn from(_: rustls::unbuffered::EncryptError) -> Self {
            Self::Encrypt
        }
    }

    pub struct TlsBuffer {
        inner: Vec<u8>,
        used: usize,
    }

    impl TlsBuffer {
        pub fn new() -> Self {
            TlsBuffer {
                inner: vec![0u8; TLS_BUFFER_SIZE],
                used: 0,
            }
        }

        // Try to run `f` and resize the buffer and try again if we got `InsufficientSizeError`
        pub fn try_or_resize_and_retry<E>(
            &mut self,
            mut f: impl FnMut(&mut [u8]) -> Result<usize, E>,
            map_err: impl FnOnce(E) -> Result<InsufficientSizeError, TlsConnectionError>,
        ) -> Result<usize, TlsConnectionError> {
            let written = match f(self.unused_mut()) {
                Ok(written) => written,

                Err(e) => {
                    let InsufficientSizeError { required_size } = map_err(e)?;
                    let new_len = self.used + required_size;
                    self.inner.resize(new_len, 0);

                    f(self.unused_mut()).map_err(|_| TlsConnectionError::Encode)?
                }
            };

            self.used += written;

            Ok(written)
        }

        // Get the immutable reference of used buffer
        pub fn used(&self) -> &[u8] {
            &self.inner[..self.used]
        }

        // Get the mutable reference of used buffer
        pub fn used_mut(&mut self) -> &mut [u8] {
            &mut self.inner[..self.used]
        }

        // Get the mutable reference of unused buffer
        pub fn unused_mut(&mut self) -> &mut [u8] {
            &mut self.inner[self.used..]
        }

        // Reset the used
        pub fn reset(&mut self) {
            self.used = 0;
        }

        // Accumulate number of used bytes
        pub fn consume(&mut self, size: usize) {
            self.used += size;
        }

        // Discard the first `size` bytes
        pub fn discard(&mut self, size: usize) {
            self.inner.copy_within(size..self.used, 0);
            self.used -= size;
        }
    }

    pub struct TlsServerConnection<T: AsyncRead + AsyncWrite + Unpin> {
        conn: UnbufferedServerConnection,
        input: TlsBuffer,
        output: TlsBuffer,
        pub transport: T,
        is_handshaking: bool,
        received_app_data: ChunkVecBuffer,
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> TlsServerConnection<T> {
        pub fn new(config: Arc<ServerConfig>, transport: T) -> Result<Self, TlsConnectionError> {
            Ok(Self {
                conn: UnbufferedServerConnection::new(config)?,
                transport,
                input: TlsBuffer::new(),
                output: TlsBuffer::new(),
                is_handshaking: true,
                received_app_data: ChunkVecBuffer::new(Some(APP_DATA_BUFFER_LIMIT)),
            })
        }

        pub async fn read(&mut self, data: &mut [u8]) -> Result<usize, TlsConnectionError> {
            if self.is_handshaking {
                self.process_tls_status().await?;
            }

            if !self.received_app_data.is_empty() {
                return Ok(self.received_app_data.read(data));
            }

            loop {
                let UnbufferedStatus { mut discard, state } =
                    self.conn.process_tls_records(self.input.used_mut());
                match state? {
                    ConnectionState::ReadTraffic(mut state) => {
                        while let Some(res) = state.next_record() {
                            let AppDataRecord {
                                discard: new_discard,
                                payload,
                            } = res?;
                            discard += new_discard;
                            self.received_app_data.append(payload.to_vec());
                        }
                        let read = self.received_app_data.read(data);
                        self.input.discard(discard);
                        return Ok(read);
                    }
                    ConnectionState::WriteTraffic(..) => {
                        let size = self.transport.read(self.input.unused_mut()).await?;
                        self.input.consume(size);
                    }
                    _ => return Err(TlsConnectionError::UnexpectedState),
                }
                self.input.discard(discard);
            }
        }

        pub async fn write(&mut self, data: &[u8]) -> Result<usize, TlsConnectionError> {
            if self.is_handshaking {
                self.process_tls_status().await?;
            }

            loop {
                let UnbufferedStatus { mut discard, state } =
                    self.conn.process_tls_records(self.input.used_mut());

                match state? {
                    ConnectionState::ReadTraffic(mut state) => {
                        while let Some(res) = state.next_record() {
                            let AppDataRecord {
                                discard: new_discard,
                                payload,
                            } = res?;
                            discard += new_discard;
                            self.received_app_data.append(payload.to_vec());
                        }
                    }
                    ConnectionState::WriteTraffic(mut state) => {
                        let map_err = |e| {
                            if let EncryptError::InsufficientSize(is) = &e {
                                Ok(*is)
                            } else {
                                Err(e.into())
                            }
                        };
                        self.output.try_or_resize_and_retry(
                            |out_buffer| state.encrypt(data, out_buffer),
                            map_err,
                        )?;
                        self.transport.write(self.output.used()).await?;
                        self.output.reset();
                        break;
                    }
                    _ => return Err(TlsConnectionError::UnexpectedState),
                }
                self.input.discard(discard);
            }
            Ok(data.len())
        }

        async fn process_tls_status(&mut self) -> Result<(), TlsConnectionError> {
            loop {
                let UnbufferedStatus { mut discard, state } =
                    self.conn.process_tls_records(self.input.used_mut());

                match state {
                    Ok(state) => match state {
                        ConnectionState::EncodeTlsData(mut state) => {
                            let _ = self.output.try_or_resize_and_retry(
                                |out_buffer| state.encode(out_buffer),
                                |e| {
                                    if let EncodeError::InsufficientSize(is) = &e {
                                        Ok(*is)
                                    } else {
                                        Err(e.into())
                                    }
                                },
                            )?;
                        }
                        ConnectionState::TransmitTlsData(state) => {
                            self.transport.write(self.output.used()).await?;
                            self.output.reset();
                            state.done();
                        }
                        ConnectionState::BlockedHandshake { .. } => {
                            let size = self.transport.read(self.input.unused_mut()).await?;
                            self.input.consume(size);
                        }
                        ConnectionState::ReadTraffic(mut state) => {
                            while let Some(res) = state.next_record() {
                                let AppDataRecord {
                                    discard: new_discard,
                                    payload,
                                } = res?;
                                discard += new_discard;
                                self.received_app_data.append(payload.to_vec());
                            }
                            self.is_handshaking = false;
                            self.input.discard(discard);
                            break;
                        }
                        ConnectionState::WriteTraffic { .. } => {
                            self.is_handshaking = false;
                            self.input.discard(discard);
                            break;
                        }
                        _ => return Err(TlsConnectionError::UnexpectedState),
                    },
                    Err(e) => {
                        self.input.discard(discard);
                        self.handle_tls_error().await?;
                        return Err(TlsConnectionError::TlsLib(e));
                    }
                }
                self.input.discard(discard);
            }
            Ok(())
        }

        async fn handle_tls_error(&mut self) -> Result<(), TlsConnectionError> {
            let status = self.conn.process_tls_records(self.input.used_mut());
            match status.state? {
                ConnectionState::EncodeTlsData(mut state) => {
                    let _ = self.output.try_or_resize_and_retry(
                        |out_buffer| state.encode(out_buffer),
                        |e| {
                            if let EncodeError::InsufficientSize(is) = &e {
                                Ok(*is)
                            } else {
                                Err(e.into())
                            }
                        },
                    )?;

                    self.transport.write(self.output.used()).await?;
                    self.output.reset();
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    // Derived from `rustls::vecbuf`
    struct ChunkVecBuffer {
        chunks: VecDeque<Vec<u8>>,
        limit: Option<usize>,
    }

    impl ChunkVecBuffer {
        fn new(limit: Option<usize>) -> Self {
            Self {
                chunks: VecDeque::new(),
                limit,
            }
        }

        fn is_full(&self) -> bool {
            self.limit
                .map(|limit| self.len() > limit)
                .unwrap_or_default()
        }

        fn is_empty(&self) -> bool {
            self.chunks.is_empty()
        }

        fn len(&self) -> usize {
            let mut len = 0;
            for ch in &self.chunks {
                len += ch.len();
            }
            len
        }

        fn append(&mut self, bytes: Vec<u8>) -> usize {
            let len = bytes.len();

            if !bytes.is_empty() {
                self.chunks.push_back(bytes);
            }

            len
        }

        fn read(&mut self, buf: &mut [u8]) -> usize {
            let mut offs = 0;

            while offs < buf.len() && !self.is_empty() {
                let used;
                if buf.len() - offs >= self.chunks[0].len() {
                    used = self.chunks[0].len();
                    buf[offs..offs + used].copy_from_slice(&self.chunks[0]);
                } else {
                    used = buf.len() - offs;
                    buf[offs..].copy_from_slice(&self.chunks[0][..used]);
                }

                self.consume(used);
                offs += used;
            }

            offs
        }

        fn consume(&mut self, mut used: usize) {
            while let Some(mut buf) = self.chunks.pop_front() {
                if used < buf.len() {
                    buf.drain(..used);
                    self.chunks.push_front(buf);
                    break;
                } else {
                    used -= buf.len();
                }
            }
        }
    }

    pub struct TlsClientConnection<T: AsyncRead + AsyncWrite + Unpin> {
        conn: UnbufferedClientConnection,
        input: TlsBuffer,
        output: TlsBuffer,
        pub transport: T,
        is_handshaking: bool,
        received_app_data: ChunkVecBuffer,
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> TlsClientConnection<T> {
        pub fn new(config: Arc<ClientConfig>, transport: T) -> Result<Self, TlsConnectionError> {
            Ok(Self {
                conn: UnbufferedClientConnection::new(config, "localhost".try_into().unwrap())?,
                transport,
                input: TlsBuffer::new(),
                output: TlsBuffer::new(),
                is_handshaking: true,
                received_app_data: ChunkVecBuffer::new(Some(APP_DATA_BUFFER_LIMIT)),
            })
        }

        pub async fn read(&mut self, data: &mut [u8]) -> Result<usize, TlsConnectionError> {
            if self.is_handshaking {
                self.process_tls_status().await?;
            }

            if !self.received_app_data.is_empty() {
                return Ok(self.received_app_data.read(data));
            }

            loop {
                let UnbufferedStatus { mut discard, state } =
                    self.conn.process_tls_records(self.input.used_mut());
                match state? {
                    ConnectionState::ReadTraffic(mut state) => {
                        while let Some(res) = state.next_record() {
                            let AppDataRecord {
                                discard: new_discard,
                                payload,
                            } = res?;
                            if !self.received_app_data.is_full() {
                                discard += new_discard;
                                self.received_app_data.append(payload.to_vec());
                            }
                        }
                        let read = self.received_app_data.read(data);
                        self.input.discard(discard);
                        return Ok(read);
                    }
                    ConnectionState::WriteTraffic(..) => {
                        let size = self.transport.read(self.input.unused_mut()).await?;
                        self.input.consume(size);
                    }
                    _ => return Err(TlsConnectionError::UnexpectedState),
                }
                self.input.discard(discard);
            }
        }

        pub async fn write(&mut self, data: &[u8]) -> Result<usize, TlsConnectionError> {
            if self.is_handshaking {
                self.process_tls_status().await?;
            }

            loop {
                let UnbufferedStatus { mut discard, state } =
                    self.conn.process_tls_records(self.input.used_mut());

                match state? {
                    ConnectionState::ReadTraffic(mut state) => {
                        while let Some(res) = state.next_record() {
                            let AppDataRecord {
                                discard: new_discard,
                                payload,
                            } = res?;
                            discard += new_discard;
                            self.received_app_data.append(payload.to_vec());
                        }
                    }
                    ConnectionState::WriteTraffic(mut state) => {
                        let map_err = |e| {
                            if let EncryptError::InsufficientSize(is) = &e {
                                Ok(*is)
                            } else {
                                Err(e.into())
                            }
                        };
                        self.output.try_or_resize_and_retry(
                            |out_buffer| state.encrypt(data, out_buffer),
                            map_err,
                        )?;
                        self.transport.write(self.output.used()).await?;
                        self.output.reset();
                        break;
                    }
                    _ => return Err(TlsConnectionError::UnexpectedState),
                }
                self.input.discard(discard);
            }
            Ok(data.len())
        }

        async fn process_tls_status(&mut self) -> Result<(), TlsConnectionError> {
            loop {
                let UnbufferedStatus { mut discard, state } =
                    self.conn.process_tls_records(self.input.used_mut());

                match state {
                    Ok(state) => match state {
                        ConnectionState::EncodeTlsData(mut state) => {
                            let _ = self.output.try_or_resize_and_retry(
                                |out_buffer| state.encode(out_buffer),
                                |e| {
                                    if let EncodeError::InsufficientSize(is) = &e {
                                        Ok(*is)
                                    } else {
                                        Err(e.into())
                                    }
                                },
                            )?;
                        }
                        ConnectionState::TransmitTlsData(state) => {
                            self.transport.write(self.output.used()).await?;
                            self.output.reset();
                            state.done();
                        }
                        ConnectionState::BlockedHandshake { .. } => {
                            let size = self.transport.read(self.input.unused_mut()).await?;
                            self.input.consume(size);
                        }
                        ConnectionState::ReadTraffic(mut state) => {
                            while let Some(res) = state.next_record() {
                                let AppDataRecord {
                                    discard: new_discard,
                                    payload,
                                } = res?;
                                discard += new_discard;
                                self.received_app_data.append(payload.to_vec());
                            }
                            self.is_handshaking = false;
                            self.input.discard(discard);
                            break;
                        }
                        ConnectionState::WriteTraffic { .. } => {
                            self.is_handshaking = false;
                            self.input.discard(discard);
                            break;
                        }
                        _ => return Err(TlsConnectionError::UnexpectedState),
                    },
                    Err(e) => {
                        self.input.discard(discard);
                        self.handle_tls_error().await?;
                        return Err(TlsConnectionError::TlsLib(e));
                    }
                }
                self.input.discard(discard);
            }
            Ok(())
        }

        async fn handle_tls_error(&mut self) -> Result<(), TlsConnectionError> {
            let status = self.conn.process_tls_records(self.input.used_mut());
            match status.state? {
                ConnectionState::EncodeTlsData(mut state) => {
                    let _ = self.output.try_or_resize_and_retry(
                        |out_buffer| state.encode(out_buffer),
                        |e| {
                            if let EncodeError::InsufficientSize(is) = &e {
                                Ok(*is)
                            } else {
                                Err(e.into())
                            }
                        },
                    )?;
                    self.transport.write(self.output.used()).await?;
                    self.output.reset();
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct TlsTimeProvider;

impl TimeProvider for TlsTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        // Avoid RTC access in AzCVMEmu; use a fixed timestamp.
        #[cfg(feature = "AzCVMEmu")]
        {
            Some(UnixTime::since_unix_epoch(Duration::new(1704067200u64, 0)))
        }
        #[cfg(not(feature = "AzCVMEmu"))]
        {
            Some(UnixTime::since_unix_epoch(Duration::new(
                sys_time::get_sys_time()? as u64,
                0,
            )))
        }
    }
}
