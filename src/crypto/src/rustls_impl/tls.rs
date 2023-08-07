// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::string::ToString;
use alloc::vec::Vec;
use rust_std_stub::io::{self, Read, Write};
use rust_std_stub::sync::Arc;
use rust_std_stub::time::SystemTime;
use rustls::cipher_suite::TLS13_AES_256_GCM_SHA384;
use rustls::client::{
    ResolvesClientCert, ServerCertVerified, ServerCertVerifier, WebPkiServerVerifier,
};
use rustls::crypto::ring::Ring;
use rustls::kx_group::SECP384R1;
use rustls::server::{ClientCertVerified, ClientCertVerifier, ClientHello, ResolvesServerCert};
use rustls::sign::{any_ecdsa_type, CertifiedKey, SigningKey};
use rustls::{
    Certificate, ClientConfig, ClientConnection, PrivateKey, ServerConfig, ServerConnection,
    ServerName,
};

use crate::{Error, Result};

use super::ecdsa::EcdsaPk;

pub type TlsLibError = rustls::Error;
const TLS_CUSTOM_CALLBACK_ERROR: &str = "TlsCustomCallbackError";

pub struct SecureChannel<T: Read + Write> {
    conn: TlsConnection,
    stream: T,
}

impl<T> SecureChannel<T>
where
    T: Read + Write,
{
    fn new(conn: TlsConnection, stream: T) -> Self {
        SecureChannel { conn, stream }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.conn.write(&mut self.stream, data)
    }

    pub fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        self.conn.read(&mut self.stream, data)
    }

    pub fn peer_cert(&mut self) -> Option<Vec<&[u8]>> {
        self.conn.peer_cert()
    }
}

enum TlsConnection {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl TlsConnection {
    fn read<T: Read + Write>(&mut self, stream: &mut T, data: &mut [u8]) -> Result<usize> {
        match self {
            Self::Server(conn) => {
                let mut tls_stream = rustls::Stream::new(conn, stream);
                tls_stream
                    .read(data)
                    .map_err(|e| Self::handle_stream_error(e))
            }
            Self::Client(conn) => {
                let mut tls_stream = rustls::Stream::new(conn, stream);
                tls_stream
                    .read(data)
                    .map_err(|e| Self::handle_stream_error(e))
            }
        }
    }

    fn write<T: Read + Write>(&mut self, stream: &mut T, data: &[u8]) -> Result<usize> {
        match self {
            Self::Server(conn) => {
                let mut tls_stream = rustls::Stream::new(conn, stream);
                tls_stream
                    .write(data)
                    .map_err(|e| Self::handle_stream_error(e))
            }
            Self::Client(conn) => {
                let mut tls_stream = rustls::Stream::new(conn, stream);
                tls_stream
                    .write(data)
                    .map_err(|e| Self::handle_stream_error(e))
            }
        }
    }

    fn peer_cert(&self) -> Option<Vec<&[u8]>> {
        let mut list = Vec::new();
        match self {
            Self::Server(conn) => conn.peer_certificates().map(|certs| {
                for cert in certs {
                    list.push(cert.as_ref())
                }
                list
            }),
            Self::Client(conn) => conn.peer_certificates().map(|certs| {
                for cert in certs {
                    list.push(cert.as_ref())
                }
                list
            }),
        }
    }

    fn handle_stream_error(e: io::Error) -> Error {
        match e.kind() {
            io::ErrorKind::InvalidData => {
                let desc = e.to_string();

                if let Some(index) = desc.find(TLS_CUSTOM_CALLBACK_ERROR) {
                    let start = index + TLS_CUSTOM_CALLBACK_ERROR.len() + 1;
                    let end = match desc[start..].find(')') {
                        Some(index) => start + index,
                        None => return Error::Unexpected,
                    };

                    return Error::TlsVerifyPeerCert(desc[start..end].to_string());
                }

                Error::TlsStream
            }
            _ => Error::TlsStream,
        }
    }
}

pub struct TlsConfig {
    resolver: Resolver,
    verifier: Verifier,
}

impl TlsConfig {
    pub fn new(
        certs_der: Vec<Vec<u8>>,
        signing_key: EcdsaPk,
        verify_callback: fn(&[u8]) -> Result<()>,
    ) -> Result<Self> {
        let mut certs = Vec::new();
        for cert in certs_der {
            let cert = rustls::Certificate(cert);
            certs.push(cert)
        }

        let resolver = Resolver::new(certs, signing_key);
        let verifier = Verifier::new(verify_callback);

        Ok(Self { resolver, verifier })
    }

    pub fn set_certs(&mut self, certs_der: Vec<Vec<u8>>, signing_key: EcdsaPk) -> Result<()> {
        let mut certs = Vec::new();
        for cert in certs_der {
            let cert = rustls::Certificate(cert);
            certs.push(cert)
        }

        self.resolver = Resolver::new(certs, signing_key);

        Ok(())
    }

    pub fn set_verify_callback(&mut self, cb: fn(&[u8]) -> Result<()>) -> Result<()> {
        self.verifier = Verifier::new(cb);

        Ok(())
    }

    pub fn tls_client<T: Read + Write>(self, stream: T) -> Result<SecureChannel<T>> {
        let client_config: ClientConfig<Ring> = ClientConfig::builder()
            .with_cipher_suites(&[TLS13_AES_256_GCM_SHA384])
            .with_kx_groups(&[&SECP384R1])
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::SetupTlsContext(e))?
            .with_custom_certificate_verifier(Arc::new(self.verifier))
            .with_client_cert_resolver(Arc::new(self.resolver));

        let connection = rustls::ClientConnection::new(
            alloc::sync::Arc::new(client_config),
            ServerName::try_from("localhost").map_err(|_| Error::InvalidDnsName)?,
        )
        .map_err(|e| Error::SetupTlsContext(e))?;

        Ok(SecureChannel::new(
            TlsConnection::Client(connection),
            stream,
        ))
    }

    pub fn tls_server<T: Read + Write>(self, stream: T) -> Result<SecureChannel<T>> {
        let server_config: ServerConfig<Ring> = ServerConfig::builder()
            .with_cipher_suites(&[TLS13_AES_256_GCM_SHA384])
            .with_kx_groups(&[&SECP384R1])
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::SetupTlsContext(e))?
            .with_client_cert_verifier(Arc::new(self.verifier))
            .with_cert_resolver(Arc::new(self.resolver));

        let connection = rustls::ServerConnection::new(alloc::sync::Arc::new(server_config))
            .map_err(|e| Error::SetupTlsContext(e))?;

        Ok(SecureChannel::new(
            TlsConnection::Server(connection),
            stream,
        ))
    }
}

struct Resolver {
    certs: Vec<Certificate>,
    signing_key: EcdsaPk,
}

impl Resolver {
    pub fn new(certs: Vec<Certificate>, signing_key: EcdsaPk) -> Self {
        Self { certs, signing_key }
    }

    fn certified_key(&self) -> Option<Arc<dyn SigningKey>> {
        let mut private_key = PrivateKey(self.signing_key.private_key().to_vec());
        let signing_key = any_ecdsa_type(&private_key).ok()?;
        // Clean up used private key data
        private_key.0.fill(0);

        Some(signing_key)
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

struct Verifier {
    cb: fn(&[u8]) -> Result<()>,
}

impl Verifier {
    pub fn new(cb: fn(&[u8]) -> Result<()>) -> Self {
        Self { cb }
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> core::result::Result<ServerCertVerified, rustls::Error> {
        if let Err(e) = (self.cb)(end_entity.as_ref()) {
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
        cert: &Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        WebPkiServerVerifier::default_verify_tls13_signature(message, cert, dss)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        WebPkiServerVerifier::default_verify_tls12_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        WebPkiServerVerifier::default_supported_verify_schemes()
    }
}

impl ClientCertVerifier for Verifier {
    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime,
    ) -> core::result::Result<ClientCertVerified, rustls::Error> {
        if let Err(e) = (self.cb)(end_entity.as_ref()) {
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

    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        WebPkiServerVerifier::default_verify_tls13_signature(message, cert, dss)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        WebPkiServerVerifier::default_verify_tls12_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        WebPkiServerVerifier::default_supported_verify_schemes()
    }
}
