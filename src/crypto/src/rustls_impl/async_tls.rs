// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{
    future::poll_fn,
    task::{ready, Context, Poll},
};

use alloc::vec::Vec;
use async_io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use async_rustls::Stream;
use rust_std_stub::io;

use crate::{
    tls::{TlsConfig, TlsConnection},
    Result,
};

pub struct SecureChannelAsync<T: AsyncRead + AsyncWrite + Unpin> {
    conn: TlsConnection,
    stream: T,
}

impl<T> SecureChannelAsync<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn new(conn: TlsConnection, stream: T) -> Self {
        Self { conn, stream }
    }

    pub async fn start(&mut self) -> Result<()> {
        poll_fn(|cx| self.conn.async_do_handshake(&mut self.stream, cx))
            .await
            .map_err(|e| e.into())
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.conn.async_write(&mut self.stream, data).await
    }

    pub async fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        self.conn.async_read(&mut self.stream, data).await
    }

    pub fn peer_cert(&mut self) -> Option<Vec<&[u8]>> {
        self.conn.peer_cert()
    }
}

impl TlsConnection {
    fn async_do_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        io: &mut T,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self {
            Self::Server(conn) => {
                let mut tls_stream = Stream::new(io, conn);

                while tls_stream.session.is_handshaking() {
                    ready!(tls_stream.handshake(cx))?;
                }

                while tls_stream.session.wants_write() {
                    ready!(tls_stream.write_io(cx))?;
                }
            }
            Self::Client(conn) => {
                let mut tls_stream = Stream::new(io, conn);

                while tls_stream.session.is_handshaking() {
                    ready!(tls_stream.handshake(cx))?;
                }

                while tls_stream.session.wants_write() {
                    ready!(tls_stream.write_io(cx))?;
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    async fn async_read<T: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        stream: &mut T,
        data: &mut [u8],
    ) -> Result<usize> {
        match self {
            Self::Server(conn) => {
                let mut tls_stream = Stream::new(stream, conn);
                tls_stream.read(data).await.map_err(|e| e.into())
            }
            Self::Client(conn) => {
                let mut tls_stream = Stream::new(stream, conn);
                tls_stream.read(data).await.map_err(|e| e.into())
            }
        }
    }

    async fn async_write<T: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        stream: &mut T,
        data: &[u8],
    ) -> Result<usize> {
        match self {
            Self::Server(conn) => {
                let mut tls_stream = Stream::new(stream, conn);
                tls_stream.write(data).await.map_err(|e| e.into())
            }
            Self::Client(conn) => {
                let mut tls_stream = Stream::new(stream, conn);
                tls_stream.write(data).await.map_err(|e| e.into())
            }
        }
    }
}

impl TlsConfig {
    pub fn async_tls_client<T: AsyncRead + AsyncWrite + Unpin>(
        self,
        stream: T,
    ) -> Result<SecureChannelAsync<T>> {
        let connection = self.client_conn()?;

        Ok(SecureChannelAsync::new(
            TlsConnection::Client(connection),
            stream,
        ))
    }

    pub fn async_tls_server<T: AsyncRead + AsyncWrite + Unpin>(
        self,
        stream: T,
    ) -> Result<SecureChannelAsync<T>> {
        let connection = self.server_conn()?;

        Ok(SecureChannelAsync::new(
            TlsConnection::Server(connection),
            stream,
        ))
    }
}
