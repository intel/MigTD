use core::{
    future::Future,
    pin::Pin,
    result::Result,
    task::{Context, Poll},
};

use rust_std_stub::io;

use crate::{AsyncRead, AsyncWrite};

/// Extension trait for [`AsyncRead`].
pub trait AsyncReadExt: AsyncRead {
    /// Reads some bytes from the byte stream.
    ///
    /// On success, returns the total number of bytes read.
    ///
    /// If the return value is `Ok(n)`, then it must be guaranteed that
    /// `0 <= n <= buf.len()`. A nonzero `n` value indicates that the buffer has been
    /// filled with `n` bytes of data. If `n` is `0`, then it can indicate one of two
    /// scenarios:
    ///
    /// 1. This reader has reached its "end of file" and will likely no longer be able to
    ///    produce bytes. Note that this does not mean that the reader will always no
    ///    longer be able to produce bytes.
    /// 2. The buffer specified was 0 bytes in length.
    ///
    /// # Examples
    ///
    /// ```
    /// use futures_lite::io::{AsyncReadExt, BufReader};
    ///
    /// # spin_on::spin_on(async {
    /// let input: &[u8] = b"hello";
    /// let mut reader = BufReader::new(input);
    ///
    /// let mut buf = vec![0; 1024];
    /// let n = reader.read(&mut buf).await?;
    /// # std::io::Result::Ok(()) });
    /// ```
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadFuture<'a, Self>
    where
        Self: Unpin,
    {
        ReadFuture { reader: self, buf }
    }
}

impl<R: AsyncRead + ?Sized> AsyncReadExt for R {}

/// Extension trait for [`AsyncWrite`].
pub trait AsyncWriteExt: AsyncWrite {
    /// Writes some bytes into the byte stream.
    ///
    /// Returns the number of bytes written from the start of the buffer.
    ///
    /// If the return value is `Ok(n)` then it must be guaranteed that
    /// `0 <= n <= buf.len()`. A return value of `0` typically means that the underlying
    /// object is no longer able to accept bytes and will likely not be able to in the
    /// future as well, or that the provided buffer is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use futures_lite::io::{AsyncWriteExt, BufWriter};
    ///
    /// # spin_on::spin_on(async {
    /// let mut output = Vec::new();
    /// let mut writer = BufWriter::new(&mut output);
    ///
    /// let n = writer.write(b"hello").await?;
    /// # std::io::Result::Ok(()) });
    /// ```
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> WriteFuture<'a, Self>
    where
        Self: Unpin,
    {
        WriteFuture { writer: self, buf }
    }
}

impl<R: AsyncWrite + ?Sized> AsyncWriteExt for R {}

/// Future for the [`AsyncReadExt::read()`] method.
#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct ReadFuture<'a, R: Unpin + ?Sized> {
    reader: &'a mut R,
    buf: &'a mut [u8],
}

impl<R: Unpin + ?Sized> Unpin for ReadFuture<'_, R> {}

impl<R: AsyncRead + Unpin + ?Sized> Future for ReadFuture<'_, R> {
    type Output = Result<usize, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self { reader, buf } = &mut *self;
        Pin::new(reader).poll_read(cx, buf)
    }
}

/// Future for the [`AsyncWriteExt::write()`] method.
#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct WriteFuture<'a, W: Unpin + ?Sized> {
    writer: &'a mut W,
    buf: &'a [u8],
}

impl<W: Unpin + ?Sized> Unpin for WriteFuture<'_, W> {}

impl<W: AsyncWrite + Unpin + ?Sized> Future for WriteFuture<'_, W> {
    type Output = Result<usize, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let buf = self.buf;
        Pin::new(&mut *self.writer).poll_write(cx, buf)
    }
}
