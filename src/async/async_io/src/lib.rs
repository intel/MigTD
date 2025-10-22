//! Asynchronous I/O
//!
//! This crate contains the `AsyncRead` and `AsyncWrite` traits.
//!

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]
// It cannot be included in the published code because this lints have false positives in the minimum required version.
#![cfg_attr(test, warn(single_use_lifetimes))]
#![doc(test(
    no_crate_inject,
    attr(
        deny(warnings, rust_2018_idioms, single_use_lifetimes),
        allow(dead_code, unused_assignments, unused_variables)
    )
))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use rust_std_stub::io;

// Re-export some types from `std::io` so that users don't have to deal
// with conflicts when `use`ing `futures::io` and `std::io`.
#[allow(unreachable_pub)] // https://github.com/rust-lang/rust/issues/57411
#[doc(no_inline)]
pub use io::{Error, ErrorKind, IoSlice, IoSliceMut, Result};

/// Read bytes asynchronously.
pub trait AsyncRead {
    /// Attempt to read from the `AsyncRead` into `buf`.
    fn read(&mut self, buf: &mut [u8]) -> impl core::future::Future<Output = Result<usize>> + Send;
}

/// Write bytes asynchronously.
pub trait AsyncWrite {
    /// Attempt to write the `buf` into `AsyncWrite`.
    fn write(&mut self, buf: &[u8]) -> impl core::future::Future<Output = Result<usize>> + Send;
}
