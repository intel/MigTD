#[cfg(test)]
mod tests;

use crate::io::{self, Error, ErrorKind, Initializer, IoSlice, IoSliceMut, Read, Write};
use core::cmp;
use core::fmt;
use core::mem;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

// =============================================================================
// Forwarding implementations

impl<R: Read + ?Sized> Read for &mut R {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (**self).read_vectored(bufs)
    }

    #[inline]
    fn is_read_vectored(&self) -> bool {
        (**self).is_read_vectored()
    }

    #[inline]
    unsafe fn initializer(&self) -> Initializer {
        (**self).initializer()
    }

    #[inline]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        (**self).read_to_end(buf)
    }

    #[inline]
    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        (**self).read_to_string(buf)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact(buf)
    }
}
impl<W: Write + ?Sized> Write for &mut W {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (**self).write(buf)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (**self).write_vectored(bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        (**self).is_write_vectored()
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        (**self).flush()
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        (**self).write_all(buf)
    }

    #[inline]
    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> io::Result<()> {
        (**self).write_fmt(fmt)
    }
}
// impl<S: Seek + ?Sized> Seek for &mut S {
//     #[inline]
//     fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
//         (**self).seek(pos)
//     }
// }
// impl<B: BufRead + ?Sized> BufRead for &mut B {
//     #[inline]
//     fn fill_buf(&mut self) -> io::Result<&[u8]> {
//         (**self).fill_buf()
//     }

//     #[inline]
//     fn consume(&mut self, amt: usize) {
//         (**self).consume(amt)
//     }

//     #[inline]
//     fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> io::Result<usize> {
//         (**self).read_until(byte, buf)
//     }

//     #[inline]
//     fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
//         (**self).read_line(buf)
//     }
// }

impl<R: Read + ?Sized> Read for Box<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (**self).read_vectored(bufs)
    }

    #[inline]
    fn is_read_vectored(&self) -> bool {
        (**self).is_read_vectored()
    }

    #[inline]
    unsafe fn initializer(&self) -> Initializer {
        (**self).initializer()
    }

    #[inline]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        (**self).read_to_end(buf)
    }

    #[inline]
    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        (**self).read_to_string(buf)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact(buf)
    }
}
impl<W: Write + ?Sized> Write for Box<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (**self).write(buf)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (**self).write_vectored(bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        (**self).is_write_vectored()
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        (**self).flush()
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        (**self).write_all(buf)
    }

    #[inline]
    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> io::Result<()> {
        (**self).write_fmt(fmt)
    }
}
// impl<S: Seek + ?Sized> Seek for Box<S> {
//     #[inline]
//     fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
//         (**self).seek(pos)
//     }
// }
// impl<B: BufRead + ?Sized> BufRead for Box<B> {
//     #[inline]
//     fn fill_buf(&mut self) -> io::Result<&[u8]> {
//         (**self).fill_buf()
//     }

//     #[inline]
//     fn consume(&mut self, amt: usize) {
//         (**self).consume(amt)
//     }

//     #[inline]
//     fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> io::Result<usize> {
//         (**self).read_until(byte, buf)
//     }

//     #[inline]
//     fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
//         (**self).read_line(buf)
//     }
// }

// Used by panicking::default_hook
// #[cfg(test)]
// /// This impl is only used by printing logic, so any error returned is always
// /// of kind `Other`, and should be ignored.
// impl Write for dyn ::realstd::io::LocalOutput {
//     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
//         (*self).write(buf).map_err(|_| ErrorKind::Other.into())
//     }

//     fn flush(&mut self) -> io::Result<()> {
//         (*self).flush().map_err(|_| ErrorKind::Other.into())
//     }
// }

// =============================================================================
// In-memory buffer implementations

/// Read is implemented for `&[u8]` by copying from the slice.
///
/// Note that reading updates the slice to point to the yet unread part.
/// The slice will be empty when EOF is reached.
impl Read for &[u8] {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let amt = cmp::min(buf.len(), self.len());
        let (a, b) = self.split_at(amt);

        // First check if the amount of bytes we want to read is small:
        // `copy_from_slice` will generally expand to a call to `memcpy`, and
        // for a single byte the overhead is significant.
        if amt == 1 {
            buf[0] = a[0];
        } else {
            buf[..amt].copy_from_slice(a);
        }

        *self = b;
        Ok(amt)
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let mut nread = 0;
        for buf in bufs {
            nread += self.read(buf)?;
            if self.is_empty() {
                break;
            }
        }

        Ok(nread)
    }

    #[inline]
    fn is_read_vectored(&self) -> bool {
        true
    }

    #[inline]
    unsafe fn initializer(&self) -> Initializer {
        Initializer::nop()
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        if buf.len() > self.len() {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ));
        }
        let (a, b) = self.split_at(buf.len());

        // First check if the amount of bytes we want to read is small:
        // `copy_from_slice` will generally expand to a call to `memcpy`, and
        // for a single byte the overhead is significant.
        if buf.len() == 1 {
            buf[0] = a[0];
        } else {
            buf.copy_from_slice(a);
        }

        *self = b;
        Ok(())
    }

    #[inline]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        buf.extend_from_slice(self);
        let len = self.len();
        *self = &self[len..];
        Ok(len)
    }
}

// impl BufRead for &[u8] {
//     #[inline]
//     fn fill_buf(&mut self) -> io::Result<&[u8]> {
//         Ok(*self)
//     }

//     #[inline]
//     fn consume(&mut self, amt: usize) {
//         *self = &self[amt..];
//     }
// }

/// Write is implemented for `&mut [u8]` by copying into the slice, overwriting
/// its data.
///
/// Note that writing updates the slice to point to the yet unwritten part.
/// The slice will be empty when it has been completely overwritten.
impl Write for &mut [u8] {
    #[inline]
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let amt = cmp::min(data.len(), self.len());
        let (a, b) = mem::take(self).split_at_mut(amt);
        a.copy_from_slice(&data[..amt]);
        *self = b;
        Ok(amt)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut nwritten = 0;
        for buf in bufs {
            nwritten += self.write(buf)?;
            if self.is_empty() {
                break;
            }
        }

        Ok(nwritten)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    #[inline]
    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        if self.write(data)? == data.len() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write whole buffer",
            ))
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Write is implemented for `Vec<u8>` by appending to the vector.
/// The vector will grow as needed.
impl Write for Vec<u8> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let len = bufs.iter().map(|b| b.len()).sum();
        self.reserve(len);
        for buf in bufs {
            self.extend_from_slice(buf);
        }
        Ok(len)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.extend_from_slice(buf);
        Ok(())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
