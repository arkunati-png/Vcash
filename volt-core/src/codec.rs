//! A small bounded binary codec for Voltcash consensus structures.
//!
//! All integers are little-endian. Every length read from untrusted input is
//! checked against an explicit maximum before anything is allocated.

use thiserror::Error;

/// Errors from decoding untrusted bytes.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CodecError {
    /// The input ended before the structure was complete.
    #[error("unexpected end of input: needed {needed} more bytes, {remaining} remaining")]
    UnexpectedEof {
        /// Bytes the decoder needed.
        needed: usize,
        /// Bytes that were left.
        remaining: usize,
    },

    /// A declared length or count exceeds its protocol maximum.
    #[error("{what} length {len} exceeds maximum {max}")]
    TooLong {
        /// The field being decoded.
        what: &'static str,
        /// The declared length.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },

    /// A value is not valid for its type.
    #[error("invalid {0}")]
    Invalid(&'static str),

    /// Bytes remained after the structure was fully decoded.
    #[error("{0} trailing bytes after decoding")]
    TrailingBytes(usize),
}

/// A growable output buffer.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Creates an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes one byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Writes a little-endian `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Writes a little-endian `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Writes a little-endian `i64`.
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Writes raw bytes with no length prefix.
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Writes a `u32` length prefix followed by `v`.
    ///
    /// # Panics
    ///
    /// If `v` is longer than `u32::MAX`, which no consensus structure can be.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        let len = u32::try_from(v.len()).expect("consensus byte strings are shorter than 4 GiB");
        self.u32(len);
        self.raw(v)
    }

    /// Writes a `u32` element count.
    ///
    /// # Panics
    ///
    /// If `n` is larger than `u32::MAX`, which no consensus structure can be.
    pub fn count(&mut self, n: usize) -> &mut Self {
        self.u32(u32::try_from(n).expect("consensus collections have fewer than 2^32 items"))
    }

    /// Returns the written bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// A cursor over untrusted input.
#[derive(Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Creates a reader over `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns the number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.data.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.data.len() < n {
            return Err(CodecError::UnexpectedEof {
                needed: n,
                remaining: self.data.len(),
            });
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    /// Reads exactly `N` bytes.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Reads one byte.
    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.array::<1>()?[0])
    }

    /// Reads a little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian `i64`.
    pub fn i64(&mut self) -> Result<i64, CodecError> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    /// Reads exactly 32 bytes.
    pub fn array32(&mut self) -> Result<[u8; 32], CodecError> {
        self.array()
    }

    /// Reads exactly 20 bytes.
    pub fn array20(&mut self) -> Result<[u8; 20], CodecError> {
        self.array()
    }
    /// Reads a `u32` element count and checks it against `max`.
    pub fn count(&mut self, what: &'static str, max: usize) -> Result<usize, CodecError> {
        let n = self.u32()? as usize; // lossless: usize is at least 32 bits on supported targets
        if n > max {
            return Err(CodecError::TooLong { what, len: n, max });
        }
        Ok(n)
    }

    /// Reads a length-prefixed byte string of at most `max` bytes.
    pub fn bytes(&mut self, what: &'static str, max: usize) -> Result<&'a [u8], CodecError> {
        let n = self.count(what, max)?;
        self.take(n)
    }

    /// Fails if any bytes remain.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes(self.data.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_bounds() {
        let mut w = Writer::new();
        w.u8(7).u32(9).u64(11).i64(-3).bytes(b"abc");
        let bytes = w.finish();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 9);
        assert_eq!(r.u64().unwrap(), 11);
        assert_eq!(r.i64().unwrap(), -3);
        assert_eq!(r.bytes("x", 3).unwrap(), b"abc");
        r.finish().unwrap();

        let mut r = Reader::new(&bytes[17..]);
        assert!(matches!(r.bytes("x", 2), Err(CodecError::TooLong { .. })));
        assert!(matches!(
            Reader::new(&[1, 2]).u32(),
            Err(CodecError::UnexpectedEof { .. })
        ));
    }
}
