//! Message framing over a byte stream.
//!
//! ```text
//! network magic (4) | payload length (u32 LE) | Blake2b-32 of payload | payload
//! ```
//!
//! The magic separates networks, the checksum catches corruption, and the length is bounded
//! before anything is allocated. A payload is read in chunks, so a peer that claims a large
//! frame but sends nothing cannot make the node reserve that memory up front.

use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::message::MAX_MESSAGE_BYTES;

/// How much of a payload is read per step.
const CHUNK: usize = 64 * 1024;

/// Errors from reading a frame.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The stream failed or ended.
    #[error("connection error: {0}")]
    Io(#[from] io::Error),

    /// The magic bytes do not match this network.
    #[error("wrong network magic")]
    WrongMagic,

    /// The declared length exceeds the maximum.
    #[error("frame of {0} bytes exceeds the maximum of {MAX_MESSAGE_BYTES}")]
    TooLarge(usize),

    /// The payload does not match its checksum.
    #[error("frame checksum mismatch")]
    BadChecksum,
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let hash = blake2b_simd::Params::new()
        .hash_length(4)
        .personal(b"VoltFrame_______")
        .hash(payload);
    let mut out = [0; 4];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Writes one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    magic: [u8; 4],
    payload: &[u8],
) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|l| *l as usize <= MAX_MESSAGE_BYTES)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;

    let mut frame = Vec::with_capacity(12 + payload.len());
    frame.extend_from_slice(&magic);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&checksum(payload));
    frame.extend_from_slice(payload);
    // One write, so concurrent frames on a shared stream cannot interleave.
    writer.write_all(&frame).await?;
    writer.flush().await
}

/// Reads one frame and returns its payload.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    magic: [u8; 4],
) -> Result<Vec<u8>, FrameError> {
    let mut header = [0u8; 12];
    reader.read_exact(&mut header).await?;

    if header[..4] != magic {
        return Err(FrameError::WrongMagic);
    }
    let len = u32::from_le_bytes(header[4..8].try_into().expect("4 bytes")) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let expected: [u8; 4] = header[8..12].try_into().expect("4 bytes");

    let mut payload = Vec::with_capacity(len.min(CHUNK));
    while payload.len() < len {
        let step = (len - payload.len()).min(CHUNK);
        let start = payload.len();
        payload.resize(start + step, 0);
        reader.read_exact(&mut payload[start..]).await?;
    }

    if checksum(&payload) != expected {
        return Err(FrameError::BadChecksum);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: [u8; 4] = *b"VOLT";

    #[tokio::test]
    async fn frames_round_trip() {
        let mut wire = Vec::new();
        write_frame(&mut wire, MAGIC, b"hello").await.unwrap();
        write_frame(&mut wire, MAGIC, b"").await.unwrap();
        write_frame(&mut wire, MAGIC, &vec![7; 200_000])
            .await
            .unwrap();

        let mut reader = wire.as_slice();
        assert_eq!(read_frame(&mut reader, MAGIC).await.unwrap(), b"hello");
        assert_eq!(read_frame(&mut reader, MAGIC).await.unwrap(), b"");
        assert_eq!(read_frame(&mut reader, MAGIC).await.unwrap().len(), 200_000);
    }

    #[tokio::test]
    async fn rejects_the_wrong_network_corruption_and_huge_lengths() {
        let mut wire = Vec::new();
        write_frame(&mut wire, MAGIC, b"payload").await.unwrap();

        let mut reader = wire.as_slice();
        assert!(matches!(
            read_frame(&mut reader, *b"TEST").await,
            Err(FrameError::WrongMagic)
        ));

        let mut corrupt = wire.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(matches!(
            read_frame(&mut corrupt.as_slice(), MAGIC).await,
            Err(FrameError::BadChecksum)
        ));

        // A header claiming 4 GiB is refused before any payload is read or allocated.
        let mut huge = MAGIC.to_vec();
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        huge.extend_from_slice(&[0; 4]);
        assert!(matches!(
            read_frame(&mut huge.as_slice(), MAGIC).await,
            Err(FrameError::TooLarge(_))
        ));
    }

    #[tokio::test]
    async fn a_truncated_stream_is_an_io_error_not_a_hang() {
        let mut wire = Vec::new();
        write_frame(&mut wire, MAGIC, &[1; 1_000]).await.unwrap();
        for cut in [0, 5, 11, 12, 500] {
            let mut reader = &wire[..cut];
            assert!(matches!(
                read_frame(&mut reader, MAGIC).await,
                Err(FrameError::Io(_))
            ));
        }
    }
}
