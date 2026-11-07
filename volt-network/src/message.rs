//! Wire messages.

use thiserror::Error;
use volt_core::{
    codec::{CodecError, Reader, Writer},
    constants::{MAX_BLOCK_PARENTS, MAX_TX_BYTES},
    VoltHash,
};

/// The version of the peer protocol. Peers on a different version are refused.
pub const PROTOCOL_VERSION: u32 = 1;

/// The maximum size of an encoded message, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// The maximum number of block hashes in a [`VoltMessage::GetBlocks`] or [`VoltMessage::Inv`].
pub const MAX_GET_BLOCKS: usize = 512;

/// The maximum number of blocks in a [`VoltMessage::Blocks`].
pub const MAX_BLOCKS_PER_MESSAGE: usize = 64;

/// The maximum number of hashes in a [`VoltMessage::GetChain`] locator.
pub const MAX_LOCATOR: usize = 64;

const TAG_NEW_BLOCK: u8 = 0;
const TAG_NEW_TX: u8 = 1;
const TAG_GET_BLOCKS: u8 = 2;
const TAG_BLOCKS: u8 = 3;
const TAG_HELLO: u8 = 4;
const TAG_PING: u8 = 5;
const TAG_PONG: u8 = 6;
const TAG_INV: u8 = 7;
const TAG_GET_CHAIN: u8 = 8;

/// The first message each side sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// The protocol version the sender speaks.
    pub version: u32,
    /// The genesis block of the sender's network. A mismatch means a different chain.
    pub genesis: VoltHash,
    /// A random per-process value, used to detect connections to oneself.
    pub nonce: u64,
    /// The sender's current DAG tips.
    pub tips: Vec<VoltHash>,
}

/// A message between nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoltMessage {
    /// The handshake.
    Hello(Hello),
    /// A keep-alive probe; the peer answers with the same value in a [`VoltMessage::Pong`].
    Ping(u64),
    /// The answer to a [`VoltMessage::Ping`].
    Pong(u64),
    /// An announcement that the sender has these blocks. Receivers fetch the ones they lack.
    Inv(Vec<VoltHash>),
    /// A newly mined block, encoded with `VoltBlock::encode`, pushed in full.
    NewBlock(Vec<u8>),
    /// A transaction for the mempool.
    NewTx(Vec<u8>),
    /// A request for blocks by hash.
    GetBlocks(Vec<VoltHash>),
    /// A request for the blocks that follow the newest block in the locator that the receiver
    /// knows. Used to catch up in bulk instead of one block at a time.
    GetChain(Vec<VoltHash>),
    /// A response carrying encoded blocks.
    Blocks(Vec<Vec<u8>>),
}

/// Errors from decoding a message.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MessageError {
    /// The message is larger than [`MAX_MESSAGE_BYTES`].
    #[error("message of {0} bytes exceeds the maximum")]
    TooLarge(usize),

    /// The message tag is unknown.
    #[error("unknown message tag {0}")]
    UnknownTag(u8),

    /// The payload is malformed.
    #[error(transparent)]
    Codec(#[from] CodecError),
}

fn write_hashes(w: &mut Writer, hashes: &[VoltHash]) {
    w.count(hashes.len());
    for hash in hashes {
        w.raw(&hash.0);
    }
}

fn read_hashes(
    r: &mut Reader<'_>,
    what: &'static str,
    max: usize,
) -> Result<Vec<VoltHash>, CodecError> {
    let n = r.count(what, max)?;
    let mut hashes = Vec::with_capacity(n);
    for _ in 0..n {
        hashes.push(VoltHash(r.array32()?));
    }
    Ok(hashes)
}

impl VoltMessage {
    /// Encodes the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Self::Hello(hello) => {
                w.u8(TAG_HELLO)
                    .u32(hello.version)
                    .raw(&hello.genesis.0)
                    .u64(hello.nonce);
                write_hashes(&mut w, &hello.tips);
            }
            Self::Ping(n) => {
                w.u8(TAG_PING).u64(*n);
            }
            Self::Pong(n) => {
                w.u8(TAG_PONG).u64(*n);
            }
            Self::Inv(hashes) => {
                w.u8(TAG_INV);
                write_hashes(&mut w, hashes);
            }
            Self::NewBlock(block) => {
                w.u8(TAG_NEW_BLOCK).bytes(block);
            }
            Self::NewTx(tx) => {
                w.u8(TAG_NEW_TX).bytes(tx);
            }
            Self::GetBlocks(hashes) => {
                w.u8(TAG_GET_BLOCKS);
                write_hashes(&mut w, hashes);
            }
            Self::GetChain(locator) => {
                w.u8(TAG_GET_CHAIN);
                write_hashes(&mut w, locator);
            }
            Self::Blocks(blocks) => {
                w.u8(TAG_BLOCKS).count(blocks.len());
                for block in blocks {
                    w.bytes(block);
                }
            }
        }
        w.finish()
    }

    /// Decodes a message, checking every length against its protocol maximum.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(MessageError::TooLarge(bytes.len()));
        }

        let mut r = Reader::new(bytes);
        let message = match r.u8()? {
            TAG_HELLO => Self::Hello(Hello {
                version: r.u32()?,
                genesis: VoltHash(r.array32()?),
                nonce: r.u64()?,
                tips: read_hashes(&mut r, "tips", MAX_BLOCK_PARENTS)?,
            }),
            TAG_PING => Self::Ping(r.u64()?),
            TAG_PONG => Self::Pong(r.u64()?),
            TAG_INV => Self::Inv(read_hashes(&mut r, "inventory", MAX_GET_BLOCKS)?),
            TAG_NEW_BLOCK => Self::NewBlock(r.bytes("block", MAX_MESSAGE_BYTES)?.to_vec()),
            TAG_NEW_TX => Self::NewTx(r.bytes("transaction", MAX_TX_BYTES)?.to_vec()),
            TAG_GET_BLOCKS => Self::GetBlocks(read_hashes(&mut r, "block hashes", MAX_GET_BLOCKS)?),
            TAG_GET_CHAIN => Self::GetChain(read_hashes(&mut r, "locator", MAX_LOCATOR)?),
            TAG_BLOCKS => {
                let n = r.count("blocks", MAX_BLOCKS_PER_MESSAGE)?;
                let mut blocks = Vec::with_capacity(n);
                for _ in 0..n {
                    blocks.push(r.bytes("block", MAX_MESSAGE_BYTES)?.to_vec());
                }
                Self::Blocks(blocks)
            }
            tag => return Err(MessageError::UnknownTag(tag)),
        };
        r.finish()?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<VoltMessage> {
        vec![
            VoltMessage::Hello(Hello {
                version: PROTOCOL_VERSION,
                genesis: VoltHash([3; 32]),
                nonce: 99,
                tips: vec![VoltHash([1; 32]), VoltHash([2; 32])],
            }),
            VoltMessage::Ping(5),
            VoltMessage::Pong(5),
            VoltMessage::Inv(vec![VoltHash([8; 32])]),
            VoltMessage::NewBlock(vec![1, 2, 3]),
            VoltMessage::NewTx(vec![]),
            VoltMessage::GetBlocks(vec![VoltHash([1; 32]), VoltHash([2; 32])]),
            VoltMessage::GetChain(vec![VoltHash([4; 32])]),
            VoltMessage::Blocks(vec![vec![9], vec![8, 7]]),
        ]
    }

    #[test]
    fn messages_round_trip() {
        for message in samples() {
            assert_eq!(VoltMessage::decode(&message.encode()).unwrap(), message);
        }
    }

    #[test]
    fn decoding_is_bounded_for_every_list_type() {
        assert_eq!(
            VoltMessage::decode(&[42]),
            Err(MessageError::UnknownTag(42))
        );
        assert!(VoltMessage::decode(&[]).is_err());

        // Each list claims 2^32 - 1 elements and must fail before allocating anything.
        for tag in [TAG_GET_BLOCKS, TAG_INV, TAG_GET_CHAIN, TAG_BLOCKS] {
            let mut huge = vec![tag];
            huge.extend_from_slice(&u32::MAX.to_le_bytes());
            assert!(
                matches!(
                    VoltMessage::decode(&huge),
                    Err(MessageError::Codec(CodecError::TooLong { .. }))
                ),
                "tag {tag}"
            );
        }

        // A Hello with too many tips.
        let mut hello = vec![TAG_HELLO];
        hello.extend_from_slice(&1u32.to_le_bytes());
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&0u64.to_le_bytes());
        hello.extend_from_slice(&1_000u32.to_le_bytes());
        assert!(VoltMessage::decode(&hello).is_err());
    }

    #[test]
    fn trailing_bytes_and_truncation_are_rejected() {
        for message in samples() {
            let mut trailing = message.encode();
            trailing.push(0);
            assert!(VoltMessage::decode(&trailing).is_err());

            let full = message.encode();
            for cut in 0..full.len() {
                assert!(
                    VoltMessage::decode(&full[..cut]).is_err(),
                    "a message cut at {cut} of {} must not decode",
                    full.len()
                );
            }
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // A cheap deterministic fuzz: decoding garbage may fail but must never panic.
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 96) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|i| (state.rotate_left((i % 61) as u32) >> 8) as u8)
                .collect();
            let _ = VoltMessage::decode(&bytes);
        }
    }
}
