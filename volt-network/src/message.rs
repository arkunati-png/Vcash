//! Wire messages.

use thiserror::Error;
use volt_core::{
    codec::{CodecError, Reader, Writer},
    constants::MAX_TX_BYTES,
    VoltHash,
};

/// The maximum size of an encoded message, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// The maximum number of block hashes in a [`VoltMessage::GetBlocks`].
pub const MAX_GET_BLOCKS: usize = 512;

/// The maximum number of blocks in a [`VoltMessage::Blocks`].
pub const MAX_BLOCKS_PER_MESSAGE: usize = 64;

const TAG_NEW_BLOCK: u8 = 0;
const TAG_NEW_TX: u8 = 1;
const TAG_GET_BLOCKS: u8 = 2;
const TAG_BLOCKS: u8 = 3;

/// A message between nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoltMessage {
    /// A newly mined block, encoded with `VoltBlock::encode`.
    NewBlock(Vec<u8>),
    /// A transaction for the mempool.
    NewTx(Vec<u8>),
    /// A request for blocks by hash.
    GetBlocks(Vec<VoltHash>),
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

impl VoltMessage {
    /// Encodes the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Self::NewBlock(block) => {
                w.u8(TAG_NEW_BLOCK).bytes(block);
            }
            Self::NewTx(tx) => {
                w.u8(TAG_NEW_TX).bytes(tx);
            }
            Self::GetBlocks(hashes) => {
                w.u8(TAG_GET_BLOCKS).count(hashes.len());
                for hash in hashes {
                    w.raw(&hash.0);
                }
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
            TAG_NEW_BLOCK => Self::NewBlock(r.bytes("block", MAX_MESSAGE_BYTES)?.to_vec()),
            TAG_NEW_TX => Self::NewTx(r.bytes("transaction", MAX_TX_BYTES)?.to_vec()),
            TAG_GET_BLOCKS => {
                let n = r.count("block hashes", MAX_GET_BLOCKS)?;
                let mut hashes = Vec::with_capacity(n);
                for _ in 0..n {
                    hashes.push(VoltHash(r.array32()?));
                }
                Self::GetBlocks(hashes)
            }
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

    #[test]
    fn messages_round_trip() {
        for message in [
            VoltMessage::NewBlock(vec![1, 2, 3]),
            VoltMessage::NewTx(vec![]),
            VoltMessage::GetBlocks(vec![VoltHash([1; 32]), VoltHash([2; 32])]),
            VoltMessage::Blocks(vec![vec![9], vec![8, 7]]),
        ] {
            assert_eq!(VoltMessage::decode(&message.encode()).unwrap(), message);
        }
    }

    #[test]
    fn decoding_is_bounded() {
        assert_eq!(
            VoltMessage::decode(&[42]),
            Err(MessageError::UnknownTag(42))
        );
        assert!(VoltMessage::decode(&[]).is_err());

        // A GetBlocks claiming 2^32 - 1 hashes must fail before allocating.
        let mut huge = vec![TAG_GET_BLOCKS];
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            VoltMessage::decode(&huge),
            Err(MessageError::Codec(CodecError::TooLong { .. }))
        ));

        // Trailing garbage is rejected.
        let mut trailing = VoltMessage::NewTx(vec![1]).encode();
        trailing.push(0);
        assert!(VoltMessage::decode(&trailing).is_err());
    }
}
