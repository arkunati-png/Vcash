//! Voltcash consensus constants.

use zebra_chain::amount::COIN;

/// The GHOSTDAG cluster parameter `k`: the maximum anticone size of a blue block
/// within the blue set.
pub const GHOSTDAG_K: usize = 32;

/// The maximum number of parents a block header may reference.
///
/// A block can merge at most `k + 1` blue tips in one step, so more parents never help.
pub const MAX_BLOCK_PARENTS: usize = GHOSTDAG_K + 1;

/// The target interval between DAG blocks, in milliseconds (about 1.18 blocks per second).
pub const TARGET_BLOCK_INTERVAL_MS: u64 = 850;

/// The number of user transactions packed into one [`RollupBatch`](crate::RollupBatch).
pub const BATCH_SIZE: usize = 10;

/// The maximum number of rollup batches in one block.
///
/// 100 batches * 10 transactions * ~1.18 blocks/s = about 1,180 transactions per second.
pub const MAX_BATCHES_PER_BLOCK: usize = 100;

/// The number of accepted blocks in a POL settlement epoch.
pub const EPOCH_LENGTH: u64 = 200;

/// How many selected-chain steps deep a step must be before it is final.
///
/// A completed epoch is locked into the POL reserve only once its step is this deep, and state
/// older than this is never reverted. Sibling tips of equal blue work swap places constantly in a
/// DAG, so the newest steps must stay revertible. About 50 blocks is 42.5 seconds at 850 ms.
pub const FINALITY_DEPTH: usize = 50;

/// How many blue blocks one RandomX key lasts (2^18, about 62 hours at 850 ms).
///
/// Changing the key forces every miner to rebuild its 2 GB RandomX dataset, which takes a
/// minute or more, so it must happen rarely. It is separate from [`EPOCH_LENGTH`], which is the
/// reward-settlement period and is far too short for this.
pub const POW_KEY_EPOCH_LENGTH: u64 = 262_144;

/// The maximum number of unique payout addresses in one block's coinbase.
pub const MAX_COINBASE_PAYOUTS: usize = 100;

/// One VOLT, in its smallest unit (the same 10^8 scale as Zcash's `COIN`).
pub const VOLT: i64 = COIN;

/// The fee for a transparent transaction: 0.0001 VOLT.
pub const TRANSPARENT_FEE: i64 = VOLT / 10_000;

/// The fee for a shielded (Sapling or Orchard) transaction: 0.0002 VOLT.
pub const SHIELDED_FEE: i64 = VOLT / 5_000;

/// The fee per logical action (a transparent input/output pair, a shielded spend/output pair or
/// an Orchard action). A transaction pays `max(tier fee, this * actions, size fee)`, so a big
/// transaction cannot pay the same as a tiny one.
pub const MARGINAL_FEE_PER_ACTION: i64 = 2_000;

/// The size-based fee floor, per started 1,000 bytes of serialized transaction.
pub const FEE_PER_KB: i64 = 2_000;

/// The most serialized transaction bytes one block may carry across all its batches.
pub const MAX_BLOCK_TX_BYTES: usize = 2_000_000;

/// The most logical actions one block may carry. This bounds proof-verification work per block.
pub const MAX_BLOCK_ACTIONS: u64 = 20_000;

/// How many chain steps a coinbase output must age before it can be spent.
pub const COINBASE_MATURITY: u32 = 100;

/// The default maximum number of transactions held in the mempool.
pub const MEMPOOL_MAX_TXS: usize = 50_000;

/// The maximum distance a block timestamp may be ahead of the local clock, in milliseconds.
pub const MAX_FUTURE_TIMESTAMP_DRIFT_MS: u64 = 60_000;

/// The number of blue blocks used by the difficulty adjustment window.
pub const DIFFICULTY_WINDOW: usize = 120;

/// The easiest allowed PoW target, as a compact `nBits` value (about 2^247).
///
/// Kept well below 2^251 so the difficulty adjustment can scale a target by 4x in 256-bit arithmetic.
pub const POW_LIMIT_BITS: u32 = 0x1f7f_ffff;

/// The PoW limit for tests, simulations and local development chains: a target of 2^253, so a
/// block takes about 8 RandomX hashes instead of about 512.
///
/// The work is still RandomX. Only the target is easy. It is the easiest limit the difficulty
/// adjustment's arithmetic allows (it scales a target by up to 4x inside 256 bits).
pub const TEST_POW_LIMIT_BITS: u32 = 0x201f_ffff;

/// The largest factor the difficulty adjustment may change the target by per block.
pub const MAX_DIFFICULTY_STEP: u64 = 4;

/// The maximum number of blocks a block may merge that are outside its selected parent chain.
pub const MAX_MERGESET_SIZE: usize = GHOSTDAG_K * 10;

/// The maximum length of a transparent lock script accepted by Voltcash, in bytes.
pub const MAX_SCRIPT_BYTES: usize = 10_000;

/// The maximum length of a single serialized transaction inside a batch, in bytes.
pub const MAX_TX_BYTES: usize = 2_000_000;

/// The maximum number of transparent inputs, outputs or nullifiers in one transaction.
pub const MAX_TX_ITEMS: usize = 10_000;

/// The maximum length of the coinbase extra data, in bytes.
pub const MAX_COINBASE_EXTRA_BYTES: usize = 100;

// A reward must split exactly in half when the miner share is 50%. Every fee is a multiple of 2,
// and emission is forced even, so every sum of them is even too.
const _: () = assert!(TRANSPARENT_FEE % 2 == 0);
const _: () = assert!(SHIELDED_FEE % 2 == 0);
const _: () = assert!(MARGINAL_FEE_PER_ACTION % 2 == 0);
const _: () = assert!(FEE_PER_KB % 2 == 0);
const _: () = assert!(TRANSPARENT_FEE == 10_000);
const _: () = assert!(SHIELDED_FEE == 20_000);
