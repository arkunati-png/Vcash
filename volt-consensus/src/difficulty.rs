//! Difficulty adjustment and the RandomX key schedule.

use volt_core::{
    constants::{
        DIFFICULTY_WINDOW, EPOCH_LENGTH, MAX_DIFFICULTY_STEP, POW_LIMIT_BITS,
        TARGET_BLOCK_INTERVAL_MS,
    },
    VoltHash,
};
use zebra_chain::{
    serialization::BytesInDisplayOrder,
    work::difficulty::{CompactDifficulty, ExpandedDifficulty},
};

use crate::ghostdag::BlockDag;

fn expand(bits: u32) -> Option<ExpandedDifficulty> {
    CompactDifficulty::from_bytes_in_display_order(&bits.to_be_bytes())
        .ok()?
        .to_expanded()
}

fn compact(target: ExpandedDifficulty) -> u32 {
    u32::from_be_bytes(target.to_compact().bytes_in_display_order())
}

/// The easiest allowed target.
pub fn pow_limit() -> ExpandedDifficulty {
    expand(POW_LIMIT_BITS).expect("the PoW limit constant is a valid compact target")
}

/// The difficulty bits required of a block whose selected parent is `selected_parent`.
///
/// The target is the average target over the last [`DIFFICULTY_WINDOW`] selected-chain blocks,
/// scaled by how much slower or faster than 500 ms per blue block they were produced. Blocks are
/// counted by blue score, not chain length, so merged parallel blocks count as work done. Each
/// step is clamped to [`MAX_DIFFICULTY_STEP`]x and the target never exceeds the PoW limit.
pub fn next_bits(dag: &BlockDag, selected_parent: &VoltHash) -> u32 {
    // (blue score, timestamp in ms, bits) of the window, newest first.
    let window: Vec<(u64, u64, u32)> = dag
        .selected_chain(selected_parent)
        .iter()
        .take(DIFFICULTY_WINDOW)
        .map(|hash| {
            let node = dag.get(hash).expect("chain blocks are in the DAG");
            (node.ghostdag.blue_score, node.timestamp_ms, node.bits)
        })
        .collect();

    let newest = window[0];
    let oldest = window[window.len() - 1];
    let blue_blocks = newest.0.saturating_sub(oldest.0);
    if blue_blocks == 0 {
        return newest.2;
    }

    let limit = pow_limit();
    let sum: ExpandedDifficulty = window
        .iter()
        .map(|(_, _, bits)| expand(*bits).unwrap_or(limit))
        .sum();
    let average = sum / window.len() as u64; // lossless: at most DIFFICULTY_WINDOW entries

    let expected_ms = blue_blocks.saturating_mul(TARGET_BLOCK_INTERVAL_MS).max(1);
    let actual_ms = newest.1.saturating_sub(oldest.1).clamp(
        (expected_ms / MAX_DIFFICULTY_STEP).max(1),
        expected_ms.saturating_mul(MAX_DIFFICULTY_STEP),
    );

    // Divide first so the product stays below 2^256: the limit is ~2^247 and the factor is <= 4.
    let mut adjusted = average / expected_ms * actual_ms;
    if adjusted > limit {
        adjusted = limit;
    }
    // A zero target is invalid. Keep the previous average instead of stepping to it.
    if adjusted.bytes_in_display_order().iter().all(|b| *b == 0) {
        adjusted = average;
    }
    compact(adjusted)
}

/// The RandomX seed (cache key) for a block whose selected parent is `selected_parent`.
///
/// The key changes once per [`EPOCH_LENGTH`] blue blocks and lags by one epoch: it is the hash of
/// the selected-chain block at or below the start of the previous epoch. A miner therefore
/// knows the next epoch's key a full epoch ahead of time and can prepare its RandomX cache.
pub fn pow_seed(dag: &BlockDag, selected_parent: &VoltHash) -> [u8; 32] {
    let score = dag
        .get(selected_parent)
        .expect("the selected parent is in the DAG")
        .ghostdag
        .blue_score;
    let epoch = score / EPOCH_LENGTH;
    if epoch == 0 {
        return dag.genesis().expect("a DAG with blocks has a genesis").0;
    }

    let key_score = (epoch - 1) * EPOCH_LENGTH;
    dag.selected_chain(selected_parent)
        .into_iter()
        .find(|hash| {
            dag.get(hash)
                .expect("chain blocks are in the DAG")
                .ghostdag
                .blue_score
                <= key_score
        })
        .expect("genesis has blue score 0, so the chain always reaches the key score")
        .0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u32) -> VoltHash {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&(n + 1).to_le_bytes());
        VoltHash(bytes)
    }

    /// A linear chain of `n` blocks after genesis, `interval_ms` apart, all at `bits`.
    fn chain(n: u32, interval_ms: u64, bits: u32) -> (BlockDag, VoltHash) {
        let mut dag = BlockDag::default();
        dag.add_genesis(h(0), 1, 0, bits).unwrap();
        for i in 1..=n {
            dag.add_block(h(i), &[h(i - 1)], 1, u64::from(i) * interval_ms, bits)
                .unwrap();
        }
        (dag, h(n))
    }

    fn target(bits: u32) -> ExpandedDifficulty {
        expand(bits).unwrap()
    }

    #[test]
    fn on_schedule_keeps_difficulty() {
        let bits = 0x1e7f_ffff;
        let (dag, tip) = chain(130, TARGET_BLOCK_INTERVAL_MS, bits);
        let next = next_bits(&dag, &tip);
        // Compact encoding rounds, so allow tiny drift.
        assert!(target(next) <= target(bits) * 2u64 && target(bits) <= target(next) * 2u64);
    }

    #[test]
    fn fast_blocks_raise_difficulty_and_slow_blocks_lower_it() {
        let bits = 0x1e7f_ffff;

        let (dag, tip) = chain(130, TARGET_BLOCK_INTERVAL_MS / 2, bits);
        assert!(
            target(next_bits(&dag, &tip)) < target(bits),
            "faster => smaller target"
        );

        let (dag, tip) = chain(130, TARGET_BLOCK_INTERVAL_MS * 2, bits);
        assert!(
            target(next_bits(&dag, &tip)) > target(bits),
            "slower => larger target"
        );
    }

    #[test]
    fn target_is_clamped_to_the_pow_limit_and_the_step() {
        // Very slow blocks at the limit cannot go easier than the limit.
        let (dag, tip) = chain(130, 60_000, POW_LIMIT_BITS);
        assert!(target(next_bits(&dag, &tip)) <= pow_limit());

        // Very fast blocks change the target by at most 4x per step.
        let bits = 0x1e7f_ffff;
        let (dag, tip) = chain(130, 1, bits);
        assert!(target(next_bits(&dag, &tip)) * MAX_DIFFICULTY_STEP >= target(bits) / 2u64);
    }

    #[test]
    fn seed_is_genesis_in_the_first_epoch_then_lags() {
        let (dag, tip) = chain(5, 500, POW_LIMIT_BITS);
        assert_eq!(pow_seed(&dag, &tip), h(0).0);

        let (dag, tip) = chain(450, 500, POW_LIMIT_BITS);
        // blue score of block i is i, so at score 450 (epoch 2) the key is the block at score 200.
        assert_eq!(pow_seed(&dag, &tip), h(200).0);
        // Within an epoch the key does not change.
        assert_eq!(pow_seed(&dag, &h(401)), pow_seed(&dag, &h(449)));
        assert_ne!(pow_seed(&dag, &h(399)), pow_seed(&dag, &h(401)));
    }
}
