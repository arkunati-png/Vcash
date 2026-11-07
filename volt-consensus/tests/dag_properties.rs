//! Property tests for the DAG: the reachability index, the GHOSTDAG k-cluster invariant and
//! independence from block arrival order, over random DAGs.

use std::collections::HashSet;

use proptest::prelude::*;
use volt_consensus::ghostdag::BlockDag;
use volt_core::VoltHash;

fn h(n: usize) -> VoltHash {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&(n as u64 + 1).to_le_bytes());
    VoltHash(bytes)
}

/// A random DAG: `parents[i]` are the parent indices of block `i + 1`, all below `i + 1`, with
/// a bias towards recent blocks so the DAG is wide rather than a few long chains.
fn dag_shape() -> impl Strategy<Value = Vec<Vec<usize>>> {
    const WINDOW: usize = 10;
    prop::collection::vec(prop::collection::vec(any::<u16>(), 1..6), 1..90).prop_map(|blocks| {
        blocks
            .into_iter()
            .enumerate()
            .map(|(i, picks)| {
                let id = i + 1;
                let mut parents: Vec<usize> = picks
                    .into_iter()
                    .map(|p| id - 1 - (usize::from(p) % WINDOW.min(id)))
                    .collect();
                parents.sort_unstable();
                parents.dedup();
                parents
            })
            .collect()
    })
}

fn build(shape: &[Vec<usize>], k: usize, order: &[usize]) -> BlockDag {
    let mut dag = BlockDag::new(k);
    dag.add_genesis(h(0), 1, 0, 0).unwrap();
    for &id in order {
        let parents: Vec<VoltHash> = shape[id - 1].iter().map(|p| h(*p)).collect();
        dag.add_block(h(id), &parents, 1, 0, 0).unwrap();
    }
    dag
}

fn in_order(shape: &[Vec<usize>]) -> Vec<usize> {
    (1..=shape.len()).collect()
}

/// A random topological order, chosen by repeatedly picking a ready block pseudo-randomly.
fn shuffled_order(shape: &[Vec<usize>], mut seed: u64) -> Vec<usize> {
    let mut inserted: HashSet<usize> = HashSet::from([0]);
    let mut remaining: Vec<usize> = (1..=shape.len()).collect();
    let mut order = Vec::new();
    while !remaining.is_empty() {
        let ready: Vec<usize> = (0..remaining.len())
            .filter(|&i| shape[remaining[i] - 1].iter().all(|p| inserted.contains(p)))
            .collect();
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let pick = ready[(seed >> 33) as usize % ready.len()];
        let id = remaining.swap_remove(pick);
        inserted.insert(id);
        order.push(id);
    }
    order
}

/// Every blue block in the past of `block`: the union of the mergeset blues along its
/// selected-parent chain.
fn blue_set(dag: &BlockDag, block: &VoltHash) -> HashSet<VoltHash> {
    dag.selected_chain(block)
        .iter()
        .flat_map(|c| dag.get(c).unwrap().ghostdag.mergeset_blues.clone())
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// The index agrees with walking the DAG, for every pair of blocks.
    #[test]
    fn reachability_matches_the_slow_walk(shape in dag_shape()) {
        let dag = build(&shape, 32, &in_order(&shape));
        let ids: Vec<usize> = (0..=shape.len()).collect();
        for &a in &ids {
            for &b in &ids {
                prop_assert_eq!(
                    dag.is_dag_ancestor_of(&h(a), &h(b)),
                    dag.is_dag_ancestor_of_slow(&h(a), &h(b)),
                    "pair ({}, {})", a, b
                );
            }
        }
    }

    /// With a small `k`, many blocks go red, yet the blue set of every block stays a k-cluster
    /// and its size is exactly the block's blue score.
    #[test]
    fn the_blue_set_is_always_a_k_cluster(shape in dag_shape(), k in 1usize..5) {
        let dag = build(&shape, k, &in_order(&shape));

        for id in 0..=shape.len() {
            let block = h(id);
            let blues = blue_set(&dag, &block);
            prop_assert_eq!(blues.len() as u64, dag.get(&block).unwrap().ghostdag.blue_score);

            for d in &blues {
                let anticone = blues
                    .iter()
                    .filter(|e| *e != d)
                    .filter(|e| {
                        !dag.is_dag_ancestor_of_slow(e, d) && !dag.is_dag_ancestor_of_slow(d, e)
                    })
                    .count();
                prop_assert!(
                    anticone <= k,
                    "blue block {} has {} blues in its anticone, more than k = {}", d, anticone, k
                );
            }
        }
    }

    /// Mergeset blues never exceed k + 1, and blues and reds partition the mergeset.
    #[test]
    fn mergesets_are_bounded_and_partitioned(shape in dag_shape(), k in 1usize..5) {
        let dag = build(&shape, k, &in_order(&shape));
        for id in 1..=shape.len() {
            let data = &dag.get(&h(id)).unwrap().ghostdag;
            prop_assert!(data.mergeset_blues.len() <= k + 1);
            prop_assert_eq!(data.mergeset_blues.first().copied(), data.selected_parent);

            let blues: HashSet<_> = data.mergeset_blues.iter().collect();
            prop_assert!(data.mergeset_reds.iter().all(|r| !blues.contains(r)));
            // Every mergeset member is in this block's past.
            for m in data.mergeset_blues.iter().chain(&data.mergeset_reds) {
                prop_assert!(dag.is_dag_ancestor_of_slow(m, &h(id)) && *m != h(id));
            }
        }
    }

    /// Two different arrival orders of the same blocks give the same coloring and the same
    /// consensus order. This is what lets nodes with different network views agree.
    #[test]
    fn arrival_order_does_not_matter(shape in dag_shape(), k in 1usize..5, seed in any::<u64>()) {
        let first = build(&shape, k, &in_order(&shape));
        let second = build(&shape, k, &shuffled_order(&shape, seed));

        prop_assert_eq!(first.sink(), second.sink());
        for id in 0..=shape.len() {
            prop_assert_eq!(
                &first.get(&h(id)).unwrap().ghostdag.mergeset_blues,
                &second.get(&h(id)).unwrap().ghostdag.mergeset_blues
            );
            prop_assert_eq!(
                &first.get(&h(id)).unwrap().ghostdag.mergeset_reds,
                &second.get(&h(id)).unwrap().ghostdag.mergeset_reds
            );
            prop_assert_eq!(
                first.get(&h(id)).unwrap().ghostdag.blue_work,
                second.get(&h(id)).unwrap().ghostdag.blue_work
            );
        }
        let sink = first.sink().unwrap();
        prop_assert_eq!(first.linear_order(&sink), second.linear_order(&sink));
    }
}

/// A large, wide DAG builds quickly and the index still agrees with the slow walk on a sample.
#[test]
fn a_large_wide_dag_stays_fast_and_correct() {
    const BLOCKS: usize = 6_000;
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let mut dag = BlockDag::default();
    dag.add_genesis(h(0), 1, 0, 0).unwrap();
    for id in 1..=BLOCKS {
        let width = 1 + (next() % 6) as usize;
        let mut parents: Vec<usize> = (0..width)
            .map(|_| id - 1 - (next() as usize % 12.min(id)))
            .collect();
        parents.sort_unstable();
        parents.dedup();
        let parents: Vec<VoltHash> = parents.into_iter().map(h).collect();
        dag.add_block(h(id), &parents, 1, 0, 0).unwrap();
    }

    assert_eq!(dag.len(), BLOCKS + 1);
    assert!(
        dag.reachability().max_covering_set() < 200,
        "covering sets stay small: {}",
        dag.reachability().max_covering_set()
    );

    for _ in 0..300 {
        let a = h(next() as usize % (BLOCKS + 1));
        let b = h(next() as usize % (BLOCKS + 1));
        assert_eq!(
            dag.is_dag_ancestor_of(&a, &b),
            dag.is_dag_ancestor_of_slow(&a, &b)
        );
    }
}
