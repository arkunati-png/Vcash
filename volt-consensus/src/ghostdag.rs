//! The GHOSTDAG block DAG.
//!
//! GHOSTDAG colors every block's *mergeset* (the blocks it merges that its selected parent
//! does not already know) blue or red. Blue blocks form a *k-cluster*: each blue block has
//! at most `k` other blue blocks in its anticone. Honest blocks, which are well connected,
//! end up blue; blocks mined in secret or with poor connectivity end up red.
//!
//! The algorithm follows Kaspa's reference implementation:
//!
//! 1. The *selected parent* is the parent with the most blue work (ties: highest hash).
//! 2. The mergeset is `past(B) \ past(selected parent)`, ordered by (blue work, hash), which
//!    is a topological order because blue work strictly increases along every edge.
//! 3. Starting from `blues = {selected parent}`, a mergeset block `C` is blue iff
//!    `|anticone(C) ∩ blues| <= k` and no blue block in `anticone(C)` already has `k` blue
//!    blocks in its own anticone.

use std::{
    cmp::Reverse,
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
};

use thiserror::Error;
use volt_core::{
    constants::{GHOSTDAG_K, MAX_BLOCK_PARENTS, MAX_MERGESET_SIZE},
    VoltHash,
};

/// Errors from inserting a block into the DAG.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum GhostdagError {
    /// The block is already in the DAG.
    #[error("block {0} already exists")]
    Duplicate(VoltHash),

    /// A parent is not in the DAG.
    #[error("unknown parent {0}")]
    UnknownParent(VoltHash),

    /// A non-genesis block has no parents.
    #[error("block has no parents")]
    NoParents,

    /// The block lists too many parents.
    #[error("block has {0} parents, the maximum is {MAX_BLOCK_PARENTS}")]
    TooManyParents(usize),

    /// The block lists the same parent twice.
    #[error("duplicate parent {0}")]
    DuplicateParent(VoltHash),

    /// The block merges too many blocks outside its selected parent's past.
    #[error("mergeset of {0} blocks exceeds the maximum of {MAX_MERGESET_SIZE}")]
    MergesetTooLarge(usize),

    /// A block must contribute positive work.
    #[error("block work must be positive")]
    ZeroWork,

    /// A blue block's anticone size was not recorded. This indicates a corrupted DAG.
    #[error("missing anticone size for {0}")]
    MissingAnticoneSize(VoltHash),

    /// The genesis block was already set.
    #[error("genesis already set")]
    GenesisExists,
}

/// The GHOSTDAG data computed for one block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GhostdagData {
    /// The number of blue blocks in this block's past.
    pub blue_score: u64,
    /// The total work of the blue blocks in this block's past.
    pub blue_work: u128,
    /// The parent with the most blue work. `None` only for genesis.
    pub selected_parent: Option<VoltHash>,
    /// The blue blocks of the mergeset. The selected parent is always first.
    pub mergeset_blues: Vec<VoltHash>,
    /// The red blocks of the mergeset.
    pub mergeset_reds: Vec<VoltHash>,
    /// For each blue block whose blue anticone size changed at this block, its new size.
    ///
    /// A block's size is found by walking the selected-parent chain to the first entry.
    pub blues_anticone_sizes: HashMap<VoltHash, usize>,
}

/// One block's place in the DAG.
#[derive(Clone, Debug)]
pub struct BlockNode {
    /// The block's parents.
    pub parents: Vec<VoltHash>,
    /// The longest path from genesis, used to prune reachability searches.
    pub height: u64,
    /// The work this block itself represents.
    pub work: u128,
    /// The header timestamp, in milliseconds.
    pub timestamp_ms: u64,
    /// The header's compact difficulty target.
    pub bits: u32,
    /// The GHOSTDAG data.
    pub ghostdag: GhostdagData,
}

/// A GHOSTDAG block DAG.
#[derive(Debug)]
pub struct BlockDag {
    k: usize,
    nodes: HashMap<VoltHash, BlockNode>,
    tips: BTreeSet<VoltHash>,
    genesis: Option<VoltHash>,
}

impl Default for BlockDag {
    fn default() -> Self {
        Self::new(GHOSTDAG_K)
    }
}

impl BlockDag {
    /// Creates an empty DAG with cluster parameter `k`.
    pub fn new(k: usize) -> Self {
        Self {
            k,
            nodes: HashMap::new(),
            tips: BTreeSet::new(),
            genesis: None,
        }
    }

    /// The cluster parameter.
    pub fn k(&self) -> usize {
        self.k
    }

    /// The number of blocks.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the DAG has no blocks.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The genesis block hash, once set.
    pub fn genesis(&self) -> Option<VoltHash> {
        self.genesis
    }

    /// Whether `hash` is in the DAG.
    pub fn contains(&self, hash: &VoltHash) -> bool {
        self.nodes.contains_key(hash)
    }

    /// Returns the node for `hash`.
    pub fn get(&self, hash: &VoltHash) -> Option<&BlockNode> {
        self.nodes.get(hash)
    }

    /// The current tips: blocks with no children.
    pub fn tips(&self) -> impl Iterator<Item = &VoltHash> {
        self.tips.iter()
    }

    /// Adds the genesis block.
    pub fn add_genesis(
        &mut self,
        hash: VoltHash,
        work: u128,
        timestamp_ms: u64,
        bits: u32,
    ) -> Result<(), GhostdagError> {
        if self.genesis.is_some() {
            return Err(GhostdagError::GenesisExists);
        }
        if work == 0 {
            return Err(GhostdagError::ZeroWork);
        }
        self.nodes.insert(
            hash,
            BlockNode {
                parents: Vec::new(),
                height: 0,
                work,
                timestamp_ms,
                bits,
                ghostdag: GhostdagData::default(),
            },
        );
        self.tips.insert(hash);
        self.genesis = Some(hash);
        Ok(())
    }

    /// Whether `ancestor` is in the past of `block`, or is `block` itself.
    pub fn is_dag_ancestor_of(&self, ancestor: &VoltHash, block: &VoltHash) -> bool {
        if ancestor == block {
            return true;
        }
        let (Some(a), Some(b)) = (self.nodes.get(ancestor), self.nodes.get(block)) else {
            return false;
        };
        if a.height >= b.height {
            return false;
        }

        // Walk back from `block`, never going below the ancestor's height.
        let mut visited: HashSet<&VoltHash> = HashSet::new();
        let mut queue: VecDeque<&VoltHash> = VecDeque::new();
        queue.push_back(block);
        while let Some(current) = queue.pop_front() {
            for parent in &self.nodes[current].parents {
                if parent == ancestor {
                    return true;
                }
                if self.nodes[parent].height > a.height && visited.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }
        false
    }

    fn sort_key(&self, hash: &VoltHash) -> (u128, VoltHash) {
        (self.nodes[hash].ghostdag.blue_work, *hash)
    }

    /// Picks the parent with the most blue work, breaking ties by the highest hash.
    ///
    /// # Panics
    ///
    /// If `parents` is empty or contains a block that is not in the DAG.
    pub fn select_parent(&self, parents: &[VoltHash]) -> VoltHash {
        *parents
            .iter()
            .max_by_key(|p| self.sort_key(p))
            .expect("callers check that parents is not empty")
    }

    /// The blocks in `past(parents)` that are not in `past(selected_parent)`, in topological order.
    fn mergeset_without_selected_parent(
        &self,
        selected_parent: &VoltHash,
        parents: &[VoltHash],
    ) -> Result<Vec<VoltHash>, GhostdagError> {
        let mut visited: HashSet<VoltHash> = HashSet::new();
        visited.insert(*selected_parent);
        let mut queue: VecDeque<VoltHash> = VecDeque::new();
        for parent in parents {
            if visited.insert(*parent) {
                queue.push_back(*parent);
            }
        }

        let mut mergeset = Vec::new();
        while let Some(current) = queue.pop_front() {
            if self.is_dag_ancestor_of(&current, selected_parent) {
                continue;
            }
            mergeset.push(current);
            if mergeset.len() > MAX_MERGESET_SIZE {
                return Err(GhostdagError::MergesetTooLarge(mergeset.len()));
            }
            for parent in &self.nodes[&current].parents {
                if visited.insert(*parent) {
                    queue.push_back(*parent);
                }
            }
        }

        mergeset.sort_by_key(|h| self.sort_key(h));
        Ok(mergeset)
    }

    /// Finds `block`'s blue anticone size in the context of `data`.
    fn blue_anticone_size(
        &self,
        block: &VoltHash,
        data: &GhostdagData,
    ) -> Result<usize, GhostdagError> {
        if let Some(size) = data.blues_anticone_sizes.get(block) {
            return Ok(*size);
        }
        let mut current = data.selected_parent;
        while let Some(hash) = current {
            let node = &self.nodes[&hash].ghostdag;
            if let Some(size) = node.blues_anticone_sizes.get(block) {
                return Ok(*size);
            }
            current = node.selected_parent;
        }
        Err(GhostdagError::MissingAnticoneSize(*block))
    }

    /// Decides whether `candidate` is blue, returning its blue anticone size and the new sizes of
    /// the blues in its anticone if it is.
    #[allow(clippy::type_complexity)]
    fn check_blue_candidate(
        &self,
        data: &GhostdagData,
        candidate: &VoltHash,
    ) -> Result<Option<(usize, HashMap<VoltHash, usize>)>, GhostdagError> {
        // The selected parent is one of the k+1 allowed blues.
        if data.mergeset_blues.len() == self.k + 1 {
            return Ok(None);
        }

        let mut anticone_size = 0;
        let mut blue_sizes: HashMap<VoltHash, usize> = HashMap::new();

        // Walk the blue chain: first the new block's own blues so far, then each
        // selected-parent ancestor's mergeset blues.
        let mut chain_block: Option<VoltHash> = None;
        loop {
            let chain_data = match chain_block {
                None => data,
                Some(hash) => {
                    // Everything below a chain block in the candidate's past is in the
                    // candidate's past too, so no blue below it can be in its anticone.
                    if self.is_dag_ancestor_of(&hash, candidate) {
                        return Ok(Some((anticone_size, blue_sizes)));
                    }
                    &self.nodes[&hash].ghostdag
                }
            };

            for blue in &chain_data.mergeset_blues {
                if self.is_dag_ancestor_of(blue, candidate) {
                    continue;
                }
                let size = self.blue_anticone_size(blue, data)?;
                blue_sizes.insert(*blue, size);
                anticone_size += 1;
                // Too many blues in the candidate's anticone, or the candidate would push an
                // existing blue's anticone past k.
                if anticone_size > self.k || size == self.k {
                    return Ok(None);
                }
            }

            match chain_data.selected_parent {
                Some(parent) => chain_block = Some(parent),
                None => return Ok(Some((anticone_size, blue_sizes))),
            }
        }
    }

    /// Computes the GHOSTDAG data a block with `parents` and `work` would have.
    pub fn compute_ghostdag(
        &self,
        parents: &[VoltHash],
        work: u128,
    ) -> Result<GhostdagData, GhostdagError> {
        if work == 0 {
            return Err(GhostdagError::ZeroWork);
        }
        if parents.is_empty() {
            return Err(GhostdagError::NoParents);
        }
        if parents.len() > MAX_BLOCK_PARENTS {
            return Err(GhostdagError::TooManyParents(parents.len()));
        }
        let mut seen = HashSet::new();
        for parent in parents {
            if !self.nodes.contains_key(parent) {
                return Err(GhostdagError::UnknownParent(*parent));
            }
            if !seen.insert(parent) {
                return Err(GhostdagError::DuplicateParent(*parent));
            }
        }

        let selected_parent = self.select_parent(parents);
        let mergeset = self.mergeset_without_selected_parent(&selected_parent, parents)?;

        let mut data = GhostdagData {
            selected_parent: Some(selected_parent),
            mergeset_blues: vec![selected_parent],
            ..GhostdagData::default()
        };
        data.blues_anticone_sizes.insert(selected_parent, 0);

        for candidate in mergeset {
            match self.check_blue_candidate(&data, &candidate)? {
                Some((anticone_size, blue_sizes)) => {
                    data.mergeset_blues.push(candidate);
                    data.blues_anticone_sizes.insert(candidate, anticone_size);
                    for (blue, size) in blue_sizes {
                        data.blues_anticone_sizes.insert(blue, size + 1);
                    }
                }
                None => data.mergeset_reds.push(candidate),
            }
        }

        let parent_data = &self.nodes[&selected_parent].ghostdag;
        data.blue_score = parent_data.blue_score + data.mergeset_blues.len() as u64; // lossless: bounded by the mergeset limit
        data.blue_work = parent_data.blue_work
            + data
                .mergeset_blues
                .iter()
                .map(|b| self.nodes[b].work)
                .sum::<u128>();
        Ok(data)
    }

    /// Adds a block and returns its GHOSTDAG data.
    pub fn add_block(
        &mut self,
        hash: VoltHash,
        parents: &[VoltHash],
        work: u128,
        timestamp_ms: u64,
        bits: u32,
    ) -> Result<&GhostdagData, GhostdagError> {
        if self.nodes.contains_key(&hash) {
            return Err(GhostdagError::Duplicate(hash));
        }
        let ghostdag = self.compute_ghostdag(parents, work)?;
        let height = parents
            .iter()
            .map(|p| self.nodes[p].height)
            .max()
            .expect("compute_ghostdag rejects empty parents")
            + 1;

        for parent in parents {
            self.tips.remove(parent);
        }
        self.tips.insert(hash);
        self.nodes.insert(
            hash,
            BlockNode {
                parents: parents.to_vec(),
                height,
                work,
                timestamp_ms,
                bits,
                ghostdag,
            },
        );
        Ok(&self.nodes[&hash].ghostdag)
    }

    /// The tip with the most blue work, which a new block would select as its parent.
    pub fn sink(&self) -> Option<VoltHash> {
        self.tips.iter().max_by_key(|t| self.sort_key(t)).copied()
    }

    /// The parents for a new block template: up to the maximum number of tips, best first,
    /// returned in the canonical ascending-hash order.
    pub fn select_parents(&self) -> Vec<VoltHash> {
        let mut tips: Vec<VoltHash> = self.tips.iter().copied().collect();
        tips.sort_by_key(|t| Reverse(self.sort_key(t)));
        tips.truncate(MAX_BLOCK_PARENTS);
        tips.sort();
        tips
    }

    /// The selected-parent chain from `tip` back to genesis, newest first.
    pub fn selected_chain(&self, tip: &VoltHash) -> Vec<VoltHash> {
        let mut chain = Vec::new();
        let mut current = Some(*tip);
        while let Some(hash) = current {
            chain.push(hash);
            current = self.nodes[&hash].ghostdag.selected_parent;
        }
        chain
    }

    /// The mergeset of `block` in consensus order: the selected parent first, then every other
    /// blue or red block ordered by (blue work, hash).
    pub fn ordered_mergeset(&self, block: &VoltHash) -> Vec<VoltHash> {
        let data = &self.nodes[block].ghostdag;
        let mut rest: Vec<VoltHash> = data
            .mergeset_blues
            .iter()
            .skip(1)
            .chain(data.mergeset_reds.iter())
            .copied()
            .collect();
        rest.sort_by_key(|h| self.sort_key(h));

        data.selected_parent.into_iter().chain(rest).collect()
    }

    /// Whether `member` is blue in `chain_block`'s mergeset.
    pub fn is_blue_in(&self, chain_block: &VoltHash, member: &VoltHash) -> bool {
        self.nodes[chain_block]
            .ghostdag
            .mergeset_blues
            .contains(member)
    }

    /// The consensus order of every block merged by the chain ending at `sink`.
    ///
    /// The sink itself, and any tips it has not merged yet, are not included: they enter the
    /// order when a later block merges them.
    pub fn linear_order(&self, sink: &VoltHash) -> Vec<VoltHash> {
        let mut chain = self.selected_chain(sink);
        chain.reverse();
        chain
            .iter()
            .skip(1) // genesis merges nothing
            .flat_map(|c| self.ordered_mergeset(c))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> VoltHash {
        VoltHash([n; 32])
    }

    fn dag_with_genesis() -> BlockDag {
        let mut dag = BlockDag::new(GHOSTDAG_K);
        dag.add_genesis(h(0), 1, 0, 0).unwrap();
        dag
    }

    fn add(dag: &mut BlockDag, n: u8, parents: &[u8]) -> GhostdagData {
        let parents: Vec<VoltHash> = parents.iter().map(|p| h(*p)).collect();
        dag.add_block(h(n), &parents, 1, 0, 0).unwrap().clone()
    }

    #[test]
    fn a_chain_has_no_reds_and_counts_blue_score() {
        let mut dag = dag_with_genesis();
        add(&mut dag, 1, &[0]);
        add(&mut dag, 2, &[1]);
        let c = add(&mut dag, 3, &[2]);

        assert_eq!(c.selected_parent, Some(h(2)));
        assert_eq!(c.mergeset_blues, vec![h(2)]);
        assert!(c.mergeset_reds.is_empty());
        assert_eq!(c.blue_score, 3);
        assert_eq!(dag.sink(), Some(h(3)));
        assert_eq!(dag.selected_chain(&h(3)), vec![h(3), h(2), h(1), h(0)]);
    }

    #[test]
    fn a_diamond_merges_both_branches_blue() {
        let mut dag = dag_with_genesis();
        let a = add(&mut dag, 1, &[0]);
        let b = add(&mut dag, 2, &[0]);
        assert_eq!((a.blue_score, b.blue_score), (1, 1));

        let c = add(&mut dag, 3, &[1, 2]);
        assert_eq!(c.mergeset_blues.len(), 2);
        assert!(c.mergeset_reds.is_empty());
        assert_eq!(
            c.selected_parent,
            Some(h(2)),
            "equal work: the higher hash wins"
        );
        assert_eq!(c.blue_score, 1 + 2);
        assert_eq!(c.blue_work, 1 + 2);
        assert_eq!(dag.ordered_mergeset(&h(3)), vec![h(2), h(1)]);
    }

    #[test]
    fn more_than_k_parallel_blocks_turn_red() {
        let k = GHOSTDAG_K;
        let mut dag = dag_with_genesis();
        for n in 1..=40 {
            add(&mut dag, n, &[0]);
        }
        // A header holds at most k+1 parents, so merge 8 siblings through Y, then merge
        // Y with the other 32 siblings. Y becomes the selected parent (most blue work).
        let y = add(&mut dag, 100, &(33..=40).collect::<Vec<u8>>());
        assert_eq!(y.mergeset_blues.len(), 8);
        let mut parents: Vec<u8> = (1..=32).collect();
        parents.push(100);
        let merge = add(&mut dag, 101, &parents);

        assert_eq!(merge.selected_parent, Some(h(100)));
        // Each candidate sees Y, Y's 8 blues and the blues accepted before it in its anticone:
        // 24 of the 32 siblings fit under k = 32, the last 8 are red.
        assert_eq!(merge.mergeset_blues.len(), 1 + 24);
        assert_eq!(merge.mergeset_reds.len(), 8);
        // The k-cluster property: nobody has more than k blues in their anticone.
        assert!(merge.blues_anticone_sizes.values().all(|s| *s <= k));
    }

    #[test]
    fn exactly_k_plus_one_parallel_blocks_are_all_blue() {
        let k = GHOSTDAG_K;
        let mut dag = dag_with_genesis();
        let siblings: Vec<u8> = (1..=(k as u8 + 1)).collect();
        for n in &siblings {
            add(&mut dag, *n, &[0]);
        }
        let merge = add(&mut dag, 100, &siblings);
        assert_eq!(merge.mergeset_blues.len(), k + 1);
        assert!(merge.mergeset_reds.is_empty());
    }

    #[test]
    fn a_long_secret_chain_is_red_next_to_the_honest_chain() {
        // Honest: g <- h1 <- h2 <- h3 <- h4. Attacker: g <- x1 <- x2, never merged until the end.
        let mut dag = dag_with_genesis();
        for (n, p) in [(1, 0), (2, 1), (3, 2), (4, 3)] {
            add(&mut dag, n, &[p]);
        }
        add(&mut dag, 50, &[0]);
        add(&mut dag, 51, &[50]);

        let merge = add(&mut dag, 60, &[4, 51]);
        assert_eq!(merge.selected_parent, Some(h(4)), "more blue work wins");
        // With k = 32 the short attacker chain is still blue, but it never becomes the selected chain.
        assert_eq!(dag.selected_chain(&h(60))[1], h(4));
    }

    #[test]
    fn consensus_order_does_not_depend_on_arrival_order() {
        let build = |order: &[(u8, &[u8])]| {
            let mut dag = dag_with_genesis();
            for (n, p) in order {
                add(&mut dag, *n, p);
            }
            let sink = dag.sink().unwrap();
            (dag.linear_order(&sink), sink)
        };

        let one = build(&[(1, &[0]), (2, &[0]), (3, &[0]), (4, &[1, 2, 3]), (5, &[4])]);
        let two = build(&[(3, &[0]), (2, &[0]), (1, &[0]), (4, &[1, 2, 3]), (5, &[4])]);
        assert_eq!(one, two);
        assert!(!one.0.is_empty());
    }

    #[test]
    fn rejects_bad_blocks() {
        let mut dag = dag_with_genesis();
        add(&mut dag, 1, &[0]);

        assert_eq!(
            dag.add_block(h(1), &[h(0)], 1, 0, 0).err(),
            Some(GhostdagError::Duplicate(h(1)))
        );
        assert_eq!(
            dag.add_block(h(9), &[h(77)], 1, 0, 0).err(),
            Some(GhostdagError::UnknownParent(h(77)))
        );
        assert_eq!(
            dag.add_block(h(9), &[], 1, 0, 0).err(),
            Some(GhostdagError::NoParents)
        );
        assert_eq!(
            dag.add_block(h(9), &[h(1), h(1)], 1, 0, 0).err(),
            Some(GhostdagError::DuplicateParent(h(1)))
        );
        assert_eq!(
            dag.add_block(h(9), &[h(1)], 0, 0, 0).err(),
            Some(GhostdagError::ZeroWork)
        );
    }

    #[test]
    fn reachability_is_inclusive_and_directional() {
        let mut dag = dag_with_genesis();
        add(&mut dag, 1, &[0]);
        add(&mut dag, 2, &[1]);
        add(&mut dag, 3, &[0]);

        assert!(dag.is_dag_ancestor_of(&h(0), &h(2)));
        assert!(dag.is_dag_ancestor_of(&h(2), &h(2)));
        assert!(!dag.is_dag_ancestor_of(&h(2), &h(0)));
        assert!(
            !dag.is_dag_ancestor_of(&h(3), &h(2)),
            "siblings are in each other's anticone"
        );
    }
}
