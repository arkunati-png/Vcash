//! A reachability index for the block DAG.
//!
//! GHOSTDAG asks "is block `a` in the past of block `b`?" constantly. Answering by walking the
//! DAG costs time proportional to the size of the past, which grows without bound. This index
//! answers in roughly `O(log n + c)` instead, where `c` is the size of a small covering set.
//!
//! # Structure
//!
//! The *selected-parent tree* has an edge from every block to its selected parent. Two things
//! are stored:
//!
//! - **Jump pointers** (Myers' skew-binary scheme) give the ancestor of a block at any depth of
//!   that tree in `O(log n)` time with one extra pointer per block. That answers "is `a` a tree
//!   ancestor of `b`?".
//! - A **future covering set** for each block `a` lists blocks in `a`'s DAG future that are not
//!   already tree descendants of `a`, such that every DAG descendant of `a` is a tree descendant
//!   of `a` or of some member of the set. The members are mutually tree-incomparable.
//!
//! Then `a` is a DAG ancestor of `b` iff `a` is a tree ancestor of `b`, or some member of
//! `a`'s covering set is.
//!
//! # Updating
//!
//! When a block `B` is added, it is inserted into the covering set of every DAG ancestor `x` that
//! is neither a tree ancestor of `B` nor already covers it. The walk starts at `B`'s non-selected
//! parents and stops at blocks that need nothing (everything in their past is covered too, by
//! induction), so it only touches the part of the DAG that `B` newly merges.

use std::collections::{HashMap, HashSet, VecDeque};

use volt_core::VoltHash;

/// An index into the node table.
type Id = u32;

#[derive(Clone, Debug)]
struct Node {
    /// The selected parent, `None` for genesis.
    tree_parent: Option<Id>,
    /// The number of tree edges to genesis.
    depth: u32,
    /// A tree ancestor chosen so that ancestor queries take `O(log n)` steps.
    jump: Id,
    /// All DAG parents.
    parents: Vec<Id>,
    /// Blocks in the DAG future not covered by the tree. See the module documentation.
    covering: Vec<Id>,
}

/// The reachability index.
#[derive(Clone, Debug, Default)]
pub struct Reachability {
    ids: HashMap<VoltHash, Id>,
    nodes: Vec<Node>,
}

impl Reachability {
    /// Creates an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of indexed blocks.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Adds the genesis block, which must be the first block added.
    ///
    /// # Panics
    ///
    /// If the index is not empty.
    pub fn add_genesis(&mut self, hash: VoltHash) {
        assert!(self.nodes.is_empty(), "genesis must be added first");
        self.ids.insert(hash, 0);
        self.nodes.push(Node {
            tree_parent: None,
            depth: 0,
            jump: 0,
            parents: Vec::new(),
            covering: Vec::new(),
        });
    }

    /// Adds `hash` with the given DAG `parents`, one of which is the `selected_parent`.
    ///
    /// # Panics
    ///
    /// If a parent is unknown, `selected_parent` is not among `parents`, or `hash` is already
    /// indexed. The DAG checks these before calling.
    pub fn add_block(&mut self, hash: VoltHash, parents: &[VoltHash], selected_parent: VoltHash) {
        assert!(!self.ids.contains_key(&hash), "block already indexed");
        let parent_ids: Vec<Id> = parents.iter().map(|p| self.id(p)).collect();
        let sp = self.id(&selected_parent);
        assert!(parent_ids.contains(&sp), "the selected parent is a parent");

        let new_id = Id::try_from(self.nodes.len()).expect("fewer than 2^32 blocks are indexed");

        // Insert into the covering set of every DAG ancestor that needs it.
        let mut visited: HashSet<Id> = HashSet::new();
        let mut queue: VecDeque<Id> = parent_ids.iter().copied().filter(|p| *p != sp).collect();
        while let Some(x) = queue.pop_front() {
            if !visited.insert(x) {
                continue;
            }
            // A tree ancestor of the selected parent is a tree ancestor of `B`, and everything
            // in its past is covered already.
            if self.is_tree_ancestor_of(x, sp) {
                continue;
            }
            // Already covered through an existing member of its covering set.
            if self.nodes[x as usize]
                .covering
                .iter()
                .any(|c| self.is_tree_ancestor_of(*c, sp))
            {
                continue;
            }
            self.nodes[x as usize].covering.push(new_id);
            queue.extend(self.nodes[x as usize].parents.iter().copied());
        }

        // The new block is a tree leaf below its selected parent.
        let sp_node = &self.nodes[sp as usize];
        let (depth, jump) = {
            let parent_jump = sp_node.jump;
            let gap_to_jump = sp_node.depth - self.nodes[parent_jump as usize].depth;
            let jump_jump = self.nodes[parent_jump as usize].jump;
            let gap_jumps =
                self.nodes[parent_jump as usize].depth - self.nodes[jump_jump as usize].depth;
            let jump = if gap_to_jump == gap_jumps {
                jump_jump
            } else {
                sp
            };
            (sp_node.depth + 1, jump)
        };
        self.ids.insert(hash, new_id);
        self.nodes.push(Node {
            tree_parent: Some(sp),
            depth,
            jump,
            parents: parent_ids,
            covering: Vec::new(),
        });
    }

    fn id(&self, hash: &VoltHash) -> Id {
        *self
            .ids
            .get(hash)
            .expect("callers only pass blocks that were added to the index")
    }

    /// The tree ancestor of `v` at `depth`, which must not exceed `v`'s depth.
    fn ancestor_at_depth(&self, mut v: Id, depth: u32) -> Id {
        while self.nodes[v as usize].depth > depth {
            let node = &self.nodes[v as usize];
            v = if self.nodes[node.jump as usize].depth >= depth {
                node.jump
            } else {
                node.tree_parent
                    .expect("a block deeper than the target depth has a tree parent")
            };
        }
        v
    }

    /// Whether `a` is `b` or a selected-parent ancestor of `b`.
    fn is_tree_ancestor_of(&self, a: Id, b: Id) -> bool {
        let depth_a = self.nodes[a as usize].depth;
        depth_a <= self.nodes[b as usize].depth && self.ancestor_at_depth(b, depth_a) == a
    }

    /// Whether `ancestor` is `block` or is in the past of `block`.
    ///
    /// Returns `false` if either block is unknown.
    pub fn is_dag_ancestor_of(&self, ancestor: &VoltHash, block: &VoltHash) -> bool {
        let (Some(&a), Some(&b)) = (self.ids.get(ancestor), self.ids.get(block)) else {
            return false;
        };
        self.is_tree_ancestor_of(a, b)
            || self.nodes[a as usize]
                .covering
                .iter()
                .any(|c| self.is_tree_ancestor_of(*c, b))
    }

    /// The size of the largest covering set, for diagnostics.
    pub fn max_covering_set(&self) -> usize {
        self.nodes
            .iter()
            .map(|n| n.covering.len())
            .max()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u32) -> VoltHash {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&n.to_le_bytes());
        VoltHash(bytes)
    }

    #[test]
    fn a_chain_is_all_tree_ancestry() {
        let mut r = Reachability::new();
        r.add_genesis(h(0));
        for i in 1..200 {
            r.add_block(h(i), &[h(i - 1)], h(i - 1));
        }
        assert!(r.is_dag_ancestor_of(&h(0), &h(199)));
        assert!(r.is_dag_ancestor_of(&h(57), &h(58)));
        assert!(r.is_dag_ancestor_of(&h(57), &h(57)));
        assert!(!r.is_dag_ancestor_of(&h(58), &h(57)));
        assert_eq!(
            r.max_covering_set(),
            0,
            "no non-tree edges, no covering sets"
        );
    }

    #[test]
    fn a_merge_makes_the_side_branch_an_ancestor() {
        // g <- a <- b ; g <- x ; m merges b and x, selecting b.
        let mut r = Reachability::new();
        r.add_genesis(h(0));
        r.add_block(h(1), &[h(0)], h(0)); // a
        r.add_block(h(2), &[h(1)], h(1)); // b
        r.add_block(h(3), &[h(0)], h(0)); // x
        assert!(
            !r.is_dag_ancestor_of(&h(3), &h(2)),
            "siblings before the merge"
        );

        r.add_block(h(4), &[h(2), h(3)], h(2)); // m
        assert!(
            r.is_dag_ancestor_of(&h(3), &h(4)),
            "x is in m's past through the merge"
        );
        assert!(r.is_dag_ancestor_of(&h(0), &h(4)));
        assert!(!r.is_dag_ancestor_of(&h(4), &h(3)));

        // A block built on m inherits the merged past.
        r.add_block(h(5), &[h(4)], h(4));
        assert!(r.is_dag_ancestor_of(&h(3), &h(5)));
    }

    #[test]
    fn unknown_blocks_are_not_ancestors() {
        let mut r = Reachability::new();
        r.add_genesis(h(0));
        assert!(!r.is_dag_ancestor_of(&h(9), &h(0)));
        assert!(!r.is_dag_ancestor_of(&h(0), &h(9)));
    }
}
