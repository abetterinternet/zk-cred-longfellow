//! Merkle tree, specified in [Section 4.1][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.1

use anyhow::anyhow;
use sha2::{Digest, Sha256};

/// The value of a node of a [`MerkleTree`]. A tree could use various hashing algorithms, but we
/// only support SHA-256, and so a `Digest` is always a 32 byte array, saving us a heap allocation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Node([u8; 32]);

impl From<[u8; 32]> for Node {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// An inclusion proof from a Merkle tree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Proof(Vec<Node>);

/// A Merkle tree of digests, enabling proofs that some digest is a leaf of the tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleTree {
    /// The nodes of the tree. The root is at index 1. Index 0 is unused.
    digests: Vec<Node>,
}

impl MerkleTree {
    /// Create a new tree big enough for the specified number of leaves.
    pub fn new(leaf_count: usize) -> Self {
        Self {
            digests: vec![Node::default(); 2 * leaf_count],
        }
    }

    /// Number of leaf nodes in the tree.
    fn leaf_count(&self) -> usize {
        self.tree_size() / 2
    }

    /// Number of nodes in the tree.
    fn tree_size(&self) -> usize {
        self.digests.len()
    }

    /// Index of left child of index.
    fn left_child_index(index: usize) -> usize {
        2 * index
    }

    /// Index of right child of index.
    fn right_child_index(index: usize) -> usize {
        2 * index + 1
    }

    /// Insert the leaf into the tree.
    pub fn set_leaf(&mut self, position: usize, leaf: Node) {
        let first_leaf_index = self.leaf_count();
        self.digests[first_leaf_index + position] = leaf;
    }

    /// Hash `left` and `right` together into a new `Node`.
    fn hash_children(left: Node, right: Node) -> Node {
        let mut sha256 = Sha256::new();
        sha256.update(left.0);
        sha256.update(right.0);
        let array: [u8; 32] = sha256.finalize().into();
        array.into()
    }

    /// Build the tree up from the leaves to the root.
    pub fn build(&mut self) {
        // Iterate backward over inner nodes, computing each node's digest from its two children.
        for index in (1..self.leaf_count()).rev() {
            self.digests[index] = Self::hash_children(
                self.digests[Self::left_child_index(index)],
                self.digests[Self::right_child_index(index)],
            );
        }
    }

    /// Get the digest at the root of the tree.
    pub fn root(&self) -> Node {
        self.digests[1]
    }

    fn mark_tree(tree_size: usize, leaf_count: usize, requested_leaves: &[usize]) -> Vec<bool> {
        let mut marked = vec![false; tree_size];

        for requested_leaf in requested_leaves {
            marked[leaf_count + requested_leaf] = true;
        }

        // Mark inner nodes if either child is marked.
        for index in (1..leaf_count).rev() {
            marked[index] =
                marked[Self::left_child_index(index)] || marked[Self::right_child_index(index)];
        }

        marked
    }

    /// Prove that all the requested leaves are included in the tree. The indices are into the leaf
    /// layer of the tree.
    pub fn prove(&self, requested_leaves: &[usize]) -> Proof {
        let marked = Self::mark_tree(self.tree_size(), self.leaf_count(), requested_leaves);

        let mut proof = Vec::new();

        for index in (1..self.leaf_count()).rev() {
            if marked[index] {
                let mut child_index = Self::left_child_index(index);
                if marked[child_index] {
                    child_index = Self::right_child_index(index);
                }
                if !marked[child_index] {
                    proof.push(self.digests[child_index]);
                }
            }
        }

        Proof(proof)
    }

    /// Verify that the `proof` proves that the `included_nodes` (each consisting of a digest and
    /// a leaf index) are included in the tree of size `leaf_count`, rooted at `root`.
    pub fn verify(
        root: Node,
        leaf_count: usize,
        included_nodes: &[Node],
        included_node_indices: &[usize],
        proof: &Proof,
    ) -> Result<(), anyhow::Error> {
        if included_nodes.len() != included_node_indices.len() {
            return Err(anyhow!("lengths of nodes and node indices must match"));
        }
        for leaf_index in included_node_indices {
            if *leaf_index >= leaf_count {
                return Err(anyhow!("included nodes index exceeds tree size"));
            }
        }

        // Partial tree constructed from provided leaf nodes
        let mut partial_tree = vec![None; 2 * leaf_count];

        let mut proof_iter = proof.0.iter();
        let marked = Self::mark_tree(leaf_count * 2, leaf_count, included_node_indices);

        for index in (1..leaf_count).rev() {
            if marked[index] {
                let mut child_index = Self::left_child_index(index);
                if marked[child_index] {
                    child_index = Self::right_child_index(index)
                }

                if !marked[child_index] {
                    let Some(proof_node) = proof_iter.next() else {
                        return Err(anyhow!("not enough proof elements to prove inclusion"));
                    };
                    partial_tree[child_index] = Some(*proof_node);
                }
            }
        }

        // Fill leaves with included nodes
        for (included_node, included_node_index) in included_nodes.iter().zip(included_node_indices)
        {
            let leaf_index = included_node_index + leaf_count;
            partial_tree[leaf_index] = Some(*included_node);
        }

        // Compute necessary inner nodes
        for index in (1..leaf_count).rev() {
            let left_child = Self::left_child_index(index);
            let right_child = Self::right_child_index(index);
            if let (Some(left_child), Some(right_child)) =
                (partial_tree[left_child], partial_tree[right_child])
            {
                partial_tree[index] = Some(Self::hash_children(left_child, right_child));
            }
        }

        if partial_tree[1] != Some(root) {
            return Err(anyhow!("partial tree root does not match"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_tree() -> MerkleTree {
        let mut tree = MerkleTree::new(4);
        tree.set_leaf(0, Node([1; 32]));
        tree.set_leaf(1, Node([2; 32]));
        tree.set_leaf(2, Node([3; 32]));
        tree.set_leaf(3, Node([4; 32]));

        tree.build();

        tree
    }

    #[test]
    fn prove_all_leaves() {
        let tree = simple_tree();
        let proof = tree.prove(&[0, 1, 2, 3]);

        MerkleTree::verify(
            tree.root(),
            4,
            &[Node([1; 32]), Node([2; 32]), Node([3; 32]), Node([4; 32])],
            &[0, 1, 2, 3],
            &proof,
        )
        .unwrap();

        for (invalid_nodes, invalid_indices) in [
            // Missing a leaf
            (
                vec![Node([1; 32]), Node([2; 32]), Node([4; 32])],
                vec![0, 1, 3],
            ),
            // Wrong node values
            (
                vec![Node([5; 32]), Node([2; 32]), Node([3; 32]), Node([4; 32])],
                vec![0, 1, 2, 3],
            ),
            // Out of range node indices
            (
                vec![Node([1; 32]), Node([2; 32]), Node([3; 32]), Node([4; 32])],
                vec![5, 1, 2, 3],
            ),
            // Wrong node indices
            (
                vec![Node([1; 32]), Node([2; 32]), Node([3; 32]), Node([4; 32])],
                vec![1, 0, 2, 3],
            ),
        ] {
            MerkleTree::verify(
                tree.root(),
                4,
                invalid_nodes.as_slice(),
                invalid_indices.as_slice(),
                &proof,
            )
            .unwrap_err();
        }
    }

    #[test]
    fn prove_leaf_subset() {
        let tree = simple_tree();
        let proof = tree.prove(&[0, 1]);

        MerkleTree::verify(
            tree.root(),
            4,
            &[Node([1; 32]), Node([2; 32])],
            &[0, 1],
            &proof,
        )
        .unwrap();

        for (invalid_nodes, invalid_indices) in [
            // Leaves exist but aren't in proof
            (vec![Node([2; 32]), Node([4; 32])], vec![1, 3]),
            // Missing a leaf
            (vec![Node([1; 32])], vec![0]),
            // Wrong node values
            (vec![Node([5; 32]), Node([3; 32])], vec![0, 2]),
            // Out of range node indices
            (vec![Node([1; 32]), Node([2; 32])], vec![5, 0]),
            // Wrong node indices
            (vec![Node([1; 32]), Node([2; 32])], vec![1, 0]),
        ] {
            MerkleTree::verify(
                tree.root(),
                4,
                invalid_nodes.as_slice(),
                invalid_indices.as_slice(),
                &proof,
            )
            .unwrap_err();
        }
    }

    #[test]
    fn prove_multiple_subtrees() {
        let tree = simple_tree();
        let proof = tree.prove(&[0, 3]);

        MerkleTree::verify(
            tree.root(),
            4,
            &[Node([1; 32]), Node([4; 32])],
            &[0, 3],
            &proof,
        )
        .unwrap();

        for (invalid_nodes, invalid_indices) in [
            // Leaves exist but aren't in proof
            (vec![Node([2; 32]), Node([3; 32])], vec![1, 2]),
            // Missing a leaf
            (vec![Node([1; 32])], vec![0]),
            // Wrong node values
            (vec![Node([5; 32]), Node([4; 32])], vec![0, 3]),
            // Out of range node indices
            (vec![Node([1; 32]), Node([4; 32])], vec![5, 3]),
            // Wrong node indices
            (vec![Node([1; 32]), Node([4; 32])], vec![1, 3]),
        ] {
            MerkleTree::verify(
                tree.root(),
                4,
                invalid_nodes.as_slice(),
                invalid_indices.as_slice(),
                &proof,
            )
            .unwrap_err();
        }
    }
}
