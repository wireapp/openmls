//! 7.4. Parent Hash
//!
//! struct {
//!     HPKEPublicKey public_key;
//!     opaque parent_hash<0..255>;
//!     HPKEPublicKey original_child_resolution<0..2^32-1>;
//! } ParentHashInput;
//!
//! 7.5. Tree Hashes
//!
//! ```text
//! struct {
//!     uint8 present;
//!     select (present) {
//!         case 0: struct{};
//!         case 1: T value;
//!     }
//! } optional<T>;
//!
//! struct {
//!     uint32 node_index;
//!     optional<KeyPackage> key_package;
//! } LeafNodeHashInput;
//!
//! struct {
//!     HPKEPublicKey public_key;
//!     opaque parent_hash<0..255>;
//!     uint32 unmerged_leaves<0..2^32-1>;
//! } ParentNode;
//!
//! struct {
//!     uint32 node_index;
//!     optional<ParentNode> parent_node;
//!     opaque left_hash<0..255>;
//!     opaque right_hash<0..255>;
//! } ParentNodeTreeHashInput;
//! ```

use super::node::ParentNode;
use super::*;
use crate::ciphersuite::{Ciphersuite, HPKEPublicKey};
use crate::codec::Codec;
use crate::key_packages::KeyPackage;

pub(crate) struct ParentHashInput<'a> {
    pub(crate) public_key: &'a HPKEPublicKey,
    pub(crate) parent_hash: &'a [u8],
    pub(crate) original_child_resolution: Vec<&'a HPKEPublicKey>,
}

impl<'a> ParentHashInput<'a> {
    pub(crate) fn new(
        tree: &'a RatchetTree,
        index: NodeIndex,
        child_index: NodeIndex,
        parent_hash: &'a [u8],
    ) -> Result<Self, ParentHashError> {
        let public_key = tree
            .public_tree
            .node(&index)
            .map_err(|_| TreeError::InvalidTree)?
            .as_ref()
            .ok_or(ParentHashError::BlankNode)?
            .as_parent_node()?
            .public_key();
        let original_child_resolution = tree.original_child_resolution(child_index)?;
        Ok(Self {
            public_key,
            parent_hash,
            original_child_resolution,
        })
    }
    pub(crate) fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}
pub struct LeafNodeHashInput<'a> {
    pub(crate) node_index: &'a NodeIndex,
    pub(crate) key_package: Option<&'a KeyPackage>,
}

impl<'a> LeafNodeHashInput<'a> {
    pub(crate) fn new(node_index: &'a NodeIndex, key_package: Option<&'a KeyPackage>) -> Self {
        Self {
            node_index,
            key_package,
        }
    }
    pub fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}
pub struct ParentNodeTreeHashInput<'a> {
    pub(crate) node_index: u32,
    pub(crate) parent_node: Option<&'a ParentNode>,
    pub(crate) left_hash: &'a [u8],
    pub(crate) right_hash: &'a [u8],
}

impl<'a> ParentNodeTreeHashInput<'a> {
    pub(crate) fn new(
        node_index: u32,
        parent_node: Option<&'a ParentNode>,
        left_hash: &'a [u8],
        right_hash: &'a [u8],
    ) -> Self {
        Self {
            node_index,
            parent_node,
            left_hash,
            right_hash,
        }
    }
    pub(crate) fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}

// === Parent hashes ===

impl RatchetTree {
    /// The list of HPKEPublicKey values of the nodes in the resolution of `index`
    /// but with the `unmerged_leaves` of the parent node omitted.
    pub(crate) fn original_child_resolution(
        &self,
        index: NodeIndex,
    ) -> Result<Vec<&HPKEPublicKey>, TreeError> {
        // Build the exclusion list that consists of the unmerged leaves of the parent
        // node
        let mut unmerged_leaves = vec![];
        // If the current index is not the root, we collect the unmerged leaves of the
        // parent
        if let Ok(parent_index) = treemath::parent(index, self.leaf_count()) {
            // Check if the target node is not blank
            if let Some(node) = self.public_tree.node(&parent_index)? {
                // Check if the target node is a parent.
                let parent_node = node.as_parent_node().map_err(|_| TreeError::InvalidTree)?;
                for index in parent_node.unmerged_leaves() {
                    unmerged_leaves.push(NodeIndex::from(*index as usize));
                }
            }
        };
        // Convert the exclusion list to a HashSet for faster searching
        let exclusion_list: HashSet<&NodeIndex> = unmerged_leaves.iter().collect();

        // Compute the resolution for the index with the exclusion list
        let resolution = self.resolve(index, &exclusion_list)?;

        // Build the list of HPKE public keys by iterating over the resolution
        Ok(resolution
            .iter()
            .map(|index| {
                self.public_tree
                    .node(index)
                    // We can unwrap here, because every index in the resolution
                    // should be within the tree.
                    .unwrap()
                    .as_ref()
                    // We can unwrap again, because nodes in the resolution can't be blank.
                    .unwrap()
                    .public_key()
            })
            .collect())
    }

    /// Computes the parent hashes for a leaf node and returns the parent hash for
    /// the parent hash extension
    pub(crate) fn set_parent_hashes(&mut self, index: LeafIndex) -> Result<Vec<u8>, TreeError> {
        // Recursive helper function used to calculate parent hashes
        fn node_parent_hash(
            tree: &mut RatchetTree,
            index: NodeIndex,
            former_index: NodeIndex,
        ) -> Result<Vec<u8>, TreeError> {
            let tree_size = tree.leaf_count();
            let root = treemath::root(tree_size);
            // When the group only has one member, there are no parent nodes
            if tree.leaf_count().as_usize() <= 1 {
                return Ok(vec![]);
            }

            // Calculate the sibling of the former index
            // It is ok to use `unwrap()` here, since we never reach the root
            let former_index_sibling = treemath::sibling(former_index, tree_size).unwrap();
            // If we already reached the tree's root, return the hash of that node
            let parent_hash = if index == root {
                vec![]
            // Otherwise return the hash of the next parent
            } else {
                // Calculate the parent's index
                // It is ok to use `unwrap()` here, since we already checked that the index is
                // not the root
                let parent = treemath::parent(index, tree_size).unwrap();
                node_parent_hash(tree, parent, index)?
            };
            // If the current node is a parent, replace the parent hash in that
            // node. If it's blank, we throw an error, as it should not be blank
            // when computing parent hashes.
            let current_node = tree
                .public_tree
                .node_mut(&index)?
                .take()
                .ok_or(TreeError::InvalidTree)?;
            // Get the parent node
            let result = if let Node::Parent(mut parent_node) = current_node {
                // Set the parent hash
                parent_node.set_parent_hash(parent_hash);
                // Calculate the parent hash of the current node and return it
                ParentHashInput::new(tree, index, former_index_sibling, parent_node.parent_hash())
                    // It is ok to use `unwrap()` here, since we can be sure the node is not blank
                    .unwrap()
                    .hash(tree.ciphersuite)
            // Otherwise we reached the leaf level, just return the hash
            } else {
                parent_hash
            };
            Ok(result)
        }
        // The same index is used for the former index here, since that parameter is
        // ignored when starting with a leaf node
        node_parent_hash(self, index.into(), index.into())
    }

    // === Tree hash ===

    /// Computes and returns the tree hash
    pub(crate) fn tree_hash(&self) -> Vec<u8> {
        // Recursive helper function to the tree hashes for a node
        fn node_hash(tree: &RatchetTree, index: NodeIndex) -> Vec<u8> {
            // We can unwrap here, because this function is private and only
            // called on indices within the tree.
            let node_option = tree.public_tree.node(&index).unwrap().as_ref();
            // Depending on the node type, we calculate the hash differently
            if index.is_leaf() {
                // For leaf nodes we just need the index and the KeyPackage
                let key_package_option = node_option.map(|node| node.as_leaf_node().unwrap());
                let leaf_node_hash = LeafNodeHashInput::new(&index, key_package_option);
                leaf_node_hash.hash(tree.ciphersuite)
            } else {
                // For parent nodes we need the hash of the two children as well
                let parent_node_option = node_option.map(|node| node.as_parent_node().unwrap());
                // Unwrapping here is safe, because parent nodes always have children
                let left = treemath::left(index).unwrap();
                let left_hash = node_hash(tree, left);
                let right = treemath::right(index, tree.leaf_count()).unwrap();
                let right_hash = node_hash(tree, right);
                let parent_node_hash = ParentNodeTreeHashInput::new(
                    index.as_u32(),
                    parent_node_option,
                    &left_hash,
                    &right_hash,
                );
                parent_node_hash.hash(tree.ciphersuite)
            }
        }
        // We start with the root and traverse the tree downwards
        let root = treemath::root(self.leaf_count());
        node_hash(&self, root)
    }
}
