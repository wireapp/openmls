use crate::ciphersuite::*;
use crate::extensions::*;

use super::*;
use std::convert::TryFrom;

/// Node type. Can be either `Leaf` or `Parent`.
#[derive(PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeType {
    Leaf = 0,
    Parent = 1,
}

impl NodeType {
    /// Returns `true` if the node type is `Leaf` and `false` otherwise.
    pub fn is_leaf(&self) -> bool {
        self == &NodeType::Leaf
    }

    /// Returns `true` if the node type is `Parent` and `false` otherwise.
    pub fn is_parent(&self) -> bool {
        self == &NodeType::Parent
    }
}

impl TryFrom<u8> for NodeType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(NodeType::Leaf),
            1 => Ok(NodeType::Parent),
            _ => Err("Unknown node type."),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum NodeContent {
    Leaf(KeyPackage),
    Parent(ParentNode),
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct ParentNode {
    public_key: HPKEPublicKey,
    unmerged_leaves: Vec<u32>,
    parent_hash: Vec<u8>,
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Node {
    Leaf(KeyPackage),
    Parent(ParentNode),
}

impl Node {
    pub fn public_key(&self) -> &HPKEPublicKey {
        match self {
            Node::Leaf(key_package) => key_package.hpke_init_key(),
            Node::Parent(parent_node) => parent_node.public_key(),
        }
    }

    pub fn hash(&self, ciphersuite: &Ciphersuite) -> Option<Vec<u8>> {
        match self {
            Node::Parent(parent_node) => {
                let payload = parent_node.encode_detached().unwrap();
                let node_hash = ciphersuite.hash(&payload);
                Some(node_hash)
            }
            Node::Leaf(_) => None,
        }
    }

    // TODO: #98 should this really return a vec?
    pub fn parent_hash(&self) -> Option<Vec<u8>> {
        match self {
            Node::Parent(parent_node) => Some(parent_node.parent_hash.clone()),
            Node::Leaf(key_package) => {
                let parent_hash_extension =
                    key_package.extension_with_type(ExtensionType::ParentHash);
                match parent_hash_extension {
                    Some(phe) => {
                        let phe = match phe.to_parent_hash_extension() {
                            Ok(phe) => phe,
                            Err(_) => return None,
                        };
                        Some(phe.parent_hash().to_vec())
                    }
                    None => None,
                }
            }
        }
    }

    /// Obtain a `KeyPackage` from a `Node`. Returns a `NodeError` if the given
    /// node is a `ParentNode`.
    pub(crate) fn as_leaf_node(&self) -> Result<&KeyPackage, NodeError> {
        match self {
            Node::Leaf(key_package) => Ok(key_package),
            Node::Parent(_) => Err(NodeError::InvalidNodeType),
        }
    }

    /// Obtain a `KeyPackage` from a `Node`. Returns a `NodeError` if the given
    /// node is a `ParentNode`.
    pub(crate) fn as_leaf_node_mut(&mut self) -> Result<&mut KeyPackage, NodeError> {
        match self {
            Node::Leaf(key_package) => Ok(key_package),
            Node::Parent(_) => Err(NodeError::InvalidNodeType),
        }
    }

/// Content of a parent node.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ParentNode {
    pub(crate) public_key: HPKEPublicKey,
    pub(crate) unmerged_leaves: Vec<u32>,
    pub(crate) parent_hash: Vec<u8>,
}

impl ParentNode {
    /// Creates a new `ParentNode` from the provided values.
    pub fn new(public_key: HPKEPublicKey, unmerged_leaves: &[u32], parent_hash: &[u8]) -> Self {
        Self {
            public_key,
            unmerged_leaves: unmerged_leaves.to_vec(),
            parent_hash: parent_hash.to_vec(),
        }
    }
    /// Returns the node's HPKE public key
    pub fn public_key(&self) -> &HPKEPublicKey {
        &self.public_key
    }
    /// Sets the node's parent hash
    pub fn set_parent_hash(&mut self, hash: Vec<u8>) {
        self.parent_hash = hash;
    }
    /// Returns the node's unmerged leaves
    pub fn unmerged_leaves(&self) -> &[u32] {
        &self.unmerged_leaves
    }
    /// Adds a leaf to the node's unmerged leaves
    pub fn add_unmerged_leaf(&mut self, leaf: u32) {
        self.unmerged_leaves.push(leaf);
    }
}

impl Codec for &ParentNode {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.public_key.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.unmerged_leaves)?;
        encode_vec(VecSize::VecU8, buffer, &self.parent_hash)?;
        Ok(())
    }
}
