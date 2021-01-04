use crate::ciphersuite::*;
use crate::codec::*;
use crate::extensions::*;

use super::*;

#[derive(PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeType {
    Leaf = 0,
    Parent = 1,
    Default = 255,
}

impl From<u8> for NodeType {
    fn from(value: u8) -> Self {
        match value {
            0 => NodeType::Leaf,
            1 => NodeType::Parent,
            _ => NodeType::Default,
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
    pub fn public_key(&self) -> Option<&HPKEPublicKey> {
        match self {
            Node::Leaf(key_package) => Some(key_package.hpke_init_key()),
            Node::Parent(parent_node) => Some(&parent_node.public_key()),
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

    /// Obtain a `ParentNode` from a `Node`. Returns a `NodeError` if the given
    /// node is a `Leaf`.
    pub(crate) fn as_parent_node(&self) -> Result<&ParentNode, NodeError> {
        match self {
            Node::Leaf(_) => Err(NodeError::InvalidNodeType),
            Node::Parent(parent_node) => Ok(parent_node),
        }
    }
}

impl ParentNode {
    pub fn new(public_key: HPKEPublicKey, unmerged_leaves: &[u32], parent_hash: &[u8]) -> Self {
        Self {
            public_key,
            unmerged_leaves: unmerged_leaves.to_vec(),
            parent_hash: parent_hash.to_vec(),
        }
    }
    pub fn public_key(&self) -> &HPKEPublicKey {
        &self.public_key
    }
    pub fn set_parent_hash(&mut self, hash: Vec<u8>) {
        self.parent_hash = hash;
    }
    pub fn unmerged_leaves(&self) -> &[u32] {
        &self.unmerged_leaves
    }
    pub fn unmerged_leaves_mut(&mut self) -> &mut Vec<u32> {
        &mut self.unmerged_leaves
    }
}

impl Codec for ParentNode {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.public_key.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.unmerged_leaves)?;
        encode_vec(VecSize::VecU8, buffer, &self.parent_hash)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = HPKEPublicKey::decode(cursor)?;
        let unmerged_leaves = decode_vec(VecSize::VecU32, cursor)?;
        let parent_hash = decode_vec(VecSize::VecU8, cursor)?;
        Ok(ParentNode {
            public_key,
            unmerged_leaves,
            parent_hash,
        })
    }
}
