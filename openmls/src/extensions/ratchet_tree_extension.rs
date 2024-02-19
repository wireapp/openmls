use std::fmt::Formatter;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};
use crate::treesync::{RatchetTree, RatchetTreeIn};

/// # Ratchet Tree Extension.
///
/// The ratchet tree extension contains a list of (optional) [`Node`](crate::treesync::node::Node)s that
/// represent the public state of the tree in an MLS group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// optional<Node> ratchet_tree<V>;
/// ```
#[derive(
    PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct RatchetTreeExtension {
    pub(crate) ratchet_tree: RatchetTreeIn,
}

impl std::fmt::Debug for RatchetTreeExtension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.ratchet_tree)
    }
}

impl RatchetTreeExtension {
    /// Build a new extension from a vector of [`Node`](crate::treesync::node::Node)s.
    pub fn new(ratchet_tree: RatchetTree) -> Self {
        RatchetTreeExtension {
            ratchet_tree: ratchet_tree.into(),
        }
    }

    /// Return the [`RatchetTreeIn`] from this extension.
    pub fn ratchet_tree(&self) -> &RatchetTreeIn {
        &self.ratchet_tree
    }
}
