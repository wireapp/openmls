//! Tests for the ratchet tree

use crate::creds::CredentialBundle;
use crate::creds::CredentialType;
use crate::key_packages::KeyPackageBundle;
use crate::prelude::Config;
use crate::prelude::LeafIndex;

use super::index::NodeIndex;
use super::RatchetTree;

#[test]
fn test_ratchet_tree() {
    for ciphersuite in Config::supported_ciphersuites() {
        let cb = CredentialBundle::new(
            b"TestBundle".to_vec(),
            CredentialType::Basic,
            ciphersuite.name(),
        )
        .unwrap();
        let kpb =
            KeyPackageBundle::new(vec![ciphersuite.name()].as_slice(), &cb, Vec::new()).unwrap();

        // Create a tree with a single node.
        let ratchet_tree = RatchetTree::new(ciphersuite, kpb);

        assert_eq!(ratchet_tree.tree_size(), NodeIndex::from(1u32));
        assert_eq!(ratchet_tree.leaf_count(), LeafIndex::from(1u32));

        // Compute the resolution.
        let resolution = ratchet_tree.resolve(NodeIndex::from(0u32));
        assert!(resolution.is_ok());

        // The resolution should contain only the leaf node itself.
        assert_eq!(resolution.unwrap(), vec![NodeIndex::from(0u32)]);

        // Compute the resolution of an out-of-bound index.
        let resolution = ratchet_tree.resolve(NodeIndex::from(1u32));
        assert!(resolution.is_err());

        let new_kpb =
            KeyPackageBundle::new(vec![ciphersuite.name()].as_slice(), &cb, Vec::new()).unwrap();

        let mut ratchet_tree = ratchet_tree;
        // Add a node to the tree.
        let index_and_credential_vector =
            ratchet_tree.add_nodes(vec![new_kpb.get_key_package()].as_slice());

        assert!(index_and_credential_vector.len() == 1);

        let (added_index, added_credential) = index_and_credential_vector.first().unwrap();
        // Check that credential and node index are as expected.
        assert_eq!(added_credential, cb.credential());
        // The node index is 2, which corresponds to leaf index 1.
        assert_eq!(added_index, &NodeIndex::from(2u32));
        // Tree size should now be 3.
        assert_eq!(ratchet_tree.tree_size(), NodeIndex::from(3u32));
        // .. which corresponds to leaf_count 2.
        assert_eq!(ratchet_tree.leaf_count(), LeafIndex::from(2u32));

        // There should not be any free leaves as of now.
        let free_leaves = ratchet_tree.free_leaves();
        assert_eq!(free_leaves, Vec::new());
    }
}
