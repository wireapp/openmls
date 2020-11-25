//! A data structure holding information about the leaf node in the tree that
//! belongs to the current client.

use hpke::HPKEKeyPair;

use super::{index::NodeIndex, path_keys::PathKeys};
use crate::ciphersuite::{Ciphersuite, HPKEPrivateKey, HPKEPublicKey, HpkeCiphertext};
use crate::key_packages::*;
use crate::prelude::Secret;

pub(crate) mod codec;

#[derive(Debug)]
pub(crate) struct CommitSecret {
    secret: Secret,
}

impl CommitSecret {
    /// Convert a `PathSecret`, which should be the result of calling
    /// `to_path_secret_and_key_pair` on the `PathSecret` corresponding to the
    /// root secret, to a `CommitSecret`, which can then be used in the key
    /// schedule.
    fn from_path_secret(root_secret: PathSecret) -> Self {
        CommitSecret {
            secret: root_secret.secret,
        }
    }
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }
}

#[derive(Debug)]
pub(crate) struct LeafSecret {
    secret: Secret,
}

impl LeafSecret {
    /// Randomly sample a fresh `LeafSecret`
    pub(crate) fn random(length: usize) -> Self {
        let secret = Secret::from_random(length);
        LeafSecret { secret }
    }

    /// Derive a `PathSecret` and (via a an intermediate secret) an
    /// `HPKEKeyPair` from a `LeafSecret`, consuming it in the process.
    pub(crate) fn to_key_pair_and_path_secret(
        self,
        ciphersuite: &Ciphersuite,
    ) -> (HPKEKeyPair, PathSecret) {
        let node_secret = self.secret.derive_secret(ciphersuite, "node");
        let hpke_key_pair = ciphersuite.derive_hpke_keypair(&node_secret);
        let path_secret_value = self.secret.derive_secret(ciphersuite, "path");
        let path_secret = PathSecret {
            secret: path_secret_value,
        };
        (hpke_key_pair, path_secret)
    }
}

#[derive(Debug)]
pub(crate) struct PathSecret {
    secret: Secret,
}

impl PathSecret {
    /// Derive a `PathSecret` and (via a an intermediate secret) an
    /// `HPKEKeyPair` from a `PathSecret`, consuming it in the process.
    pub(crate) fn to_path_secret_and_key_pair(
        self,
        ciphersuite: &Ciphersuite,
    ) -> (HPKEKeyPair, PathSecret) {
        let node_secret = self.secret.derive_secret(ciphersuite, "node");
        let hpke_key_pair = ciphersuite.derive_hpke_keypair(&node_secret);
        let path_secret_value = self.secret.derive_secret(ciphersuite, "path");
        let path_secret = PathSecret {
            secret: path_secret_value,
        };
        (hpke_key_pair, path_secret)
    }

    /// Decrypt a `PathSecret`.
    pub(crate) fn decrypt_path_secret(
        ciphersuite: &Ciphersuite,
        hpke_ciphertext: &HpkeCiphertext,
        hpke_private_key: &HPKEPrivateKey,
        group_context: &[u8],
    ) -> Self {
        let secret = Secret::from(ciphersuite.hpke_open(
            hpke_ciphertext,
            &hpke_private_key,
            group_context,
            &[],
        ));
        PathSecret { secret }
    }
}

pub(crate) type PathSecrets = Vec<PathSecret>;
#[derive(Debug)]
pub(crate) struct PrivateTree {
    // The index of the node corresponding to this leaf information.
    node_index: NodeIndex,

    // The `KeyPackageBundle` that corresponds to the `KeyPackage` in the
    // client's leaf of the public key.
    key_package_bundle: KeyPackageBundle,
    // This is the HPKE private key corresponding to the HPKEPublicKey in the
    // node with index `node_index`.
    //hpke_private_key: Option<HPKEPrivateKey>,

    // A vector of HPKEKeyPairs in the path from this leaf.
    path_keys: PathKeys,
}

impl PrivateTree {
    /// Create a new empty placeholder `PrivateTree` with default values and no
    /// `HPKEPrivateKey`
    pub(crate) fn new(node_index: NodeIndex) -> PrivateTree {
        PrivateTree {
            node_index,
            path_keys: PathKeys::default(),
            key_package_bundle: (),
        }
    }
    /// Create a minimal `PrivateTree` setting only the private key.
    /// This function is used to initialize a `PrivateTree` with a
    /// `KeyPackageBundle`. Further secrets like path secrets and keypairs
    /// will only be derived in a further step. The HPKE private key is
    /// derived from the leaf secret contained in the KeyPackageBundle.
    pub(crate) fn from_key_package_bundle(
        node_index: NodeIndex,
        key_package_bundle: KeyPackageBundle,
    ) -> Self {
        Self {
            node_index,
            key_package_bundle,
            path_keys: PathKeys::default(),
        }
    }

    /// Creates a `PrivateTree` with a new private key, leaf secret and path
    /// The private key is derived from the leaf secret contained in the
    /// KeyPackageBundle.
    pub(crate) fn new_with_keys(
        ciphersuite: &Ciphersuite,
        node_index: NodeIndex,
        key_package_bundle: KeyPackageBundle,
        path: &[NodeIndex],
    ) -> (Self, Vec<HPKEPublicKey>, CommitSecret) {
        let mut private_tree = PrivateTree::from_key_package_bundle(node_index, key_package_bundle);

        // Compute path secrets and generate keypairs
        let (public_keys, commit_secret) = private_tree.derive_path_secrets(
            ciphersuite,
            key_package_bundle.consume_leaf_path_secret(),
            path,
        );

        (private_tree, public_keys, commit_secret)
    }

    // === Setter and Getter ===

    pub(crate) fn hpke_private_key(&self) -> &HPKEPrivateKey {
        &self.key_package_bundle.private_key()
    }
    pub(crate) fn get_node_index(&self) -> NodeIndex {
        self.node_index
    }
    pub(crate) fn get_path_keys(&self) -> &PathKeys {
        &self.path_keys
    }

    /// Generate `n` path secrets with the given `leaf_secret`.
    ///
    /// From 5.4. Ratchet Tree Evolution:
    /// ```text
    /// path_secret[0] = DeriveSecret(leaf_secret, "path")
    /// path_secret[n] = DeriveSecret(path_secret[n-1], "path")
    /// ```
    ///
    /// Note that this overrides the `path_secrets`.
    //pub(crate) fn generate_path_secrets(
    //    &mut self,
    //    ciphersuite: &Ciphersuite,
    //    leaf_path_secret: PathSecret,
    //    path: &[NodeIndex],
    //) -> Vec<HPKEPublicKey> {
    //    let path_secrets = if path.is_empty() {
    //        vec![]
    //    } else {
    //        vec![leaf_path_secret]
    //    };

    //    self.derive_path_secrets(ciphersuite, path_secrets, path)
    //}

    /// Generate `n` path secrets with the given `start_secret`.
    ///
    /// From 5.4. Ratchet Tree Evolution:
    /// ```text
    /// path_secret[0] = DeriveSecret(leaf_secret, "path")
    /// path_secret[n] = DeriveSecret(path_secret[n-1], "path")
    /// ```
    ///
    /// Note that this overrides the `path_secrets`.
    //pub(crate) fn continue_path_secrets(
    //    &mut self,
    //    ciphersuite: &Ciphersuite,
    //    start_secret: PathSecret,
    //    path: &[NodeIndex],
    //) -> (Vec<HPKEPublicKey>, CommitSecret) {
    //    let path_secrets: Vec<PathSecret> = vec![start_secret];
    //    self.derive_path_secrets(ciphersuite, path_secrets, path)
    //}

    /// This function generates the path secrets internally and is only called
    /// from either `generate_path_secrets` or `continue_path_secrets`.
    pub(crate) fn derive_path_secrets(
        &mut self,
        ciphersuite: &Ciphersuite,
        start_path_secret: PathSecret,
        path: &[NodeIndex],
    ) -> (Vec<HPKEPublicKey>, CommitSecret) {
        let hash_len = ciphersuite.hash_length();

        let key_pairs = Vec::new();
        let path_secret = start_path_secret;
        for i in 1..path.len() {
            let (key_pair, path_secret) = path_secret.to_path_secret_and_key_pair(ciphersuite);
            key_pairs.push(key_pair);
        }
        // Add the private keys of the key_pairs to the pathkeys.

        let (private_keys, public_keys): (Vec<HPKEPrivateKey>, Vec<HPKEPublicKey>) = key_pairs
            .iter()
            .map(|key_pair| key_pair.into_keys())
            .unzip();

        self.path_keys.add(private_keys, path);

        // Generate the Commit Secret from the last remaining path secret (the
        // root secret).
        let commit_secret = CommitSecret::from_path_secret(path_secret);

        (public_keys, commit_secret)
    }
}
