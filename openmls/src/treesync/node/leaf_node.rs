//! This module contains the [`LeafNode`] struct and its implementation.
use openmls_traits::{signatures::Signer, types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use tls_codec::{Serialize as TlsSerializeTrait, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

#[cfg(test)]
use openmls_traits::key_store::OpenMlsKeyStore;
#[cfg(test)]
use thiserror::Error;

use super::encryption_keys::{EncryptionKey, EncryptionKeyPair};
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        Signature, SignaturePublicKey,
    },
    credentials::{Credential, CredentialWithKey},
    error::LibraryError,
    extensions::{ExtensionType, Extensions},
    group::{config::CryptoConfig, GroupId},
    key_packages::{KeyPackage, Lifetime},
    treesync::errors::PublicTreeError,
    versions::ProtocolVersion,
};

use crate::treesync::errors::LeafNodeValidationError;

mod capabilities;
mod codec;

use crate::group::PublicGroup;
use crate::treesync::node::validate::ValidatableLeafNode;
pub use capabilities::*;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::SignatureScheme;

/// Private module to ensure protection.
mod private_mod {
    #[derive(Default)]
    pub(crate) struct Seal;
}

pub(crate) struct NewLeafNodeParams {
    pub(crate) config: CryptoConfig,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) leaf_node_source: LeafNodeSource,
    pub(crate) capabilities: Capabilities,
    pub(crate) extensions: Extensions,
    pub(crate) tree_info_tbs: TreeInfoTbs,
}

/// This struct implements the MLS leaf node.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     HPKEPublicKey encryption_key;
///     SignaturePublicKey signature_key;
///     Credential credential;
///     Capabilities capabilities;
///
///     LeafNodeSource leaf_node_source;
///     select (LeafNode.leaf_node_source) {
///         case key_package:
///             Lifetime lifetime;
///
///         case update:
///             struct{};
///
///         case commit:
///             opaque parent_hash<V>;
///     };
///
///     Extension extensions<V>;
///     /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
///     opaque signature<V>;
/// } LeafNode;
/// ```
// TODO(#1242): Do not derive `TlsDeserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct LeafNode {
    payload: LeafNodePayload,
    signature: Signature,
}

impl LeafNode {
    /// Create a new [`LeafNode`].
    /// This first creates a `LeadNodeTbs` and returns the result of signing
    /// it.
    ///
    /// This function generates a fresh HPKE key pair for the leaf node and
    /// returns the HPKE key pair along with the new leaf node.
    /// The caller is responsible for storing the private key.
    pub(crate) fn new(
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        new_leaf_node_params: NewLeafNodeParams,
    ) -> Result<(Self, EncryptionKeyPair), LibraryError> {
        let NewLeafNodeParams {
            config,
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            tree_info_tbs,
        } = new_leaf_node_params;

        // Create a new encryption key pair.
        let encryption_key_pair = EncryptionKeyPair::random(backend, config)?;

        let leaf_node = Self::new_with_key(
            encryption_key_pair.public_key().clone(),
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            tree_info_tbs,
            signer,
        )?;

        Ok((leaf_node, encryption_key_pair))
    }

    /// Create a new leaf node with a given HPKE encryption key pair.
    /// The key pair must be stored in the key store by the caller.
    fn new_with_key(
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions,
        tree_info_tbs: TreeInfoTbs,
        signer: &impl Signer,
    ) -> Result<Self, LibraryError> {
        let leaf_node_tbs = LeafNodeTbs::new(
            encryption_key,
            credential_with_key,
            capabilities,
            leaf_node_source,
            extensions,
            tree_info_tbs,
        )?;

        leaf_node_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))
    }

    /// Update the parent hash of this [`LeafNode`].
    ///
    /// This re-signs the leaf node.
    pub(in crate::treesync) fn update_parent_hash(
        &mut self,
        parent_hash: &[u8],
        group_id: GroupId,
        leaf_index: LeafNodeIndex,
        signer: &impl Signer,
    ) -> Result<(), LibraryError> {
        self.payload.leaf_node_source = LeafNodeSource::Commit(parent_hash.into());
        let tbs = LeafNodeTbs::from(
            self.clone(), // TODO: With a better setup we wouldn't have to clone here.
            TreeInfoTbs::Commit(TreePosition {
                group_id,
                leaf_index,
            }),
        );
        let leaf_node = tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))?;
        self.payload = leaf_node.payload;
        self.signature = leaf_node.signature;

        Ok(())
    }

    /// Generate a fresh leaf node with a fresh encryption key but otherwise
    /// the same properties as the current leaf node.
    ///
    /// The newly generated encryption key pair is stored in the key store.
    ///
    /// This function can be used when generating an update. In most other cases
    /// a leaf node should be generated as part of a new [`KeyPackage`].
    #[cfg(test)]
    pub(crate) async fn updated<KeyStore: OpenMlsKeyStore>(
        &self,
        config: CryptoConfig,
        tree_info_tbs: TreeInfoTbs,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<Self, LeafNodeGenerationError<KeyStore::Error>> {
        Self::generate_update(
            config,
            CredentialWithKey {
                credential: self.payload.credential.clone(),
                signature_key: self.payload.signature_key.clone(),
            },
            self.payload.capabilities.clone(),
            self.payload.extensions.clone(),
            tree_info_tbs,
            backend,
            signer,
        )
        .await
    }

    /// Generate a fresh leaf node.
    ///
    /// This includes generating a new encryption key pair that is stored in the
    /// key store.
    ///
    /// This function can be used when generating an update. In most other cases
    /// a leaf node should be generated as part of a new [`KeyPackage`].
    #[cfg(test)]
    pub(crate) async fn generate_update<KeyStore: OpenMlsKeyStore>(
        config: CryptoConfig,
        credential_with_key: CredentialWithKey,
        capabilities: Capabilities,
        extensions: Extensions,
        tree_info_tbs: TreeInfoTbs,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<Self, LeafNodeGenerationError<KeyStore::Error>> {
        // Note that this function is supposed to be used in the public API only
        // because it is interacting with the key store.

        let new_leaf_node_params = NewLeafNodeParams {
            config,
            credential_with_key,
            leaf_node_source: LeafNodeSource::Update,
            capabilities,
            extensions,
            tree_info_tbs,
        };

        let (leaf_node, encryption_key_pair) = Self::new(backend, signer, new_leaf_node_params)?;

        // Store the encryption key pair in the key store.
        encryption_key_pair
            .write_to_key_store(backend)
            .await
            .map_err(LeafNodeGenerationError::KeyStoreError)?;

        Ok(leaf_node)
    }

    /// Update the `encryption_key` in this leaf node and re-signs it.
    ///
    /// Optionally, a new leaf node can be provided to update more values such
    /// as the credential.
    pub(crate) fn update_and_re_sign(
        &mut self,
        new_encryption_key: Option<EncryptionKey>,
        leaf_node: Option<LeafNode>,
        group_id: GroupId,
        leaf_index: LeafNodeIndex,
        signer: &impl Signer,
    ) -> Result<(), PublicTreeError> {
        let tree_info = TreeInfoTbs::Update(TreePosition::new(group_id, leaf_index));
        // TODO: If we could take out the leaf_node without cloning, this would all be
        // nicer.
        let mut leaf_node_tbs = LeafNodeTbs::from(self.clone(), tree_info);

        // Update credential
        leaf_node_tbs.payload.leaf_node_source = LeafNodeSource::Update;
        if let Some(leaf_node) = leaf_node {
            leaf_node_tbs.payload.credential = leaf_node.credential().clone();
            leaf_node_tbs.payload.signature_key = leaf_node.signature_key().clone();
            leaf_node_tbs.payload.encryption_key = leaf_node.encryption_key().clone();

            // The application MAY specify other changes to the leaf node, e.g. [..] updated
            // capabilities, or different extensions cf https://www.rfc-editor.org/rfc/rfc9420.html#section-7.5-7
            leaf_node_tbs.payload.capabilities = leaf_node.capabilities().clone();
            leaf_node_tbs.payload.extensions = leaf_node.extensions().clone();
        } else if let Some(new_encryption_key) = new_encryption_key {
            leaf_node_tbs.payload.encryption_key = new_encryption_key;
        } else {
            return Err(LibraryError::custom(
                "Has to be called with either a new leaf node or a new encryption key",
            )
            .into());
        }

        // Set the new signed leaf node with the new encryption key
        let leaf_node = leaf_node_tbs.sign(signer)?;
        self.payload = leaf_node.payload;
        self.signature = leaf_node.signature;

        Ok(())
    }

    /// Replace the encryption key in this leaf with a random one.
    ///
    /// This signs the new leaf node as well.
    #[allow(clippy::too_many_arguments)]
    pub fn rekey(
        &mut self,
        group_id: &GroupId,
        leaf_index: LeafNodeIndex,
        leaf_node: Option<LeafNode>,
        ciphersuite: Ciphersuite,
        protocol_version: ProtocolVersion,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
    ) -> Result<EncryptionKeyPair, PublicTreeError> {
        let ciphersuite_capable = self
            .payload
            .capabilities
            .ciphersuites
            .contains(&ciphersuite.into());
        let version_capable = self.capabilities().versions.contains(&protocol_version);

        if !ciphersuite_capable || !version_capable {
            debug_assert!(
                false,
                "Ciphersuite or protocol version is not supported by this leaf node.\
                 \ncapabilities: {:?}\nprotocol version: {:?}\nciphersuite: {:?}",
                self.payload.capabilities, protocol_version, ciphersuite
            );
            return Err(LibraryError::custom(
                "Ciphersuite or protocol version is not supported by this leaf node.",
            )
            .into());
        }
        let keypair = EncryptionKeyPair::random(
            backend,
            CryptoConfig {
                ciphersuite,
                version: protocol_version,
            },
        )?;

        if let Some(mut leaf_node) = leaf_node {
            leaf_node.payload.encryption_key = keypair.public_key().clone();
            self.update_and_re_sign(None, Some(leaf_node), group_id.clone(), leaf_index, signer)?;
        } else {
            self.update_and_re_sign(
                Some(keypair.public_key().clone()),
                None,
                group_id.clone(),
                leaf_index,
                signer,
            )?;
        }

        Ok(keypair)
    }

    /// Returns the `encryption_key`.
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.payload.encryption_key
    }

    /// Returns the `signature_key` as byte slice.
    pub fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }

    /// Returns the `signature_key` as byte slice.
    pub fn credential(&self) -> &Credential {
        &self.payload.credential
    }

    /// Returns the `parent_hash` as byte slice or `None`.
    pub fn parent_hash(&self) -> Option<&[u8]> {
        match &self.payload.leaf_node_source {
            LeafNodeSource::Commit(ph) => Some(ph.as_slice()),
            _ => None,
        }
    }

    /// Returns the [`Lifetime`] if present.
    /// `None` otherwise.
    pub fn life_time(&self) -> Option<&Lifetime> {
        if let LeafNodeSource::KeyPackage(life_time) = &self.payload.leaf_node_source {
            Some(life_time)
        } else {
            None
        }
    }

    /// Returns a reference to the [`Signature`] of this leaf.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Return a reference to [`Capabilities`].
    pub fn capabilities(&self) -> &Capabilities {
        &self.payload.capabilities
    }

    /// Return a reference to the leaf node extensions.
    pub fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }

    /// Returns `true` if the [`ExtensionType`] is supported by this leaf node.
    pub(crate) fn supports_extension(&self, extension_type: &ExtensionType) -> bool {
        extension_type.is_spec_default()
            || self
                .payload
                .capabilities
                .extensions
                .contains(extension_type)
            || default_extensions().iter().any(|et| et == extension_type)
    }

    /// Check whether this leaf node supports all the required extensions
    /// in the provided list.
    pub(crate) fn check_extension_support(
        &self,
        extensions: &[ExtensionType],
    ) -> Result<(), LeafNodeValidationError> {
        for required in extensions.iter() {
            if !self.supports_extension(required) {
                return Err(LeafNodeValidationError::UnsupportedExtensions);
            }
        }
        Ok(())
    }

    /// Checks if leaf node supports the given ciphersuite.
    pub(crate) fn supports_ciphersuite(&self, ciphersuite: Ciphersuite) -> bool {
        self.payload
            .capabilities
            .ciphersuites()
            .contains(&ciphersuite.into())
    }

    /// Replace the credential material in the LeafNode.
    pub fn set_credential_with_key(&mut self, credential_with_key: CredentialWithKey) {
        self.payload.credential = credential_with_key.credential;
        self.payload.signature_key = credential_with_key.signature_key;
    }
}

#[cfg(test)]
impl LeafNode {
    /// Expose [`new_with_key`] for tests.
    pub(crate) fn create_new_with_key(
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions,
        tree_info_tbs: TreeInfoTbs,
        signer: &impl Signer,
    ) -> Result<Self, LibraryError> {
        Self::new_with_key(
            encryption_key,
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            tree_info_tbs,
            signer,
        )
    }

    /// Return a mutable reference to [`Capabilities`].
    pub fn capabilities_mut(&mut self) -> &mut Capabilities {
        &mut self.payload.capabilities
    }
}

#[cfg(any(feature = "test-utils", test))]
impl LeafNode {
    /// Replace the credential in the KeyPackage.
    pub(crate) fn set_credential(&mut self, credential: Credential) {
        self.payload.credential = credential;
    }

    /// Replace the signature key in the KeyPackage.
    pub(crate) fn set_signature_key(&mut self, signature_key: SignaturePublicKey) {
        self.payload.signature_key = signature_key;
    }

    /// Resign the node
    pub(crate) fn resign(
        &mut self,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        tree_info_tbs: TreeInfoTbs,
    ) {
        let leaf_node_tbs = LeafNodeTbs::new(
            self.payload.encryption_key.clone(),
            credential_with_key,
            self.payload.capabilities.clone(),
            self.payload.leaf_node_source.clone(),
            self.payload.extensions.clone(),
            tree_info_tbs,
        )
        .unwrap();

        let leaf_node = leaf_node_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))
            .unwrap();
        self.payload = leaf_node.payload;
        self.signature = leaf_node.signature;
    }

    /// Re-signs a leaf node with a specific tree position.
    #[cfg(test)]
    pub(crate) fn resign_with_position(
        &mut self,
        leaf_index: LeafNodeIndex,
        group_id: GroupId,
        signer: &impl Signer,
    ) {
        let tree_info_tbs = TreeInfoTbs::commit(group_id, leaf_index);
        let leaf_node_tbs = LeafNodeTbs::from(self.clone(), tree_info_tbs);
        let leaf_node = leaf_node_tbs.sign(signer).unwrap();
        self.payload = leaf_node.payload;
        self.signature = leaf_node.signature;
    }
}

/// The payload of a [`LeafNode`]
///
/// ```text
/// struct {
///     HPKEPublicKey encryption_key;
///     SignaturePublicKey signature_key;
///     Credential credential;
///     Capabilities capabilities;
///
///     LeafNodeSource leaf_node_source;
///     select (LeafNode.leaf_node_source) {
///         case key_package:
///             Lifetime lifetime;
///
///         case update:
///             struct{};
///
///         case commit:
///             opaque parent_hash<V>;
///     };
///
///     Extension extensions<V>;
///     ...
/// } LeafNode;
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub(crate) struct LeafNodePayload {
    pub(crate) encryption_key: EncryptionKey,
    pub(crate) signature_key: SignaturePublicKey,
    pub(crate) credential: Credential,
    pub(crate) capabilities: Capabilities,
    pub(crate) leaf_node_source: LeafNodeSource,
    pub(crate) extensions: Extensions,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
pub enum LeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(Lifetime),
    Update,
    Commit(ParentHash),
}

pub type ParentHash = VLBytes;

/// To-be-signed leaf node.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     HPKEPublicKey encryption_key;
///     SignaturePublicKey signature_key;
///     Credential credential;
///     Capabilities capabilities;
///
///     LeafNodeSource leaf_node_source;
///     select (LeafNodeTBS.leaf_node_source) {
///         case key_package:
///             Lifetime lifetime;
///
///         case update:
///             struct{};
///
///         case commit:
///             opaque parent_hash<V>;
///     };
///
///     Extension extensions<V>;
///
///     // ... continued in [`TreeInfo`] ...
/// } LeafNodeTBS;
/// ```
#[derive(Debug, TlsSerialize, TlsSize)]
pub struct LeafNodeTbs {
    payload: LeafNodePayload,
    tree_info_tbs: TreeInfoTbs,
}

impl LeafNodeTbs {
    /// Build a [`LeafNodeTbs`] from a [`LeafNode`] and a [`TreeInfoTbs`]
    /// to update a leaf node.
    pub(crate) fn from(leaf_node: LeafNode, tree_info_tbs: TreeInfoTbs) -> Self {
        Self {
            payload: leaf_node.payload,
            tree_info_tbs,
        }
    }

    /// Build a new [`LeafNodeTbs`] from a [`KeyPackage`] and [`Credential`].
    /// To get the [`LeafNode`] call [`LeafNode::sign`].
    pub(crate) fn new(
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        capabilities: Capabilities,
        leaf_node_source: LeafNodeSource,
        extensions: Extensions,
        tree_info_tbs: TreeInfoTbs,
    ) -> Result<Self, LibraryError> {
        let payload = LeafNodePayload {
            encryption_key,
            signature_key: credential_with_key.signature_key,
            credential: credential_with_key.credential,
            capabilities,
            leaf_node_source,
            extensions,
        };
        let tbs = LeafNodeTbs {
            payload,
            tree_info_tbs,
        };
        Ok(tbs)
    }
}

/// Helper struct that holds additional information required to sign a leaf
/// node.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     // ... continued from [`LeafNodeTbs`] ...
///
///     select (LeafNodeTBS.leaf_node_source) {
///         case key_package:
///             struct{};
///
///         case update:
///             opaque group_id<V>;
///             uint32 leaf_index;
///
///         case commit:
///             opaque group_id<V>;
///             uint32 leaf_index;
///     };
/// } LeafNodeTBS;
/// ```
#[derive(Debug)]
pub(crate) enum TreeInfoTbs {
    KeyPackage,
    Update(TreePosition),
    Commit(TreePosition),
}

impl TreeInfoTbs {
    #[cfg(test)]
    pub(crate) fn commit(group_id: GroupId, leaf_index: LeafNodeIndex) -> Self {
        Self::Commit(TreePosition {
            group_id,
            leaf_index,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsSize)]
pub(crate) struct TreePosition {
    group_id: GroupId,
    pub(crate) leaf_index: LeafNodeIndex,
}

impl TreePosition {
    pub(crate) fn new(group_id: GroupId, leaf_index: LeafNodeIndex) -> Self {
        Self {
            group_id,
            leaf_index,
        }
    }
}

const LEAF_NODE_SIGNATURE_LABEL: &str = "LeafNodeTBS";

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct LeafNodeIn {
    payload: LeafNodePayload,
    signature: Signature,
}

impl LeafNodeIn {
    pub(crate) fn try_into_verifiable_leaf_node(
        self,
        tree_position: Option<TreePosition>,
    ) -> Result<VerifiableLeafNode, LeafNodeValidationError> {
        Ok(match self.payload.leaf_node_source {
            LeafNodeSource::KeyPackage(_) => {
                VerifiableLeafNode::KeyPackage(VerifiableKeyPackageLeafNode {
                    payload: self.payload,
                    signature: self.signature,
                })
            }
            LeafNodeSource::Update => {
                let tree_position = tree_position
                    .ok_or(LibraryError::custom("No tree position for Update LeafNode"))?;
                VerifiableLeafNode::Update(VerifiableUpdateLeafNode {
                    payload: self.payload,
                    signature: self.signature,
                    tree_position,
                })
            }
            LeafNodeSource::Commit(_) => {
                let tree_position = tree_position
                    .ok_or(LibraryError::custom("No tree position for Commit LeafNode"))?;
                VerifiableLeafNode::Commit(VerifiableCommitLeafNode {
                    payload: self.payload,
                    signature: self.signature,
                    tree_position,
                })
            }
        })
    }

    /// Returns the `signature_key` as byte slice.
    pub fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }

    /// Returns the `signature_key` as byte slice.
    pub fn credential(&self) -> &Credential {
        &self.payload.credential
    }
}

impl From<LeafNode> for LeafNodeIn {
    fn from(leaf_node: LeafNode) -> Self {
        Self {
            payload: leaf_node.payload,
            signature: leaf_node.signature,
        }
    }
}

impl From<LeafNodeIn> for LeafNode {
    fn from(deserialized: LeafNodeIn) -> Self {
        Self {
            payload: deserialized.payload,
            signature: deserialized.signature,
        }
    }
}

impl From<KeyPackage> for LeafNode {
    fn from(key_package: KeyPackage) -> Self {
        key_package.leaf_node().clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifiableLeafNode {
    KeyPackage(VerifiableKeyPackageLeafNode),
    Update(VerifiableUpdateLeafNode),
    Commit(VerifiableCommitLeafNode),
}

impl VerifiableLeafNode {
    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        match self {
            VerifiableLeafNode::KeyPackage(v) => v.signature_key(),
            VerifiableLeafNode::Update(v) => v.signature_key(),
            VerifiableLeafNode::Commit(v) => v.signature_key(),
        }
    }

    pub(crate) fn validate(
        self,
        crypto: &impl OpenMlsCrypto,
        sc: SignatureScheme,
        group: Option<&PublicGroup>,
    ) -> Result<LeafNode, LeafNodeValidationError> {
        let r = match (self, group) {
            (VerifiableLeafNode::KeyPackage(ln), None) => {
                println!(
                    "> validate kp leafnode: {}",
                    hex::encode(ln.payload.credential.identity())
                );
                ln.standalone_validate(crypto, sc)
            }
            (VerifiableLeafNode::KeyPackage(ln), Some(group)) => ln.validate(group, crypto),
            (VerifiableLeafNode::Update(ln), None) => {
                println!(
                    "> validate update leafnode: {} - {}",
                    ln.tree_position.leaf_index,
                    hex::encode(ln.payload.credential.identity())
                );
                ln.standalone_validate(crypto, sc)
            }
            (VerifiableLeafNode::Update(ln), Some(group)) => ln.validate(group, crypto),
            (VerifiableLeafNode::Commit(ln), None) => {
                println!(
                    "> validate commit leafnode: {} - {}",
                    ln.tree_position.leaf_index,
                    hex::encode(ln.payload.credential.identity())
                );
                ln.standalone_validate(crypto, sc)
            }
            (VerifiableLeafNode::Commit(ln), Some(group)) => ln.validate(group, crypto),
        };
        println!("/ {:?}", r);
        r
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiableKeyPackageLeafNode {
    pub(crate) payload: LeafNodePayload,
    signature: Signature,
}

impl VerifiableKeyPackageLeafNode {
    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }
}

impl Verifiable for VerifiableKeyPackageLeafNode {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }
}

impl VerifiedStruct<VerifiableKeyPackageLeafNode> for LeafNode {
    fn from_verifiable(verifiable: VerifiableKeyPackageLeafNode, _seal: Self::SealingType) -> Self {
        Self {
            payload: verifiable.payload,
            signature: verifiable.signature,
        }
    }

    type SealingType = private_mod::Seal;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiableUpdateLeafNode {
    pub(crate) payload: LeafNodePayload,
    signature: Signature,
    pub(crate) tree_position: TreePosition,
}

impl VerifiableUpdateLeafNode {
    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }

    pub(crate) fn encryption_key(&self) -> &EncryptionKey {
        &self.payload.encryption_key
    }
}

impl Verifiable for VerifiableUpdateLeafNode {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        LeafNodeTbs {
            payload: self.payload.clone(),
            tree_info_tbs: TreeInfoTbs::Commit(self.tree_position.clone()),
        }
        .tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }
}

impl VerifiedStruct<VerifiableUpdateLeafNode> for LeafNode {
    fn from_verifiable(verifiable: VerifiableUpdateLeafNode, _seal: Self::SealingType) -> Self {
        Self {
            payload: verifiable.payload,
            signature: verifiable.signature,
        }
    }

    type SealingType = private_mod::Seal;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiableCommitLeafNode {
    pub(crate) payload: LeafNodePayload,
    signature: Signature,
    tree_position: TreePosition,
}

impl VerifiableCommitLeafNode {
    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }
}

impl Verifiable for VerifiableCommitLeafNode {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        LeafNodeTbs {
            payload: self.payload.clone(),
            tree_info_tbs: TreeInfoTbs::Commit(self.tree_position.clone()),
        }
        .tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }
}

impl VerifiedStruct<VerifiableCommitLeafNode> for LeafNode {
    fn from_verifiable(verifiable: VerifiableCommitLeafNode, _seal: Self::SealingType) -> Self {
        Self {
            payload: verifiable.payload,
            signature: verifiable.signature,
        }
    }

    type SealingType = private_mod::Seal;
}

impl Signable for LeafNodeTbs {
    type SignedOutput = LeafNode;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }
}

impl SignedStruct<LeafNodeTbs> for LeafNode {
    fn from_payload(tbs: LeafNodeTbs, signature: Signature) -> Self {
        Self {
            payload: tbs.payload,
            signature,
        }
    }
}

#[cfg(test)]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeafNodeGenerationError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Error storing leaf private key in key store.
    #[error("Error storing leaf private key in key store.")]
    KeyStoreError(KeyStoreError),
}
