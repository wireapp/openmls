use crate::{
    prelude::{
        Capabilities, CredentialType, ExtensionType, Extensions, SignaturePublicKey, Verifiable,
    },
    prelude::{Extension, LeafNode, LibraryError, PublicGroup, VerifiedStruct},
    treesync::node::leaf_node::LeafNodeSource,
    treesync::TreeSync,
    treesync::{
        errors::{LeafNodeValidationError, LifetimeError},
        node::leaf_node::{
            VerifiableCommitLeafNode, VerifiableKeyPackageLeafNode, VerifiableUpdateLeafNode,
        },
    },
};
use itertools::Itertools;
use openmls_traits::{crypto::OpenMlsCrypto, types::SignatureScheme};

impl ValidatableLeafNode for VerifiableCommitLeafNode {
    fn signature_key(&self) -> &SignaturePublicKey {
        self.signature_key()
    }

    fn capabilities(&self) -> &Capabilities {
        &self.payload.capabilities
    }

    fn credential_type(&self) -> &CredentialType {
        &self.payload.credential.credential_type
    }

    fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }
}

impl ValidatableLeafNode for VerifiableUpdateLeafNode {
    fn validate(
        self,
        group: &PublicGroup,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<LeafNode, LeafNodeValidationError> {
        self.validate_replaced_encryption_key(group)?;
        self._generic_validate(crypto, group)
    }

    fn signature_key(&self) -> &SignaturePublicKey {
        self.signature_key()
    }

    fn capabilities(&self) -> &Capabilities {
        &self.payload.capabilities
    }

    fn credential_type(&self) -> &CredentialType {
        &self.payload.credential.credential_type
    }

    fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }
}

impl VerifiableUpdateLeafNode {
    /// Verify that encryption_key represents a different public key than the
    /// encryption_key in the leaf node being replaced by the Update proposal.
    fn validate_replaced_encryption_key(
        &self,
        group: &PublicGroup,
    ) -> Result<(), LeafNodeValidationError> {
        let index = self.tree_position.leaf_index;
        let leaf_to_replace = group
            .leaf(index)
            .ok_or(LibraryError::custom("Invalid update proposal"))?;
        if leaf_to_replace.encryption_key() == self.encryption_key() {
            return Err(LeafNodeValidationError::UpdatedEncryptionKeyAlreadyInUse);
        }
        Ok(())
    }
}

impl ValidatableLeafNode for VerifiableKeyPackageLeafNode {
    fn standalone_validate(
        self,
        crypto: &impl OpenMlsCrypto,
        signature_scheme: SignatureScheme,
    ) -> Result<LeafNode, LeafNodeValidationError> {
        self.validate_lifetime()?;
        self._generic_standalone_validate(crypto, signature_scheme)
    }

    fn validate(
        self,
        group: &PublicGroup,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<LeafNode, LeafNodeValidationError> {
        self.validate_lifetime()?;
        self._generic_validate(crypto, group)
    }

    fn signature_key(&self) -> &SignaturePublicKey {
        self.signature_key()
    }

    fn capabilities(&self) -> &Capabilities {
        &self.payload.capabilities
    }

    fn credential_type(&self) -> &CredentialType {
        &self.payload.credential.credential_type
    }

    fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }
}

impl VerifiableKeyPackageLeafNode {
    fn validate_lifetime(&self) -> Result<(), LeafNodeValidationError> {
        println!("> Validate KeyPackage Lifetime");
        let LeafNodeSource::KeyPackage(lifetime) = self.payload.leaf_node_source else {
            return Err(LeafNodeValidationError::InvalidLeafNodeSource);
        };
        if !lifetime.is_valid() {
            return Err(LeafNodeValidationError::Lifetime(LifetimeError::NotCurrent));
        }
        Ok(())
    }
}

pub(crate) trait ValidatableLeafNode: Verifiable + Sized
where
    LeafNode: VerifiedStruct<Self>,
{
    fn standalone_validate(
        self,
        crypto: &impl OpenMlsCrypto,
        signature_scheme: SignatureScheme,
    ) -> Result<LeafNode, LeafNodeValidationError> {
        self._generic_standalone_validate(crypto, signature_scheme)
    }

    /// Should never be called directly, always through [standalone_validate]
    fn _generic_standalone_validate(
        self,
        crypto: &impl OpenMlsCrypto,
        signature_scheme: SignatureScheme,
    ) -> Result<LeafNode, LeafNodeValidationError> {
        let extension_types = self.extension_types();
        let leaf_node = self.verify_signature(crypto, signature_scheme)?;
        Self::validate_extension_support(&leaf_node, &extension_types[..])?;
        Ok(leaf_node)
    }

    /// Validate a LeafNode as per https://www.rfc-editor.org/rfc/rfc9420.html#name-leaf-node-validation
    fn validate(
        self,
        group: &PublicGroup,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<LeafNode, LeafNodeValidationError> {
        self._generic_validate(crypto, group)
    }

    /// Validation regardless of [LeafNode]'s source
    /// Should never be called directly, always through [validate]
    fn _generic_validate(
        self,
        crypto: &impl OpenMlsCrypto,
        group: &PublicGroup,
    ) -> Result<LeafNode, LeafNodeValidationError> {
        self.validate_capabilities(group)?;
        self.validate_credential_type(group)?;
        let tree = group.treesync();
        self.validate_signature_key_unique(tree)?;
        self.validate_encryption_key_unique(tree)?;

        let extension_types = self.extension_types();
        let signature_scheme = group.ciphersuite().signature_algorithm();
        let leaf_node = self.verify_signature(crypto, signature_scheme)?;
        Self::validate_extension_support(&leaf_node, &extension_types[..])?;
        Ok(leaf_node)
    }

    fn signature_key(&self) -> &SignaturePublicKey;
    fn capabilities(&self) -> &Capabilities;
    fn credential_type(&self) -> &CredentialType;
    fn extensions(&self) -> &Extensions;

    fn extension_types(&self) -> Vec<ExtensionType> {
        self.extensions()
            .iter()
            .map(Extension::extension_type)
            .collect::<Vec<ExtensionType>>()
    }

    /// Verify that the LeafNode is compatible with the group's parameters.
    /// If the GroupContext has a required_capabilities extension, then the
    /// required extensions, proposals, and credential types MUST be listed
    /// in the LeafNode's capabilities field.
    fn validate_capabilities(&self, group: &PublicGroup) -> Result<(), LeafNodeValidationError> {
        if let Some(group_required_capabilities) = group.required_capabilities() {
            self.capabilities()
                .supports_required_capabilities(group_required_capabilities)?;
        }
        Ok(())
    }

    /// (1) Verify that the credential type is supported by all members of the
    /// group, as specified by the capabilities field of each member's LeafNode
    /// (2) and that the capabilities field of this LeafNode indicates support
    /// for all the credential types currently in use by other members.
    fn validate_credential_type(&self, group: &PublicGroup) -> Result<(), LeafNodeValidationError> {
        for leaf_node in group.treesync().raw_leaves() {
            // (1)
            let own_ct = self.credential_type();
            if !leaf_node.capabilities().contains_credential(own_ct) {
                return Err(LeafNodeValidationError::LeafNodeCredentialNotSupportedByMember);
            }

            // (2)
            let leaf_node_ct = leaf_node.credential().credential_type();
            if !self.capabilities().contains_credential(&leaf_node_ct) {
                return Err(LeafNodeValidationError::MemberCredentialNotSupportedByLeafNode);
            }
        }
        Ok(())
    }

    /// Verify that the following fields are unique among the members of the
    /// group: signature_key
    fn validate_signature_key_unique(
        &self,
        tree: &TreeSync,
    ) -> Result<(), LeafNodeValidationError> {
        if !tree.raw_leaves().map(LeafNode::signature_key).all_unique() {
            return Err(LeafNodeValidationError::SignatureKeyAlreadyInUse);
        }
        Ok(())
    }
    /// Verify that the following fields are unique among the members of the
    /// group: encryption_key
    fn validate_encryption_key_unique(
        &self,
        tree: &TreeSync,
    ) -> Result<(), LeafNodeValidationError> {
        if !tree.raw_leaves().map(LeafNode::encryption_key).all_unique() {
            return Err(LeafNodeValidationError::EncryptionKeyAlreadyInUse);
        }

        Ok(())
    }

    /// Verify that the extensions in the LeafNode are supported by checking
    /// that the ID for each extension in the extensions field is listed in
    /// the capabilities.extensions field of the LeafNode.
    fn validate_extension_support(
        leaf_node: &LeafNode,
        extensions: &[ExtensionType],
    ) -> Result<(), LeafNodeValidationError> {
        leaf_node.check_extension_support(extensions)
    }

    /// Verify that the signature on the LeafNode is valid using signature_key.
    fn verify_signature(
        self,
        crypto: &impl OpenMlsCrypto,
        signature_scheme: SignatureScheme,
    ) -> Result<LeafNode, LeafNodeValidationError> {
        let pk = self
            .signature_key()
            .clone()
            .into_signature_public_key_enriched(signature_scheme);
        Ok(self.verify::<LeafNode>(crypto, &pk)?)
    }
}
