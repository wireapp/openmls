//! Incoming KeyPackages. This modules contains deserialization and validation
//! of KeyPackages.

use crate::{
    ciphersuite::{signable::*, *},
    credentials::*,
    extensions::Extensions,
    prelude::PublicGroup,
    treesync::{
        node::leaf_node::{LeafNodeIn, VerifiableLeafNode},
        node::validate::ValidatableLeafNode,
    },
    versions::ProtocolVersion,
};
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use tls_codec::{Serialize as TlsSerializeTrait, TlsDeserialize, TlsSerialize, TlsSize};

use super::{
    errors::KeyPackageVerifyError, KeyPackage, KeyPackageTbs, SIGNATURE_KEY_PACKAGE_LABEL,
};

/// Intermediary struct for deserialization of a [`KeyPackageIn`].
struct VerifiableKeyPackage {
    payload: KeyPackageTbs,
    signature: Signature,
}

impl VerifiableKeyPackage {
    fn new(payload: KeyPackageTbs, signature: Signature) -> Self {
        Self { payload, signature }
    }
}

impl Verifiable for VerifiableKeyPackage {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        SIGNATURE_KEY_PACKAGE_LABEL
    }
}

impl VerifiedStruct<VerifiableKeyPackage> for KeyPackage {
    type SealingType = private_mod::Seal;

    fn from_verifiable(verifiable: VerifiableKeyPackage, _seal: Self::SealingType) -> Self {
        Self {
            payload: verifiable.payload,
            signature: verifiable.signature,
        }
    }
}

mod private_mod {
    #[derive(Default)]
    pub struct Seal;
}

/// The unsigned payload of a key package.
///
/// ```text
/// struct {
///     ProtocolVersion version;
///     CipherSuite cipher_suite;
///     HPKEPublicKey init_key;
///     LeafNode leaf_node;
///     Extension extensions<V>;
/// } KeyPackageTBS;
/// ```
#[derive(
    Debug, Clone, PartialEq, TlsSize, TlsSerialize, TlsDeserialize, Serialize, Deserialize,
)]
struct KeyPackageTbsIn {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    init_key: HpkePublicKey,
    leaf_node: LeafNodeIn,
    extensions: Extensions,
}

/// The key package struct.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct KeyPackageIn {
    payload: KeyPackageTbsIn,
    signature: Signature,
}

impl KeyPackageIn {
    /// Returns a [`CredentialWithKey`] from the unverified payload
    pub fn unverified_credential(&self) -> CredentialWithKey {
        let credential = self.payload.leaf_node.credential().clone();
        let signature_key = self.payload.leaf_node.signature_key().clone();
        CredentialWithKey {
            credential,
            signature_key,
        }
    }

    /// Verify that this key package is valid:
    /// * verify that the signature on this key package is valid
    /// * verify that the signature on the leaf node is valid
    /// * verify that all extensions are supported by the leaf node
    /// * make sure that the lifetime is valid
    /// * make sure that the init key and the encryption key are different
    /// * make sure that the protocol version is valid
    ///
    /// Returns a [`KeyPackage`] after having verified the signature or a
    /// [`KeyPackageVerifyError`] otherwise.
    pub async fn validate(
        self,
        backend: &impl OpenMlsCryptoProvider,
        protocol_version: ProtocolVersion,
        group: &PublicGroup,
        sender: bool,
    ) -> Result<KeyPackage, KeyPackageVerifyError> {
        self._validate(backend, protocol_version, Some(group), sender)
            .await
    }

    /// Verify that this key package is valid disregarding the group it is supposed to be used with.
    pub async fn standalone_validate(
        self,
        backend: &impl OpenMlsCryptoProvider,
        protocol_version: ProtocolVersion,
        sender: bool,
    ) -> Result<KeyPackage, KeyPackageVerifyError> {
        self._validate(backend, protocol_version, None, sender)
            .await
    }

    async fn _validate(
        self,
        backend: &impl OpenMlsCryptoProvider,
        protocol_version: ProtocolVersion,
        group: Option<&PublicGroup>,
        sender: bool,
    ) -> Result<KeyPackage, KeyPackageVerifyError> {
        // We first need to verify the LeafNode inside the KeyPackage

        let signature_scheme = self.payload.ciphersuite.signature_algorithm();
        let signature_key = &OpenMlsSignaturePublicKey::from_signature_key(
            self.payload.leaf_node.signature_key().clone(),
            signature_scheme,
        );

        let verifiable_leaf_node = self
            .payload
            .leaf_node
            .clone()
            .try_into_verifiable_leaf_node(None)?;
        let leaf_node = match verifiable_leaf_node {
            VerifiableLeafNode::KeyPackage(leaf_node) => {
                if let Some(group) = group {
                    leaf_node.validate(group, backend, sender).await?
                } else {
                    leaf_node
                        .standalone_validate(backend, signature_scheme, sender)
                        .await?
                }
            }
            _ => return Err(KeyPackageVerifyError::InvalidLeafNodeSourceType),
        };

        // Verify that the protocol version is valid
        if !self.is_version_supported(protocol_version) {
            return Err(KeyPackageVerifyError::InvalidProtocolVersion);
        }

        // Verify that the encryption key and the init key are different
        if leaf_node.encryption_key().key() == &self.payload.init_key {
            return Err(KeyPackageVerifyError::InitKeyEqualsEncryptionKey);
        }

        // Verify the KeyPackage signature
        let key_package = VerifiableKeyPackage::new(self.payload.into(), self.signature)
            .verify::<KeyPackage>(backend.crypto(), signature_key)
            .map_err(|_| KeyPackageVerifyError::InvalidSignature)?;

        // Extension included in the extensions or leaf_node.extensions fields
        // MUST be included in the leaf_node.capabilities field.
        let leaf_node = &key_package.payload.leaf_node;
        for extension in key_package.payload.extensions.iter() {
            if !leaf_node.supports_extension(&extension.extension_type()) {
                return Err(KeyPackageVerifyError::UnsupportedExtension);
            }
        }

        Ok(key_package)
    }

    /// Returns true if the protocol version is supported by this key package and
    /// false otherwise.
    pub(crate) fn is_version_supported(&self, protocol_version: ProtocolVersion) -> bool {
        self.payload.protocol_version == protocol_version
    }

    pub fn credential(&self) -> &Credential {
        self.payload.leaf_node.credential()
    }
}

impl From<KeyPackageTbsIn> for KeyPackageTbs {
    fn from(value: KeyPackageTbsIn) -> Self {
        KeyPackageTbs {
            protocol_version: value.protocol_version,
            ciphersuite: value.ciphersuite,
            init_key: value.init_key,
            leaf_node: value.leaf_node.into(),
            extensions: value.extensions,
        }
    }
}

impl From<KeyPackageTbs> for KeyPackageTbsIn {
    fn from(value: KeyPackageTbs) -> Self {
        Self {
            protocol_version: value.protocol_version,
            ciphersuite: value.ciphersuite,
            init_key: value.init_key,
            leaf_node: value.leaf_node.into(),
            extensions: value.extensions,
        }
    }
}

impl From<KeyPackage> for KeyPackageIn {
    fn from(value: KeyPackage) -> Self {
        Self {
            payload: value.payload.into(),
            signature: value.signature,
        }
    }
}

impl From<KeyPackageIn> for KeyPackage {
    fn from(value: KeyPackageIn) -> Self {
        Self {
            payload: value.payload.into(),
            signature: value.signature,
        }
    }
}
