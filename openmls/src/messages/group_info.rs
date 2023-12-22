//! This module contains all types related to group info handling.

use thiserror::Error;
use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize};

use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        AeadKey, AeadNonce, Signature,
    },
    extensions::{Extension, Extensions},
    group::{group_context::GroupContext, GroupId},
    messages::ConfirmationTag,
    treesync::{RatchetTree, TreeSync},
};

const SIGNATURE_GROUP_INFO_LABEL: &str = "GroupInfoTBS";

/// A type that represents a group info of which the signature has not been
/// verified. It implements the [`Verifiable`] trait and can be turned into a
/// group info by calling `verify(...)` with the signature key of the
/// [`Credential`](crate::credentials::Credential). When receiving a serialized
/// group info, it can only be deserialized into a [`VerifiableGroupInfo`],
/// which can then be turned into a group info as described above.
#[derive(Debug, PartialEq, Clone, TlsDeserialize, TlsSize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(TlsSerialize))]
pub struct VerifiableGroupInfo {
    payload: GroupInfoTBS,
    signature: Signature,
}

/// Error related to group info.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum GroupInfoError {
    /// Decryption failed.
    #[error("Decryption failed.")]
    DecryptionFailed,
    /// Malformed.
    #[error("Malformed.")]
    Malformed,
    /// The required RatchetTreeExtension is missing
    #[error("The required RatchetTreeExtension is missing")]
    MissingRatchetTreeExtension,
    /// Invalid
    #[error("Invalid")]
    Invalid,
    /// Ratchet Tree error
    #[error(transparent)]
    RatchetTreeError(#[from] crate::treesync::RatchetTreeError),
    /// TreeSyncFromNodesError
    #[error(transparent)]
    TreeSyncFromNodesError(#[from] crate::treesync::errors::TreeSyncFromNodesError),
    /// A RatchetTree extension is required for this operation
    #[error("A RatchetTree extension is required for this operation")]
    RequiredRatchetTree,
}

impl VerifiableGroupInfo {
    pub(crate) fn try_from_ciphertext(
        skey: &AeadKey,
        nonce: &AeadNonce,
        ciphertext: &[u8],
        context: &[u8],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, GroupInfoError> {
        let verifiable_group_info_plaintext = skey
            .aead_open(backend, ciphertext, context, nonce)
            .map_err(|_| GroupInfoError::DecryptionFailed)?;

        let mut verifiable_group_info_plaintext_slice = verifiable_group_info_plaintext.as_slice();

        let verifiable_group_info =
            VerifiableGroupInfo::tls_deserialize(&mut verifiable_group_info_plaintext_slice)
                .map_err(|_| GroupInfoError::Malformed)?;

        if !verifiable_group_info_plaintext_slice.is_empty() {
            return Err(GroupInfoError::Malformed);
        }

        Ok(verifiable_group_info)
    }

    /// Get (unverified) ciphersuite of the verifiable group info.
    ///
    /// Note: This method should only be used when necessary to verify the group
    /// info signature.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.payload.group_context.ciphersuite()
    }

    /// Get (unverified) signer of the verifiable group info.
    ///
    /// Note: This method should only be used when necessary to verify the group
    /// info signature.
    pub(crate) fn signer(&self) -> LeafNodeIndex {
        self.payload.signer
    }

    /// Get (unverified) extensions of the verifiable group info.
    ///
    /// Note: This method should only be used when necessary to verify the group
    /// info signature.
    pub(crate) fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }

    /// Get (unverified) group ID of the verifiable group info.
    ///
    /// Note: This method should only be used when necessary to verify the group
    /// info signature.
    pub fn group_id(&self) -> &GroupId {
        self.payload.group_context.group_id()
    }

    pub(crate) fn context(&self) -> &GroupContext {
        &self.payload.group_context
    }

    /// Do whatever it takes not to clone the RatchetTree
    pub async fn take_ratchet_tree(
        mut self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<RatchetTree, GroupInfoError> {
        let cs = self.ciphersuite();

        let ratchet_tree = self
            .payload
            .extensions
            .unique
            .iter_mut()
            .find_map(|e| match e {
                Extension::RatchetTree(rt) => {
                    // we have to clone it here as well..
                    Some(rt.ratchet_tree.clone())
                }
                _ => None,
            })
            .ok_or(GroupInfoError::MissingRatchetTreeExtension)?
            .into_verified(cs, backend.crypto(), self.group_id())?;

        // although it clones the ratchet tree here...
        let group_id = self.group_id();
        let treesync =
            TreeSync::from_ratchet_tree(backend, cs, ratchet_tree.clone(), group_id, true).await?;

        let signer_signature_key = treesync
            .leaf(self.signer())
            .ok_or(GroupInfoError::Invalid)?
            .signature_key()
            .clone()
            .into_signature_public_key_enriched(cs.signature_algorithm());

        self.verify::<GroupInfo>(backend.crypto(), &signer_signature_key)
            .map_err(|_| GroupInfoError::Invalid)?;

        Ok(ratchet_tree)
    }
}

#[cfg(test)]
impl VerifiableGroupInfo {
    pub(crate) fn payload_mut(&mut self) -> &mut GroupInfoTBS {
        &mut self.payload
    }

    /// Break the signature for testing purposes.
    pub(crate) fn break_signature(&mut self) {
        self.signature.modify(b"");
    }
}

impl From<VerifiableGroupInfo> for GroupInfo {
    fn from(vgi: VerifiableGroupInfo) -> Self {
        GroupInfo {
            payload: vgi.payload,
            signature: vgi.signature,
        }
    }
}

/// GroupInfo
///
/// Note: The struct is split into a `GroupInfoTBS` payload and a signature.
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     GroupContext group_context;
///     Extension extensions<V>;
///     MAC confirmation_tag;
///     uint32 signer;
///     /* SignWithLabel(., "GroupInfoTBS", GroupInfoTBS) */
///     opaque signature<V>;
/// } GroupInfo;
/// ```
#[derive(Debug, PartialEq, Clone, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "test-utils", derive(TlsDeserialize))]
pub struct GroupInfo {
    payload: GroupInfoTBS,
    signature: Signature,
}

impl GroupInfo {
    /// Returns the group context.
    pub(crate) fn group_context(&self) -> &GroupContext {
        &self.payload.group_context
    }

    /// Returns the extensions.
    pub(crate) fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }

    /// Returns the confirmation tag.
    pub(crate) fn confirmation_tag(&self) -> &ConfirmationTag {
        &self.payload.confirmation_tag
    }

    pub(crate) fn into_verifiable_group_info(self) -> VerifiableGroupInfo {
        VerifiableGroupInfo {
            payload: GroupInfoTBS {
                group_context: self.payload.group_context,
                extensions: self.payload.extensions,
                confirmation_tag: self.payload.confirmation_tag,
                signer: self.payload.signer,
            },
            signature: self.signature,
        }
    }
}

impl From<GroupInfo> for GroupContext {
    fn from(value: GroupInfo) -> Self {
        value.payload.group_context
    }
}

/// GroupInfo (To Be Signed)
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     GroupContext group_context;
///     Extension extensions<V>;
///     MAC confirmation_tag;
///     uint32 signer;
/// } GroupInfoTBS;
/// ```
#[derive(Debug, PartialEq, Clone, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct GroupInfoTBS {
    group_context: GroupContext,
    extensions: Extensions,
    confirmation_tag: ConfirmationTag,
    signer: LeafNodeIndex,
}

impl GroupInfoTBS {
    /// Create a new to-be-signed group info.
    pub(crate) fn new(
        group_context: GroupContext,
        extensions: Extensions,
        confirmation_tag: ConfirmationTag,
        signer: LeafNodeIndex,
    ) -> Self {
        Self {
            group_context,
            extensions,
            confirmation_tag,
            signer,
        }
    }
}

#[cfg(test)]
impl GroupInfoTBS {
    pub(crate) fn group_context_mut(&mut self) -> &mut GroupContext {
        &mut self.group_context
    }
}

// -------------------------------------------------------------------------------------------------

impl Signable for GroupInfoTBS {
    type SignedOutput = GroupInfo;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        SIGNATURE_GROUP_INFO_LABEL
    }
}

impl SignedStruct<GroupInfoTBS> for GroupInfo {
    fn from_payload(payload: GroupInfoTBS, signature: Signature) -> Self {
        Self { payload, signature }
    }
}

impl Verifiable for VerifiableGroupInfo {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        SIGNATURE_GROUP_INFO_LABEL
    }
}

impl VerifiedStruct<VerifiableGroupInfo> for GroupInfo {
    type SealingType = private_mod::Seal;

    fn from_verifiable(v: VerifiableGroupInfo, _seal: Self::SealingType) -> Self {
        Self {
            payload: v.payload,
            signature: v.signature,
        }
    }
}

mod private_mod {
    #[derive(Default)]
    pub struct Seal;
}
