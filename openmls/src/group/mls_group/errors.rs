//! # MlsGroup errors
//!
//! This module defines the public errors that can be returned from all calls
//! to methods of [`MlsGroup`](super::MlsGroup).

// These errors are exposed through `crate::group::errors`.

use openmls_traits::types::CryptoError;
use thiserror::Error;

use crate::prelude::KeyPackageVerifyError;
use crate::{
    credentials::errors::CredentialError,
    error::LibraryError,
    extensions::errors::{ExtensionError, InvalidExtensionError},
    group::errors::{
        CreateAddProposalError, CreateCommitError, MergeCommitError, ReInitValidationError,
        StageCommitError, ValidationError,
    },
    prelude::KeyPackageExtensionSupportError,
    schedule::errors::PskError,
    treesync::errors::{LeafNodeValidationError, MemberExtensionValidationError, PublicTreeError},
};

/// New group error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum NewGroupError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// No matching KeyPackage was found in the key store.
    #[error("No matching KeyPackage was found in the key store.")]
    NoMatchingKeyPackage,
    /// Error accessing the key store.
    #[error("Error accessing the key store.")]
    KeyStoreError(KeyStoreError),
    /// Unsupported proposal type in required capabilities.
    #[error("Unsupported proposal type in required capabilities.")]
    UnsupportedProposalType,
    /// Unsupported extension type in required capabilities.
    #[error("Unsupported extension type in required capabilities.")]
    UnsupportedExtensionType,
    /// Invalid extensions set in configuration
    #[error("Invalid extensions set in configuration")]
    InvalidExtensions(InvalidExtensionError),
}

/// EmptyInput error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum EmptyInputError {
    /// An empty list of KeyPackages was provided.
    #[error("An empty list of KeyPackages was provided.")]
    AddMembers,
    /// An empty list of KeyPackage references was provided.
    #[error("An empty list of KeyPackage references was provided.")]
    RemoveMembers,
}

/// Group state error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MlsGroupStateError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Tried to use a group after being evicted from it.
    #[error("Tried to use a group after being evicted from it.")]
    UseAfterEviction,
    /// Can't create message because a pending proposal exists.
    #[error("Can't create message because a pending proposal exists.")]
    PendingProposal,
    /// Can't execute operation because a pending commit exists.
    #[error("Can't execute operation because a pending commit exists.")]
    PendingCommit,
    /// Can't execute operation because there is no pending commit.
    #[error("Can't execute operation because there is no pending commit")]
    NoPendingCommit,
    /// Requested pending proposal hasn't been found in local pending proposals
    #[error("Requested pending proposal hasn't been found in local pending proposals.")]
    PendingProposalNotFound,
    /// When trying to delete an Update proposal, it's associated encryption key was not found. This is an implementor's error
    #[error("When trying to delete an Update proposal, it's associated encryption key was not found. This is an implementor's error")]
    EncryptionKeyNotFound,
}

/// Error merging pending commit
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MergePendingCommitError<KeyStoreError> {
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    MlsGroupStateError(#[from] MlsGroupStateError),
    /// See [`MergeCommitError`] for more details.
    #[error(transparent)]
    MergeCommitError(#[from] MergeCommitError<KeyStoreError>),
}

/// Process message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProcessMessageError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The message's wire format is incompatible with the group's wire format policy.
    #[error("The message's wire format is incompatible with the group's wire format policy.")]
    IncompatibleWireFormat,
    /// See [`ValidationError`] for more details.
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// The message's signature is invalid.
    #[error("The message's signature is invalid.")]
    InvalidSignature,
    /// See [`StageCommitError`] for more details.
    #[error(transparent)]
    InvalidCommit(#[from] StageCommitError),
    /// External application messages are not permitted.
    #[error("External application messages are not permitted.")]
    UnauthorizedExternalApplicationMessage,
    /// The proposal is invalid for the Sender of type [External](crate::prelude::Sender::External)
    #[error("The proposal is invalid for the Sender of type External")]
    UnsupportedProposalType,
    /// Error parsing the certificate chain
    #[error("Error parsing the X509 certificate chain: {0}")]
    CredentialError(#[from] CredentialError),
    /// Error validating the certificate chain
    #[error("Error validating certificate chain")]
    CryptoError(#[from] CryptoError),
}

/// Create message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateMessageError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Add members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum AddMembersError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`EmptyInputError`] for more details.
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`KeyPackageVerifyError`] for more details.
    #[error(transparent)]
    KeyPackageVerifyError(#[from] KeyPackageVerifyError),
}

/// Propose add members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeAddMemberError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The new member does not support all required extensions.
    #[error("The new member does not support all required extensions.")]
    UnsupportedExtensions,
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`KeyPackageVerifyError`] for more details.
    #[error(transparent)]
    KeyPackageVerifyError(#[from] KeyPackageVerifyError),
    /// See [`CreateAddProposalError`] for more details.
    #[error(transparent)]
    CreateAddProposalError(#[from] CreateAddProposalError),
}

/// Propose remove members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeRemoveMemberError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// The member that should be removed can not be found.
    #[error("The member that should be removed can not be found.")]
    UnknownMember,
}

/// Remove members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RemoveMembersError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`EmptyInputError`] for more details.
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// The member that should be removed can not be found.
    #[error("The member that should be removed can not be found.")]
    UnknownMember,
}

/// Leave group error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeaveGroupError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum SelfUpdateError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
    /// Error accessing the key store.
    #[error("Error accessing the key store.")]
    KeyStoreError(KeyStoreError),
}

/// Propose self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeSelfUpdateError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// Error accessing the key store.
    #[error("Error accessing the key store.")]
    KeyStoreError(KeyStoreError),
    /// See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
    /// See [`LeafNodeValidationError`] for more details.
    #[error(transparent)]
    LeafNodeValidationError(#[from] LeafNodeValidationError),
}

/// Create group context ext proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum UpdateExtensionsError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MemberExtensionValidationError`] for more details.
    #[error(transparent)]
    MemberExtensionValidationError(#[from] MemberExtensionValidationError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Create group context ext proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeGroupContextExtensionError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`KeyPackageExtensionSupportError`] for more details.
    #[error(transparent)]
    KeyPackageExtensionSupport(#[from] KeyPackageExtensionSupportError),
    /// See [`ExtensionError`] for more details.
    #[error(transparent)]
    Extension(#[from] ExtensionError),
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`MemberExtensionValidationError`] for more details.
    #[error(transparent)]
    MemberExtensionValidationError(#[from] MemberExtensionValidationError),
}

/// ReInit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ReInitError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Create ReInit proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeReInitError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`ReInitValidationError`] for more details.
    #[error(transparent)]
    ReInitValidationError(#[from] ReInitValidationError),
}
/// Commit to pending proposals error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CommitToPendingProposalsError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Errors that can happen when exporting a group info object.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExportGroupInfoError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Export secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExportSecretError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The requested key length is too long.
    #[error("The requested key length is too long.")]
    KeyLengthTooLong,
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Propose PSK error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposePskError {
    /// See [`PskError`] for more details.
    #[error(transparent)]
    Psk(#[from] PskError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
}

/// Export secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposalError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`ProposeAddMemberError`] for more details.
    #[error(transparent)]
    ProposeAddMemberError(#[from] ProposeAddMemberError),
    /// See [`CreateAddProposalError`] for more details.
    #[error(transparent)]
    CreateAddProposalError(#[from] CreateAddProposalError),
    /// See [`ProposeSelfUpdateError`] for more details.
    #[error(transparent)]
    ProposeSelfUpdateError(#[from] ProposeSelfUpdateError<KeyStoreError>),
    /// See [`ProposeRemoveMemberError`] for more details.
    #[error(transparent)]
    ProposeRemoveMemberError(#[from] ProposeRemoveMemberError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`ValidationError`] for more details.
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    /// See [`KeyPackageVerifyError`] for more details.
    #[error(transparent)]
    KeyPackageVerifyError(#[from] KeyPackageVerifyError),
}
