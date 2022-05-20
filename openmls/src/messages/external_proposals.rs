//! External Proposal
//!
//! Contains the types and methods to build external proposal
//! to add a client from a MLS group
//! `Remove` & `ReInit are nto yet implemented`

use crate::{
    credentials::CredentialBundle,
    error::LibraryError,
    framing::{FramingParameters, MlsMessageOut, MlsPlaintext, Sender, WireFormat},
    group::{
        mls_group::errors::ProposeAddMemberError,
        GroupEpoch, GroupId,
    },
    key_packages::KeyPackage,
    messages::{Proposal, AddProposal}
};
use openmls_traits::OpenMlsCryptoProvider;

/// External Proposal.
/// External proposal allows parties outside a group to request changes to the latter.
///
/// This `enum` contains the different external proposals in its variants.
/// Not yet implemented: `Remove` & `ReInit`
#[non_exhaustive]
pub enum ExternalProposal {
    /// Proposes adding a client to a group.
    /// Newly added client can be either the sender itself or not.
    Add(AddProposal),
}

impl From<ExternalProposal> for Proposal {
    fn from(ext: ExternalProposal) -> Self {
        match ext {
            ExternalProposal::Add(add) => Self::Add(add),
        }
    }
}

impl ExternalProposal {
    /// Creates a proposal to add a member to the group
    pub fn new_add(
        key_package: KeyPackage,
        sender_index: Option<&[u8]>,
        group_id: GroupId,
        epoch: GroupEpoch,
        credential: &CredentialBundle,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsMessageOut, ProposeAddMemberError> {
        let sender = sender_index
            .map(|r| Sender::Preconfigured(r.into()))
            .unwrap_or(Sender::NewMember);
        Self::Add(AddProposal { key_package })
            .create_message(sender, group_id, epoch, credential, backend)
            .map_err(ProposeAddMemberError::from)
    }

    fn create_message(
        self,
        sender: Sender,
        group_id: GroupId,
        epoch: GroupEpoch,
        credential: &CredentialBundle,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsMessageOut, LibraryError> {
        let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);
        MlsPlaintext::member_external_proposal(
            framing_parameters,
            sender,
            self,
            credential,
            group_id,
            epoch,
            backend,
        )
        .map(MlsMessageOut::from)
    }
}
