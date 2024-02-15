//! MLS group context extensions
//!
//! Contains all the methods related to modifying a group's extensions.

use openmls_traits::signatures::Signer;

use crate::{
    messages::group_info::GroupInfo,
    prelude::{create_commit_params::CreateCommitParams, hash_ref::ProposalRef},
};

use super::*;

impl MlsGroup {
    /// Propose to update the group context extensions. This replaces the existing extensions
    /// of the group but does not merge them yet.
    ///
    /// Returns an error if there is a pending commit.
    #[inline]
    pub fn propose_extensions<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        extensions: Extensions,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<KeyStore::Error>> {
        self.propose_group_context_extensions(
            backend,
            signer,
            extensions,
            ProposalOrRefType::Proposal,
        )
    }

    /// Updates the extensions of the group
    ///
    /// This operation results in a Commit with a `path`, i.e. it includes an
    /// update of the committer's leaf [KeyPackage].
    ///
    /// If successful, it returns a triple where the first element
    /// contains the commit, the second one the [Welcome] and the third an optional [GroupInfo] that
    /// will be [Some] if the group has the `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    pub async fn update_extensions<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        extensions: Extensions,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        UpdateExtensionsError<KeyStore::Error>,
    > {
        self.is_operational()?;
        self.group
            .members_support_extensions(&extensions, self.pending_proposals())?;
        let proposal =
            Proposal::GroupContextExtensions(GroupContextExtensionProposal::new(extensions));
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .inline_proposals(vec![proposal])
            .build();
        let create_commit_result = self.group.create_commit(params, backend, signer).await?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.content_to_mls_message(create_commit_result.commit, backend)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();
        Ok((
            mls_messages,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.group.version())),
            create_commit_result.group_info,
        ))
    }

    /// Get the group's [`Extensions`].
    pub fn group_context_extensions(&self) -> &Extensions {
        self.group.context().extensions()
    }
}
