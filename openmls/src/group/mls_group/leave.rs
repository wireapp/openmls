//! MLS group membership leave
//!

use std::borrow::BorrowMut;

use tls_codec::Serialize;

use crate::prelude::CreateCommitError;
use crate::{ciphersuite::hash_ref::KeyPackageRef, group::staged_commit::StagedCommitState};

use super::{errors::LeaveGroupError, *};

impl MlsGroup {
    /// Leave the group.
    ///
    /// Creates a Remove Proposal that needs to be covered by a Commit from a different member.
    /// The Remove Proposal is returned as a [`MlsMessageOut`].
    ///
    /// Returns an error if there is a pending commit.
    pub async fn leave_group(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsMessageOut, LeaveGroupError> {
        self.is_operational()?;

        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(
                &self
                    .credential()?
                    .signature_key()
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .await
            .ok_or(LeaveGroupError::NoMatchingCredentialBundle)?;

        let removed = self
            .group
            .key_package_ref()
            .ok_or_else(|| LibraryError::custom("No key package reference for own key package."))?;
        let remove_proposal = self.group.create_remove_proposal(
            self.framing_parameters(),
            &credential_bundle,
            removed,
            backend,
        )?;

        self.proposal_store.add(QueuedProposal::from_mls_plaintext(
            self.ciphersuite(),
            backend,
            remove_proposal.clone(),
        )?);

        Ok(self.plaintext_to_mls_message(remove_proposal, backend)?)
    }

    /// Extends [`leave_group`] by allowing to also remove other members in a commit
    ///
    /// Creates a commit for removing the other members.
    /// Then creates a Remove Proposal for self that needs to be covered by a Commit from a different member.
    ///
    /// Once merging the commit, the sender must take care of restoring the proposal from the store.
    /// Indeed, this restoring logic might depend upon implementer delivery semantics guaranteed by
    /// its Delivery Service. For example, it might have to also restore proposals by reference in the store
    /// in case its DS does not guarantees message ordering.
    ///
    /// Returns (SelfRemoveProposal, OthersRemoveCommit)
    /// Returns an error if there is a pending commit.
    pub async fn leave_group_and_remove_others(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        members: &[KeyPackageRef],
    ) -> Result<(MlsMessageOut, MlsMessageOut), LeaveGroupError> {
        self.is_operational()?;

        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(
                &self
                    .credential()?
                    .signature_key()
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .await
            .ok_or(LeaveGroupError::NoMatchingCredentialBundle)?;

        // Let's create a commit without (potentially) encrypting it. We will need it later on
        // to create a Remove Proposal for self with the new epoch secrets
        let mut commit_result = self
            .create_remove_commit(backend, members)
            .await
            .map_err(|e| match e {
                RemoveMembersError::CreateCommitError(CreateCommitError::CannotRemoveSelf) => {
                    LeaveGroupError::AttemptToRemoveSelf
                }
                _ => e.into(),
            })?;

        // if the sender KeyPackage changed during commit
        let self_kpr_from_commit = commit_result
            .staged_commit
            .commit_update_key_package()
            .map(|k| k.hash_ref(backend.crypto()))
            .transpose()
            .map_err(LeaveGroupError::LibraryError)?;
        // else there's no UpdatePath and the KeyPackage is unchanged
        let self_kpr = self_kpr_from_commit
            .as_ref()
            .or_else(|| self.group.key_package_ref())
            .ok_or(LeaveGroupError::NoKeyPackageForSelf)?;

        let staged_commit_state = match commit_result.staged_commit.state.borrow_mut() {
            StagedCommitState::GroupMember(state) => state,
            StagedCommitState::SelfRemoved(_) => return Err(LeaveGroupError::AttemptToRemoveSelf),
        };

        // Now we create a Remove Proposal for self. This proposal will have to be committed by
        // another member of the group.
        // We use the previous commit to create the proposal so that it remains valid if the commit gets merged
        let self_remove_proposal = MlsPlaintext::member_proposal(
            self.framing_parameters(),
            self_kpr,
            Proposal::Remove(RemoveProposal { removed: *self_kpr }),
            &credential_bundle,
            &staged_commit_state.group_context,
            staged_commit_state.message_secrets.membership_key(),
            backend,
        )?;

        let proposal_msg = self.plaintext_to_mls_message_for_new_epoch(
            self_remove_proposal.clone(),
            Some(&staged_commit_state.group_context),
            Some(&mut staged_commit_state.message_secrets),
            backend,
        )?;

        // Stores the proposal in the store but it will have to be manually restored after
        // 'merge_pending_commit' which clears the store
        self.proposal_store.add(QueuedProposal::from_mls_plaintext(
            self.ciphersuite(),
            backend,
            self_remove_proposal.clone(),
        )?);

        // Now finish wrapping the commit in a message
        let commit = self.plaintext_to_mls_message(commit_result.commit, backend)?;
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((proposal_msg, commit))
    }
}
