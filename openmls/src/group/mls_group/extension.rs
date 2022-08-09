//! MLS group context extensions
//!
//! Contains all the method related to modifying a group's extensions

use tls_codec::Serialize;

use crate::prelude::CreateGroupContextExtProposalError;
use crate::prelude::hash_ref::ProposalRef;

use super::*;

impl MlsGroup {
    /// Creates proposals to update extensions of the group. This replaces the existing extensions
    /// of a group and does not merge them.
    ///
    /// Returns an error if there is a pending commit.
    pub async fn propose_extension(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        extensions: &[Extension],
    ) -> Result<(MlsMessageOut, ProposalRef), CreateGroupContextExtProposalError> {
        self.is_operational()?;

        let sign_key = self
            .credential()?
            .signature_key()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(&sign_key)
            .await
            .ok_or(CreateGroupContextExtProposalError::NoMatchingCredentialBundle)?;

        let gce_proposal = self.group.create_group_context_ext_proposal(
            self.framing_parameters(),
            &credential_bundle,
            extensions,
            self.pending_proposals(),
            backend,
        )?;

        let queued_proposal = QueuedProposal::from_mls_plaintext(
            self.ciphersuite(),
            backend,
            gce_proposal.clone(),
        )?;
        let proposal_ref = queued_proposal.proposal_reference();
        self.proposal_store.add(queued_proposal);

        let mls_message = self.plaintext_to_mls_message(gce_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }

    /// Get a group's [`Extension`].
    pub fn group_context_extensions(&self) -> &[Extension] {
        self.group.context().extensions()
    }
}
