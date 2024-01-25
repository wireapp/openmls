use openmls_traits::signatures::Signer;

use crate::group::core_group::create_commit_params::CreateCommitParams;
use crate::{messages::group_info::GroupInfo, versions::ProtocolVersion};

use super::*;

impl MlsGroup {
    /// Propose the group to be reinitialized. When commited this will make the current group
    /// innactive and a new one should be created from the commit message. The new group will have
    /// the new given extensions, ciphersuite and version from the proposal.
    ///
    /// Returns an error if there is a pending commit, if the new proposed version is older than
    /// the current or if any member doesn't support the proposed extensions and/or ciphersuite.
    pub fn propose_reinit(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        extensions: Extensions,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeReInitError> {
        self.is_operational()?;

        let reinit_proposal = self.group.create_reinit_proposal(
            self.framing_parameters(),
            extensions,
            ciphersuite,
            version,
            signer,
        )?;

        let proposal = QueuedProposal::from_authenticated_content(
            self.ciphersuite(),
            backend,
            reinit_proposal.clone(),
            ProposalOrRefType::Proposal,
        )?;
        let reference = proposal.proposal_reference().clone();

        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(reinit_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, reference))
    }

    /// ReInits the group. If there are any proposals in the `ProposalStore` they are going to be
    /// commited, but the ReInit won't be issued. A ReInit must be done exclusively with a
    /// empty `ProposalStore`. In that case the ReInit must be reissued.
    ///
    /// If successful, it returns a triple where the first element
    /// contains the commit, the second one the [Welcome] and the third an optional [GroupInfo] that
    /// will be [Some] if the group has the `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    pub async fn reinit<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        extensions: Extensions,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        ReInitError<KeyStore::Error>,
    > {
        self.is_operational()?;
        let proposal = Proposal::ReInit(ReInitProposal {
            group_id: self.group_id().clone(),
            version,
            ciphersuite,
            extensions,
        });
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
}
