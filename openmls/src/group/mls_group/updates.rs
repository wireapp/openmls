use core_group::create_commit_params::CreateCommitParams;
use openmls_traits::signatures::Signer;

use crate::treesync::node::leaf_node::{LeafNodeIn, TreePosition, VerifiableLeafNode};
use crate::treesync::node::validate::ValidatableLeafNode;
use crate::{messages::group_info::GroupInfo, treesync::LeafNode, versions::ProtocolVersion};

use super::*;

impl MlsGroup {
    /// Updates the own leaf node.
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] (containing the
    /// commit), an optional [`MlsMessageOut`] (containing the [`Welcome`]) and the [GroupInfo].
    /// The [Welcome] is [Some] when the queue of pending proposals contained
    /// add proposals
    /// The [GroupInfo] is [Some] if the group has the `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    ///
    /// TODO #1208 : The caller should be able to optionally provide a
    /// [`LeafNode`] here, so that things like extensions can be changed via
    /// commit.
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub async fn self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        SelfUpdateError<KeyStore::Error>,
    > {
        self.explicit_self_update(backend, signer, None).await
    }

    /// Like [Self::self_update] but accepts an explicit node. Mostly to rotate its credential
    #[allow(clippy::type_complexity)]
    pub async fn explicit_self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        leaf_node: Option<LeafNode>,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        SelfUpdateError<KeyStore::Error>,
    > {
        self.is_operational()?;

        let parameters = self.framing_parameters();
        let builder = CreateCommitParams::builder()
            .framing_parameters(parameters)
            .proposal_store(&self.proposal_store);

        let params = if let Some(leaf_node) = leaf_node {
            let mut own_leaf = self
                .own_leaf()
                .ok_or_else(|| LibraryError::custom("The tree is broken. Couldn't find own leaf."))?
                .clone();

            own_leaf.update_and_re_sign(
                None,
                Some(leaf_node),
                self.group_id().clone(),
                self.own_leaf_index(),
                signer,
            )?;

            let update_proposal = Proposal::Update(UpdateProposal {
                leaf_node: own_leaf,
            });

            builder.inline_proposals(vec![update_proposal])
        } else {
            builder.force_self_update(true)
        }
        .build();

        // Create Commit over all proposals.
        // TODO #751
        let create_commit_result = self.group.create_commit(params, backend, signer).await?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.content_to_mls_message(create_commit_result.commit, backend)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((
            mls_message,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.group.version())),
            create_commit_result.group_info,
        ))
    }

    /// Creates a proposal to update the own leaf node.
    pub async fn propose_self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeSelfUpdateError<KeyStore::Error>> {
        let update_proposal = self._propose_self_update(backend, signer).await?;
        let proposal = QueuedProposal::from_authenticated_content_by_ref(
            self.ciphersuite(),
            backend,
            update_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference().clone();
        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(update_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }

    /// Creates a proposal to update the own leaf node.
    pub async fn propose_self_update_by_value<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeSelfUpdateError<KeyStore::Error>> {
        let update_proposal = self._propose_self_update(backend, signer).await?;
        let proposal = QueuedProposal::from_authenticated_content_by_value(
            self.ciphersuite(),
            backend,
            update_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference().clone();
        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(update_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }

    /// Creates a proposal to update the own leaf node. Optionally, a
    /// [`LeafNode`] can be provided to update the leaf node. Note that its
    /// private key must be manually added to the key store.
    pub(crate) async fn _propose_self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, ProposeSelfUpdateError<KeyStore::Error>> {
        self.is_operational()?;

        // Here we clone our own leaf to rekey it such that we don't change the tree.
        // The new leaf node will be applied later when the proposal is committed.
        let mut own_leaf = self
            .own_leaf()
            .ok_or_else(|| LibraryError::custom("The tree is broken. Couldn't find own leaf."))?
            .clone();
        let keypair = own_leaf.rekey(
            self.group_id(),
            self.own_leaf_index(),
            None,
            self.ciphersuite(),
            ProtocolVersion::default(), // XXX: openmls/openmls#1065
            backend,
            signer,
        )?;

        keypair
            .write_to_key_store(backend)
            .await
            .map_err(ProposeSelfUpdateError::KeyStoreError)?;

        let tree_position = TreePosition::new(self.group_id().clone(), self.own_leaf_index());
        let VerifiableLeafNode::Update(own_leaf) =
            LeafNodeIn::from(own_leaf).try_into_verifiable_leaf_node(Some(tree_position))?
        else {
            return Err(LibraryError::custom(
                "LeafNode source should have been set to 'update' at this point",
            )
            .into());
        };
        let own_leaf = own_leaf
            .validate(self.group().public_group(), backend)
            .await?;

        let update_proposal = self.group.create_update_proposal(
            self.framing_parameters(),
            own_leaf.clone(),
            signer,
        )?;

        self.own_leaf_nodes.push(own_leaf);

        Ok(update_proposal)
    }

    /// Creates a proposal to update the own leaf node.
    pub async fn propose_explicit_self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        leaf_node: LeafNode,
        leaf_node_signer: &impl Signer,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeSelfUpdateError<KeyStore::Error>> {
        let update_proposal = self
            ._propose_explicit_self_update(backend, signer, leaf_node, leaf_node_signer)
            .await?;
        let proposal = QueuedProposal::from_authenticated_content_by_value(
            self.ciphersuite(),
            backend,
            update_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference().clone();
        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(update_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }

    /// Creates a proposal to update the own leaf node. Optionally, a
    /// [`LeafNode`] can be provided to update the leaf node. Note that its
    /// private key must be manually added to the key store.
    pub(crate) async fn _propose_explicit_self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        leaf_node: LeafNode,
        leaf_node_signer: &impl Signer,
    ) -> Result<AuthenticatedContent, ProposeSelfUpdateError<KeyStore::Error>> {
        self.is_operational()?;

        let mut own_leaf = self
            .own_leaf()
            .ok_or_else(|| LibraryError::custom("The tree is broken. Couldn't find own leaf."))?
            .clone();

        let keypair = own_leaf.rekey(
            self.group_id(),
            self.own_leaf_index(),
            Some(leaf_node),
            self.ciphersuite(),
            ProtocolVersion::Mls10,
            backend,
            leaf_node_signer,
        )?;

        keypair
            .write_to_key_store(backend)
            .await
            .map_err(ProposeSelfUpdateError::KeyStoreError)?;

        let tree_position = TreePosition::new(self.group_id().clone(), self.own_leaf_index());
        let VerifiableLeafNode::Update(own_leaf) =
            LeafNodeIn::from(own_leaf).try_into_verifiable_leaf_node(Some(tree_position))?
        else {
            return Err(LibraryError::custom(
                "LeafNode source should have been set to 'update' at this point",
            )
            .into());
        };
        let own_leaf = own_leaf
            .validate(self.group().public_group(), backend)
            .await?;

        let update_proposal = self.group.create_update_proposal(
            self.framing_parameters(),
            own_leaf.clone(),
            signer,
        )?;

        self.own_leaf_nodes.push(own_leaf);

        Ok(update_proposal)
    }
}
