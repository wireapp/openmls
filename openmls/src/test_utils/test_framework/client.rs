//! This module provides the `Client` datastructure, which contains the state
//! associated with a client in the context of MLS, along with functions to have
//! that client perform certain MLS operations.
use async_lock::RwLock;
use std::collections::HashMap;

use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    key_store::OpenMlsKeyStore,
    types::{Ciphersuite, HpkeKeyPair, SignatureScheme},
    OpenMlsCryptoProvider,
};
use tls_codec::Serialize;

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::hash_ref::KeyPackageRef,
    credentials::*,
    extensions::*,
    framing::*,
    group::{config::CryptoConfig, *},
    key_packages::*,
    messages::{group_info::GroupInfo, *},
    treesync::{
        node::{leaf_node::Capabilities, Node},
        LeafNode, RatchetTree, RatchetTreeIn,
    },
    versions::ProtocolVersion,
};

use super::{errors::ClientError, ActionType};

#[derive(Debug)]
/// The client contains the necessary state for a client in the context of MLS.
/// It contains the group states, as well as a reference to a `KeyStore`
/// containing its `CredentialWithKey`s. The `key_package_bundles` field
/// contains generated `KeyPackageBundle`s that are waiting to be used for new
/// groups.
pub struct Client {
    /// Name of the client.
    pub identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub credentials: HashMap<Ciphersuite, CredentialWithKey>,
    pub crypto: OpenMlsRustCrypto,
    pub groups: RwLock<HashMap<GroupId, MlsGroup>>,
}

impl Client {
    /// Generate a fresh key package and return it.
    /// The first ciphersuite determines the
    /// credential used to generate the `KeyPackage`.
    pub async fn get_fresh_key_package(
        &self,
        ciphersuite: Ciphersuite,
    ) -> Result<KeyPackage, ClientError> {
        let credential_with_key = self
            .credentials
            .get(&ciphersuite)
            .ok_or(ClientError::CiphersuiteNotSupported)?;
        let keys = SignatureKeyPair::read(
            self.crypto.key_store(),
            credential_with_key.signature_key.as_slice(),
        )
        .await
        .unwrap();

        let key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                &self.crypto,
                &keys,
                credential_with_key.clone(),
            )
            .await
            .unwrap();

        Ok(key_package)
    }

    /// Create a group with the given [MlsGroupConfig] and [Ciphersuite], and return the created [GroupId].
    ///
    /// Returns an error if the client doesn't support the `ciphersuite`.
    pub async fn create_group(
        &self,
        mls_group_config: MlsGroupConfig,
        ciphersuite: Ciphersuite,
    ) -> Result<GroupId, ClientError> {
        let credential_with_key = self
            .credentials
            .get(&ciphersuite)
            .ok_or(ClientError::CiphersuiteNotSupported)?;
        let signer = SignatureKeyPair::read(
            self.crypto.key_store(),
            credential_with_key.signature_key.as_slice(),
        )
        .await
        .unwrap();

        let group_state = MlsGroup::new(
            &self.crypto,
            &signer,
            &mls_group_config,
            credential_with_key.clone(),
        )
        .await?;

        let group_id = group_state.group_id().clone();
        self.groups
            .write()
            .await
            .insert(group_state.group_id().clone(), group_state);
        Ok(group_id)
    }

    /// Join a group based on the given `welcome` and `ratchet_tree`. The group
    /// is created with the given `MlsGroupConfig`. Throws an error if no
    /// `KeyPackage` exists matching the `Welcome`, if the client doesn't
    /// support the ciphersuite, or if an error occurs processing the `Welcome`.
    pub async fn join_group(
        &self,
        mls_group_config: MlsGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<RatchetTreeIn>,
    ) -> Result<(), ClientError> {
        let new_group: MlsGroup =
            MlsGroup::new_from_welcome(&self.crypto, &mls_group_config, welcome, ratchet_tree)
                .await?;
        self.groups
            .write()
            .await
            .insert(new_group.group_id().to_owned(), new_group);
        Ok(())
    }

    /// Have the client process the given messages. Returns an error if an error
    /// occurs during message processing or if no group exists for one of the
    /// messages.
    pub async fn receive_messages_for_group(
        &self,
        message: &ProtocolMessage,
        sender_id: &[u8],
    ) -> Result<(), ClientError> {
        let mut group_states = self.groups.write().await;
        let group_id = message.group_id();
        let group_state = group_states
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        if sender_id == self.identity && message.content_type() == ContentType::Commit {
            group_state.merge_pending_commit(&self.crypto).await?
        } else {
            if message.content_type() == ContentType::Commit {
                // Clear any potential pending commits.
                group_state.clear_pending_commit();
            }
            // Process the message.
            let processed_message = group_state
                .process_message(&self.crypto, message.clone())
                .await?;

            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => {}
                ProcessedMessageContent::ProposalMessage(staged_proposal) => {
                    group_state.store_pending_proposal(*staged_proposal);
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(staged_proposal) => {
                    group_state.store_pending_proposal(*staged_proposal);
                }
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                    group_state
                        .merge_staged_commit(&self.crypto, *staged_commit)
                        .await?;
                }
            }
        }

        drop(group_states);

        Ok(())
    }

    /// Get the credential and the index of each group member of the group with
    /// the given id. Returns an error if no group exists with the given group
    /// id.
    pub async fn get_members_of_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<Member>, ClientError> {
        let groups = self.groups.read().await;
        let group = groups.get(group_id).ok_or(ClientError::NoMatchingGroup)?;
        let members = group.members().collect();
        Ok(members)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) a self update in the group with the given group id.
    /// Optionally, a `HpkeKeyPair` can be provided, which the client will
    /// update their leaf with. Returns an error if no group with the given
    /// group id can be found or if an error occurs while creating the update.
    #[allow(clippy::type_complexity)]
    pub async fn self_update(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        leaf_node: Option<LeafNode>,
    ) -> Result<(MlsMessageOut, Option<Welcome>, Option<GroupInfo>), ClientError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        // Get the signature public key to read the signer from the
        // key store.
        let signature_pk = group.own_leaf().unwrap().signature_key();
        let signer = SignatureKeyPair::read(self.crypto.key_store(), signature_pk.as_slice())
            .await
            .unwrap();
        let (msg, welcome_option, group_info) = match action_type {
            ActionType::Commit => group.self_update(&self.crypto, &signer).await?,
            ActionType::Proposal => {
                let proposal = if let Some(ln) = leaf_node {
                    // FIXME: this does not work since both signers are the same
                    group
                        .propose_explicit_self_update(&self.crypto, &signer, ln, &signer)
                        .await
                } else {
                    group.propose_self_update(&self.crypto, &signer).await
                }
                .map(|(out, _)| out)?;
                (proposal, None, None)
            }
        };
        Ok((
            msg,
            welcome_option.map(|w| w.into_welcome().expect("Unexpected message type.")),
            group_info,
        ))
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) adding the clients with the given `KeyPackage`s to the
    /// group with the given group id. Returns an error if no group with the
    /// given group id can be found or if an error occurs while performing the
    /// add operation.
    #[allow(clippy::type_complexity)]
    pub async fn add_members(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        key_packages: Vec<KeyPackageIn>,
    ) -> Result<(Vec<MlsMessageOut>, Option<Welcome>, Option<GroupInfo>), ClientError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        // Get the signature public key to read the signer from the
        // key store.
        let signature_pk = group.own_leaf().unwrap().signature_key();
        let signer = SignatureKeyPair::read(self.crypto.key_store(), signature_pk.as_slice())
            .await
            .unwrap();
        let action_results = match action_type {
            ActionType::Commit => {
                let (messages, welcome_message, group_info) = group
                    .add_members(&self.crypto, &signer, key_packages)
                    .await?;
                (
                    vec![messages],
                    Some(
                        welcome_message
                            .into_welcome()
                            .expect("Unexpected message type."),
                    ),
                    group_info,
                )
            }
            ActionType::Proposal => {
                let mut messages = Vec::new();
                for key_package in key_packages {
                    let message = group
                        .propose_add_member(&self.crypto, &signer, key_package.clone())
                        .await
                        .map(|(out, _)| out)?;
                    messages.push(message);
                }
                (messages, None, None)
            }
        };
        Ok(action_results)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) removing the clients with the given indices from the
    /// group with the given group id. Returns an error if no group with the
    /// given group id can be found or if an error occurs while performing the
    /// remove operation.
    #[allow(clippy::type_complexity)]
    pub async fn remove_members(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        targets: &[LeafNodeIndex],
    ) -> Result<(Vec<MlsMessageOut>, Option<Welcome>, Option<GroupInfo>), ClientError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        // Get the signature public key to read the signer from the
        // key store.
        let signature_pk = group.own_leaf().unwrap().signature_key();
        let signer = SignatureKeyPair::read(self.crypto.key_store(), signature_pk.as_slice())
            .await
            .unwrap();
        let action_results = match action_type {
            ActionType::Commit => {
                let (message, welcome_option, group_info) =
                    group.remove_members(&self.crypto, &signer, targets).await?;
                (
                    vec![message],
                    welcome_option.map(|w| w.into_welcome().expect("Unexpected message type.")),
                    group_info,
                )
            }
            ActionType::Proposal => {
                let mut messages = Vec::new();
                for target in targets {
                    let message = group
                        .propose_remove_member(&self.crypto, &signer, *target)
                        .map(|(out, _)| out)?;
                    messages.push(message);
                }
                (messages, None, None)
            }
        };
        Ok(action_results)
    }

    /// Get the identity of this client in the given group.
    pub async fn identity(&self, group_id: &GroupId) -> Option<Vec<u8>> {
        let groups = self.groups.read().await;
        let group = groups.get(group_id).unwrap();
        group.own_identity().map(|s| s.to_vec())
    }
}
