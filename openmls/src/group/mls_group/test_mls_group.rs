use core_group::test_core_group::setup_client;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};

use crate::{
    binary_tree::LeafNodeIndex,
    framing::*,
    group::{config::CryptoConfig, errors::*, *},
    key_packages::*,
    messages::proposals::*,
    test_utils::test_framework::{
        errors::ClientError, ActionType::Commit, CodecUse, MlsGroupTestSetup,
    },
    test_utils::*,
};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn test_mls_group_persistence(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, backend).await;

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &alice_signer,
        &mls_group_config,
        group_id.clone(),
        alice_credential_with_key,
    )
    .await
    .expect("An unexpected error occurred.");

    // Check the internal state has changed
    assert_eq!(alice_group.state_changed(), InnerState::Changed);

    alice_group
        .save(backend)
        .await
        .expect("Could not write group state to file");

    let alice_group_deserialized = MlsGroup::load(&group_id, backend)
        .await
        .expect("Could not deserialize MlsGroup");

    assert_eq!(
        (
            alice_group.export_ratchet_tree(),
            alice_group.export_secret(backend, "test", &[], 32)
        ),
        (
            alice_group_deserialized.export_ratchet_tree(),
            alice_group_deserialized.export_secret(backend, "test", &[], 32)
        )
    );
}

// This tests if the remover is correctly passed to the callback when one member
// issues a RemoveProposal and another members issues the next Commit.
#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn remover(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, backend).await;
    let (_bob_credential, bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, backend).await;
    let (_charlie_credential, charlie_kpb, charlie_signer, _charlie_pk) =
        setup_client("Charly", ciphersuite, backend).await;

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfigBuilder::new()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &alice_signer,
        &mls_group_config,
        group_id,
        alice_credential_with_key,
    )
    .await
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    let (_queued_message, welcome, _group_info) = alice_group
        .add_members(
            backend,
            &alice_signer,
            vec![bob_kpb.key_package().clone().into()],
        )
        .await
        .expect("Could not add member to group.");

    alice_group
        .merge_pending_commit(backend)
        .await
        .expect("error merging pending commit");

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected message type."),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .await
    .expect("Error creating group from Welcome");

    // === Bob adds Charlie ===
    let (queued_messages, welcome, _group_info) = bob_group
        .add_members(
            backend,
            &bob_signer,
            vec![charlie_kpb.key_package().clone().into()],
        )
        .await
        .unwrap();

    let alice_processed_message = alice_group
        .process_message(
            backend,
            queued_messages
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .await
        .expect("Could not process messages.");
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(backend, *staged_commit)
            .await
            .expect("Error merging commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    bob_group
        .merge_pending_commit(backend)
        .await
        .expect("error merging pending commit");

    let mut charlie_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected message type."),
        Some(bob_group.export_ratchet_tree().into()),
    )
    .await
    .expect("Error creating group from Welcome");

    // === Alice removes Bob & Charlie commits ===

    let (queued_messages, _) = alice_group
        .propose_remove_member(backend, &alice_signer, LeafNodeIndex::new(1))
        .expect("Could not propose removal");

    let charlie_processed_message = charlie_group
        .process_message(
            backend,
            queued_messages
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .await
        .expect("Could not process messages.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        charlie_processed_message.into_content()
    {
        if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
            // Check that Bob was removed
            assert_eq!(remove_proposal.removed(), LeafNodeIndex::new(1));
            // Store proposal
            charlie_group.store_pending_proposal(*staged_proposal.clone());
        } else {
            unreachable!("Expected a Proposal.");
        }

        // Check that Alice removed Bob
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if member.u32() == 0
        ));
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Charlie commits
    let (_queued_messages, _welcome, _group_info) = charlie_group
        .commit_to_pending_proposals(backend, &charlie_signer)
        .await
        .expect("Could not commit proposal");

    // Check that we receive the correct proposal
    if let Some(staged_commit) = charlie_group.pending_commit() {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(remove.remove_proposal().removed().u32(), 1);
        // Check that Alice removed Bob
        assert!(matches!(remove.sender(), Sender::Member(member) if member.u32() == 0));
    } else {
        unreachable!("Expected a StagedCommit.");
    };

    charlie_group
        .merge_pending_commit(backend)
        .await
        .expect("error merging pending commit");

    // TODO #524: Check that Alice removed Bob
}

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn export_secret(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, backend).await;

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let alice_group = MlsGroup::new_with_group_id(
        backend,
        &alice_signer,
        &mls_group_config,
        group_id,
        alice_credential_with_key,
    )
    .await
    .expect("An unexpected error occurred.");

    assert!(
        alice_group
            .export_secret(backend, "test1", &[], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
            != alice_group
                .export_secret(backend, "test2", &[], ciphersuite.hash_length())
                .expect("An unexpected error occurred.")
    );
    assert!(
        alice_group
            .export_secret(backend, "test", &[0u8], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
            != alice_group
                .export_secret(backend, "test", &[1u8], ciphersuite.hash_length())
                .expect("An unexpected error occurred.")
    )
}

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn test_invalid_plaintext(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Some basic setup functions for the MlsGroup.
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    let number_of_clients = 20;
    let setup = MlsGroupTestSetup::new(
        mls_group_config,
        number_of_clients,
        CodecUse::StructMessages,
    )
    .await;
    // Create a basic group with more than 4 members to create a tree with intermediate nodes.
    let group_id = setup
        .create_random_group(10, ciphersuite)
        .await
        .expect("An unexpected error occurred.");
    let mut groups = setup.groups.write().await;
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let (_, client_id) = &group
        .members()
        .find(|(index, _)| index == &0)
        .expect("An unexpected error occurred.");

    let clients = setup.clients.read().await;
    let client = clients
        .get(client_id)
        .expect("An unexpected error occurred.")
        .read()
        .await;

    let (mls_message, _welcome_option, _group_info) = client
        .self_update(Commit, &group_id, None)
        .await
        .expect("error creating self update");

    // Store the context and membership key so that we can re-compute the membership tag later.
    let client_groups = client.groups.read().await;
    let client_group = client_groups.get(&group_id).unwrap();
    let membership_key = client_group.group().message_secrets().membership_key();

    // Tamper with the message such that signature verification fails
    // Once #574 is addressed the new function from there should be used to manipulate the signature.
    // Right now the membership tag is verified first, wihich yields `VerificationError::InvalidMembershipTag`
    // error instead of a `CredentialError:InvalidSignature`.
    let mut msg_invalid_signature = mls_message.clone();
    if let MlsMessageOutBody::PublicMessage(ref mut pt) = msg_invalid_signature.body {
        pt.invalidate_signature()
    };

    // Tamper with the message such that sender lookup fails
    let mut msg_invalid_sender = mls_message;
    let random_sender = Sender::build_member(LeafNodeIndex::new(987543210));
    match &mut msg_invalid_sender.body {
        MlsMessageOutBody::PublicMessage(pt) => {
            pt.set_sender(random_sender);
            pt.set_membership_tag(
                backend,
                membership_key,
                client_group.group().message_secrets().serialized_context(),
            )
            .unwrap()
        }
        _ => panic!("This should be a plaintext!"),
    };

    drop(client_groups);
    drop(client);
    drop(clients);

    let error = setup
        // We're the "no_client" id to prevent the original sender from treating
        // this message as his own and merging the pending commit.
        .distribute_to_members("no_client".as_bytes(), group, &msg_invalid_signature.into())
        .await
        .expect_err("No error when distributing message with invalid signature.");

    assert_eq!(
        ClientError::ProcessMessageError(ProcessMessageError::ValidationError(
            ValidationError::InvalidMembershipTag
        )),
        error
    );

    let error = setup
        // We're the "no_client" id to prevent the original sender from treating
        // this message as his own and merging the pending commit.
        .distribute_to_members("no_client".as_bytes(), group, &msg_invalid_sender.into())
        .await
        .expect_err("No error when distributing message with invalid signature.");

    assert_eq!(
        ClientError::ProcessMessageError(ProcessMessageError::ValidationError(
            ValidationError::UnknownMember
        )),
        error
    );
}

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn test_pending_commit_logic(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, backend).await;
    let (_bob_credential, bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, backend).await;

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &alice_signer,
        &mls_group_config,
        group_id,
        alice_credential_with_key,
    )
    .await
    .expect("An unexpected error occurred.");

    // There should be no pending commit after group creation.
    assert!(alice_group.pending_commit().is_none());

    let bob_key_package = bob_kpb.key_package();

    // Let's add bob
    let (proposal, _) = alice_group
        .propose_add_member(backend, &alice_signer, bob_key_package.clone().into())
        .await
        .expect("error creating self-update proposal");

    let alice_processed_message = alice_group
        .process_message(backend, proposal.into_protocol_message().unwrap())
        .await
        .expect("Could not process messages.");
    assert!(alice_group.pending_commit().is_none());

    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        alice_processed_message.into_content()
    {
        alice_group.store_pending_proposal(*staged_proposal);
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // There should be no pending commit after issuing and processing a proposal.
    assert!(alice_group.pending_commit().is_none());

    println!("\nCreating commit with add proposal.");
    let (_msg, _welcome_option, _group_info) = alice_group
        .self_update(backend, &alice_signer)
        .await
        .expect("error creating self-update commit");
    println!("Done creating commit.");

    // There should be a pending commit after issueing a proposal.
    assert!(alice_group.pending_commit().is_some());

    // If there is a pending commit, other commit- or proposal-creating actions
    // should fail.
    let error = alice_group
        .add_members(backend, &alice_signer, vec![bob_key_package.clone().into()])
        .await
        .expect_err("no error committing while a commit is pending");
    assert!(matches!(
        error,
        AddMembersError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .propose_add_member(backend, &alice_signer, bob_key_package.clone().into())
        .await
        .expect_err("no error creating a proposal while a commit is pending");
    assert!(matches!(
        error,
        ProposeAddMemberError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .remove_members(backend, &alice_signer, &[LeafNodeIndex::new(1)])
        .await
        .expect_err("no error committing while a commit is pending");
    assert!(matches!(
        error,
        RemoveMembersError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .propose_remove_member(backend, &alice_signer, LeafNodeIndex::new(1))
        .expect_err("no error creating a proposal while a commit is pending");
    assert!(matches!(
        error,
        ProposeRemoveMemberError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .commit_to_pending_proposals(backend, &alice_signer)
        .await
        .expect_err("no error committing while a commit is pending");
    assert!(matches!(
        error,
        CommitToPendingProposalsError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .self_update(backend, &alice_signer)
        .await
        .expect_err("no error committing while a commit is pending");
    assert!(matches!(
        error,
        SelfUpdateError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .propose_self_update(backend, &alice_signer)
        .await
        .expect_err("no error creating a proposal while a commit is pending");
    assert!(matches!(
        error,
        ProposeSelfUpdateError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));

    // Clearing the pending commit should actually clear it.
    alice_group.clear_pending_commit();
    assert!(alice_group.pending_commit().is_none());

    // Creating a new commit should commit the same proposals.
    let (_msg, welcome_option, _group_info) = alice_group
        .self_update(backend, &alice_signer)
        .await
        .expect("error creating self-update commit");

    // Merging the pending commit should clear the pending commit and we should
    // end up in the same state as bob.
    alice_group
        .merge_pending_commit(backend)
        .await
        .expect("error merging pending commit");
    assert!(alice_group.pending_commit().is_none());

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome_option
            .expect("no welcome after commit")
            .into_welcome()
            .expect("Unexpected message type."),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .await
    .expect("error creating group from welcome");

    assert_eq!(
        bob_group.export_ratchet_tree(),
        alice_group.export_ratchet_tree()
    );
    assert_eq!(
        bob_group.export_secret(backend, "test", &[], ciphersuite.hash_length()),
        alice_group.export_secret(backend, "test", &[], ciphersuite.hash_length())
    );

    // While a commit is pending, merging Bob's commit should clear the pending commit.
    let (_msg, _welcome_option, _group_info) = alice_group
        .self_update(backend, &alice_signer)
        .await
        .expect("error creating self-update commit");

    let (msg, _welcome_option, _group_info) = bob_group
        .self_update(backend, &bob_signer)
        .await
        .expect("error creating self-update commit");

    let alice_processed_message = alice_group
        .process_message(backend, msg.into_protocol_message().unwrap())
        .await
        .expect("Could not process messages.");
    assert!(alice_group.pending_commit().is_some());

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(backend, *staged_commit)
            .await
            .expect("Error merging commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }
    assert!(alice_group.pending_commit().is_none());
}

// Test that the key package and the corresponding private key are deleted when
// creating a new group for a welcome message.
#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn key_package_deletion(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, backend).await;
    let (_bob_credential_with_key, bob_kpb, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, backend).await;
    let bob_key_package = bob_kpb.key_package();

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfigBuilder::new()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &alice_signer,
        &mls_group_config,
        group_id,
        alice_credential_with_key,
    )
    .await
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    let (_queued_message, welcome, _group_info) = alice_group
        .add_members(backend, &alice_signer, vec![bob_key_package.clone().into()])
        .await
        .unwrap();

    alice_group.merge_pending_commit(backend).await.unwrap();

    // === Bob joins the group ===
    let _bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected message type."),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .await
    .expect("Error creating group from Welcome");

    // TEST: The private key must be gone from the key store.
    assert!(backend
        .key_store()
        .read::<HpkePrivateKey>(bob_key_package.hpke_init_key().as_slice()).await
        .is_none(),
        "The HPKE private key is still in the key store after creating a new group from the key package.");

    // TEST: The key package must be gone from the key store.
    assert!(
        backend
            .key_store()
            .read::<KeyPackage>(
                bob_key_package
                    .hash_ref(backend.crypto())
                    .unwrap()
                    .as_slice()
            )
            .await
            .is_none(),
        "The key package is still in the key store after creating a new group from it."
    );
}

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn remove_prosposal_by_ref(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, backend).await;
    let (_bob_credential_with_key, bob_kpb, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, backend).await;
    let bob_key_package = bob_kpb.key_package().clone();
    let (_charlie_credential_with_key, charlie_kpb, _charlie_signer, _charlie_pk) =
        setup_client("Charlie", ciphersuite, backend).await;
    let charlie_key_package = charlie_kpb.key_package();

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfigBuilder::new()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &alice_signer,
        &mls_group_config,
        group_id,
        alice_credential_with_key,
    )
    .await
    .expect("An unexpected error occurred.");

    // alice adds bob and bob processes the welcome
    let (_, welcome, _) = alice_group
        .add_members(backend, &alice_signer, vec![bob_key_package.clone().into()])
        .await
        .unwrap();
    alice_group.merge_pending_commit(backend).await.unwrap();
    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .await
    .unwrap();
    // alice proposes to add charlie
    let (_, reference) = alice_group
        .propose_add_member(backend, &alice_signer, charlie_key_package.clone().into())
        .await
        .unwrap();

    assert_eq!(alice_group.proposal_store.proposals().count(), 1);
    // clearing the proposal by reference
    alice_group
        .remove_pending_proposal(backend.key_store(), &reference)
        .await
        .unwrap();
    assert!(alice_group.proposal_store.is_empty());

    // the proposal should not be stored anymore
    let err = alice_group
        .remove_pending_proposal(backend.key_store(), &reference)
        .await
        .unwrap_err();
    assert_eq!(err, MlsGroupStateError::PendingProposalNotFound);

    // the commit should have no proposal
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(backend, &alice_signer)
        .await
        .unwrap();
    let msg = bob_group
        .process_message(backend, MlsMessageIn::from(commit))
        .await
        .unwrap();
    match msg.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            // assert that no proposal was commited
            assert!(commit.add_proposals().next().is_none());
            assert!(commit.update_proposals().next().is_none());
            assert!(commit.remove_proposals().next().is_none());
            assert!(commit.psk_proposals().next().is_none());
            assert_eq!(alice_group.members().count(), 2);
        }
        _ => unreachable!("Expected a StagedCommit."),
    }
}
