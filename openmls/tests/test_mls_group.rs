use openmls::{
    prelude::{config::CryptoConfig, test_utils::new_credential, *},
    test_utils::*,
};

use openmls_traits::{key_store::OpenMlsKeyStore, signatures::Signer, OpenMlsCryptoProvider};

async fn generate_key_package<KeyStore: OpenMlsKeyStore>(
    ciphersuite: Ciphersuite,
    extensions: Extensions,
    backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    credential_with_key: CredentialWithKey,
    signer: &impl Signer,
) -> KeyPackage {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            signer,
            credential_with_key,
        )
        .await
        .unwrap()
}

/// This test simulates various group operations like Add, Update, Remove in a
/// small group
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob updates and commits
///  - Alice updates and commits
///  - Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
///  - Alice removes Charlie and adds Bob
///  - Bob leaves
///  - Test saving the group state
#[apply(ciphersuites_and_backends)]
async fn mls_group_operations(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let group_id = GroupId::from_slice(b"Test Group");

        // Generate credentials with keys
        let (alice_credential, alice_signer) =
            new_credential(backend, b"Alice", ciphersuite.signature_algorithm()).await;

        let (bob_credential, bob_signer) =
            new_credential(backend, b"Bob", ciphersuite.signature_algorithm()).await;

        let (charlie_credential, charlie_signer) =
            new_credential(backend, b"Charlie", ciphersuite.signature_algorithm()).await;

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            backend,
            bob_credential.clone(),
            &bob_signer,
        )
        .await;

        // Define the MlsGroup configuration

        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(*wire_format_policy)
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &alice_signer,
            &mls_group_config,
            group_id.clone(),
            alice_credential.clone(),
        )
        .await
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let welcome = match alice_group
            .add_members(backend, &alice_signer, vec![bob_key_package.into()])
            .await
        {
            Ok((_, welcome, _)) => welcome,
            Err(e) => panic!("Could not add member to group: {e:?}"),
        };

        // Check that we received the correct proposals
        if let Some(staged_commit) = alice_group.pending_commit() {
            let add = staged_commit
                .add_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was added
            assert_eq!(
                add.add_proposal().key_package().leaf_node().credential(),
                &bob_credential.credential
            );
            // Check that Alice added Bob
            assert!(
                matches!(add.sender(), Sender::Member(member) if *member == alice_group.own_leaf_index())
            );
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit(backend)
            .await
            .expect("error merging pending commit");

        // Check that the group now has two members
        assert_eq!(alice_group.members().count(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");

        let mut bob_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome.into_welcome().expect("Unexpected message type."),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .await
        .expect("Error creating group from Welcome");

        // Make sure that both groups have the same members
        assert!(alice_group.members().eq(bob_group.members()));

        // Make sure that both groups have the same epoch authenticator
        assert_eq!(
            alice_group.epoch_authenticator().as_slice(),
            bob_group.epoch_authenticator().as_slice()
        );

        // === Alice sends a message to Bob ===
        let message_alice = b"Hi, I'm Alice!";
        let queued_message = alice_group
            .create_message(backend, &alice_signer, message_alice)
            .expect("Error creating application message");

        let processed_message = bob_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");
        let sender = processed_message.credential().clone();

        // Check that we received the correct message
        if let ProcessedMessageContent::ApplicationMessage(application_message) =
            processed_message.into_content()
        {
            // Check the message
            assert_eq!(application_message.into_bytes(), message_alice);
            // Check that Alice sent the message
            assert_eq!(
                &sender.credential,
                alice_group
                    .credential()
                    .expect("An unexpected error occurred.")
            );
        } else {
            unreachable!("Expected an ApplicationMessage.");
        }

        // === Bob updates and commits ===
        let (queued_message, welcome_option, _group_info) =
            bob_group.self_update(backend, &bob_signer).await.unwrap();

        let alice_processed_message = alice_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");

        // Check that we received the correct message
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            // Merge staged Commit
            alice_group
                .merge_staged_commit(backend, *staged_commit)
                .await
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        bob_group
            .merge_pending_commit(backend)
            .await
            .expect("error merging pending commit");

        // Check we didn't receive a Welcome message
        assert!(welcome_option.is_none());

        // Check that both groups have the same state
        assert_eq!(
            alice_group.export_secret(backend, "", &[], 32),
            bob_group.export_secret(backend, "", &[], 32)
        );

        // Make sure that both groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree()
        );

        // === Alice updates and commits ===
        let (queued_message, _) = alice_group
            .propose_self_update(backend, &alice_signer)
            .await
            .unwrap();

        let bob_processed_message = bob_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            bob_processed_message.into_content()
        {
            if let Proposal::Update(ref update_proposal) = staged_proposal.proposal() {
                // Check that Alice updated
                assert_eq!(
                    update_proposal.leaf_node().credential(),
                    &alice_credential.credential
                );
                // Store proposal
                alice_group.store_pending_proposal(*staged_proposal.clone());
            } else {
                unreachable!("Expected a Proposal.");
            }

            // Check that Alice sent the proposal.
            assert!(matches!(
                staged_proposal.sender(),
                Sender::Member(member) if *member == alice_group.own_leaf_index()
            ));

            bob_group.store_pending_proposal(*staged_proposal);
        } else {
            unreachable!("Expected a QueuedProposal.");
        }

        let (queued_message, _welcome_option, _group_info) = alice_group
            .commit_to_pending_proposals(backend, &alice_signer)
            .await
            .unwrap();

        let bob_processed_message = bob_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");

        // Check that we received the correct message
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            bob_group
                .merge_staged_commit(backend, *staged_commit)
                .await
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit(backend)
            .await
            .expect("error merging pending commit");

        // Check that both groups have the same state
        assert_eq!(
            alice_group.export_secret(backend, "", &[], 32),
            bob_group.export_secret(backend, "", &[], 32)
        );

        // Make sure that both groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree()
        );

        // === Bob adds Charlie ===
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            backend,
            charlie_credential,
            &charlie_signer,
        )
        .await;

        let (queued_message, welcome, _group_info) = bob_group
            .add_members(backend, &bob_signer, vec![charlie_key_package.into()])
            .await
            .unwrap();

        let alice_processed_message = alice_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");
        bob_group
            .merge_pending_commit(backend)
            .await
            .expect("error merging pending commit");

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            alice_group
                .merge_staged_commit(backend, *staged_commit)
                .await
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        let mut charlie_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome.into_welcome().expect("Unexpected message type."),
            Some(bob_group.export_ratchet_tree().into()),
        )
        .await
        .expect("Error creating group from Welcome");

        // Make sure that all groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree(),
        );
        assert_eq!(
            alice_group.export_ratchet_tree(),
            charlie_group.export_ratchet_tree()
        );

        // Check that Alice, Bob & Charlie are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");
        assert_eq!(members[2].credential.identity(), b"Charlie");

        // === Charlie sends a message to the group ===
        let message_charlie = b"Hi, I'm Charlie!";
        let queued_message = charlie_group
            .create_message(backend, &charlie_signer, message_charlie)
            .expect("Error creating application message");

        let _alice_processed_message = alice_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");
        let _bob_processed_message = bob_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");

        // === Charlie updates and commits ===
        let (queued_message, welcome_option, _group_info) = charlie_group
            .self_update(backend, &charlie_signer)
            .await
            .unwrap();

        let alice_processed_message = alice_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");
        let bob_processed_message = bob_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");
        charlie_group
            .merge_pending_commit(backend)
            .await
            .expect("error merging pending commit");

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            alice_group
                .merge_staged_commit(backend, *staged_commit)
                .await
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            bob_group
                .merge_staged_commit(backend, *staged_commit)
                .await
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check we didn't receive a Welcome message
        assert!(welcome_option.is_none());

        // Check that all groups have the same state
        assert_eq!(
            alice_group.export_secret(backend, "", &[], 32),
            bob_group.export_secret(backend, "", &[], 32)
        );
        assert_eq!(
            alice_group.export_secret(backend, "", &[], 32),
            charlie_group.export_secret(backend, "", &[], 32)
        );

        // Make sure that all groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree(),
        );
        assert_eq!(
            alice_group.export_ratchet_tree(),
            charlie_group.export_ratchet_tree()
        );

        // === Charlie removes Bob ===
        println!(" >>> Charlie is removing bob");
        let (queued_message, welcome_option, _group_info) = charlie_group
            .remove_members(backend, &charlie_signer, &[bob_group.own_leaf_index()])
            .await
            .expect("Could not remove member from group.");

        // Check that Bob's group is still active
        assert!(bob_group.is_active());

        let alice_processed_message = alice_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");
        let bob_processed_message = bob_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");
        charlie_group
            .merge_pending_commit(backend)
            .await
            .expect("error merging pending commit");

        // Check that we receive the correct proposal for Alice
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            let remove = staged_commit
                .remove_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was removed
            assert_eq!(remove.remove_proposal().removed(), members[1].index);
            // Check that Charlie removed Bob
            assert!(
                matches!(remove.sender(), Sender::Member(member) if *member == members[2].index)
            );

            // Merge staged Commit
            alice_group
                .merge_staged_commit(backend, *staged_commit)
                .await
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check that we receive the correct proposal for Alice
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            let remove = staged_commit
                .remove_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was removed
            assert_eq!(remove.remove_proposal().removed(), members[1].index);
            // Check that Charlie removed Bob
            assert!(
                matches!(remove.sender(), Sender::Member(member) if *member == members[2].index)
            );

            // Merge staged Commit
            bob_group
                .merge_staged_commit(backend, *staged_commit)
                .await
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check we didn't receive a Welcome message
        assert!(welcome_option.is_none());

        // Check that Bob's group is no longer active
        assert!(!bob_group.is_active());

        // Make sure that all groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            charlie_group.export_ratchet_tree()
        );

        // Make sure the group only contains two members
        assert_eq!(alice_group.members().count(), 2);

        // Check that Alice & Charlie are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Charlie");

        // Check that Bob can no longer send messages
        assert!(bob_group
            .create_message(backend, &bob_signer, b"Should not go through")
            .is_err());

        // === Alice removes Charlie and re-adds Bob ===

        // Create a new KeyPackageBundle for Bob
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            backend,
            bob_credential.clone(),
            &bob_signer,
        )
        .await;

        // Create RemoveProposal and process it
        let (queued_message, _) = alice_group
            .propose_remove_member(backend, &alice_signer, charlie_group.own_leaf_index())
            .expect("Could not create proposal to remove Charlie");

        let charlie_processed_message = charlie_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            charlie_processed_message.into_content()
        {
            if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
                // Check that Charlie was removed
                assert_eq!(remove_proposal.removed(), members[1].index);
                // Store proposal
                charlie_group.store_pending_proposal(*staged_proposal.clone());
            } else {
                unreachable!("Expected a Proposal.");
            }

            // Check that Alice removed Charlie
            assert!(matches!(
                staged_proposal.sender(),
                Sender::Member(member) if *member == members[0].index
            ));
        } else {
            unreachable!("Expected a QueuedProposal.");
        }

        // Create AddProposal and process it
        let (queued_message, _) = alice_group
            .propose_add_member(backend, &alice_signer, bob_key_package.into())
            .await
            .expect("Could not create proposal to add Bob");

        let charlie_processed_message = charlie_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            charlie_processed_message.into_content()
        {
            if let Proposal::Add(add_proposal) = staged_proposal.proposal() {
                // Check that Bob was added
                assert_eq!(
                    add_proposal.key_package().leaf_node().credential(),
                    &bob_credential.credential
                );
            } else {
                unreachable!("Expected an AddProposal.");
            }

            // Check that Alice added Bob
            assert!(matches!(
                staged_proposal.sender(),
                Sender::Member(member) if *member == members[0].index
            ));
            // Store proposal
            charlie_group.store_pending_proposal(*staged_proposal);
        } else {
            unreachable!("Expected a QueuedProposal.");
        }

        // Commit to the proposals and process it
        let (queued_message, welcome_option, _group_info) = alice_group
            .commit_to_pending_proposals(backend, &alice_signer)
            .await
            .expect("Could not flush proposals");

        let charlie_processed_message = charlie_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");

        // Merge Commit
        alice_group
            .merge_pending_commit(backend)
            .await
            .expect("error merging pending commit");

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            charlie_processed_message.into_content()
        {
            charlie_group
                .merge_staged_commit(backend, *staged_commit)
                .await
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Make sure the group contains two members
        assert_eq!(alice_group.members().count(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");

        // Bob creates a new group
        let mut bob_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome_option
                .expect("Welcome was not returned")
                .into_welcome()
                .expect("Unexpected message type."),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .await
        .expect("Error creating group from Welcome");

        // Make sure the group contains two members
        assert_eq!(alice_group.members().count(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");

        // Make sure the group contains two members
        assert_eq!(bob_group.members().count(), 2);

        // Check that Alice & Bob are the members of the group
        let members = bob_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");

        // === Alice sends a message to the group ===
        let message_alice = b"Hi, I'm Alice!";
        let queued_message = alice_group
            .create_message(backend, &alice_signer, message_alice)
            .expect("Error creating application message");

        let bob_processed_message = bob_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");
        let sender = bob_processed_message.credential().clone();

        // Check that we received the correct message
        if let ProcessedMessageContent::ApplicationMessage(application_message) =
            bob_processed_message.into_content()
        {
            // Check the message
            assert_eq!(application_message.into_bytes(), message_alice);
            // Check that Alice sent the message
            assert_eq!(
                &sender.credential,
                alice_group.credential().expect("Expected a credential")
            );
        } else {
            unreachable!("Expected an ApplicationMessage.");
        }

        // === Bob leaves the group ===

        let queued_message = bob_group
            .leave_group(backend, &bob_signer)
            .expect("Could not leave group");

        let alice_processed_message = alice_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");

        // Store proposal
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            alice_processed_message.into_content()
        {
            // Store proposal
            alice_group.store_pending_proposal(*staged_proposal);
        } else {
            unreachable!("Expected a QueuedProposal.");
        }

        // Should fail because you cannot remove yourself from a group
        assert!(matches!(
            bob_group
                .commit_to_pending_proposals(backend, &bob_signer)
                .await,
            Err(CommitToPendingProposalsError::CreateCommitError(
                CreateCommitError::CannotRemoveSelf
            ))
        ));

        let (queued_message, _welcome_option, _group_info) = alice_group
            .commit_to_pending_proposals(backend, &alice_signer)
            .await
            .expect("Could not commit to proposals.");

        // Check that Bob's group is still active
        assert!(bob_group.is_active());

        // Check that we received the correct proposals
        let bob_leaf_index = bob_group.own_leaf_index();
        if let Some(staged_commit) = alice_group.pending_commit() {
            let remove = staged_commit
                .remove_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was removed
            assert_eq!(remove.remove_proposal().removed(), bob_leaf_index);
            // Check that Bob removed himself
            assert!(matches!(remove.sender(), Sender::Member(member) if *member == bob_leaf_index));

            // Merge staged Commit
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit(backend)
            .await
            .expect("Could not merge Commit.");

        let bob_processed_message = bob_group
            .process_message(
                backend,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .await
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            let remove = staged_commit
                .remove_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was removed
            assert_eq!(remove.remove_proposal().removed(), bob_leaf_index);
            // Check that Bob removed himself
            assert!(matches!(remove.sender(), Sender::Member(member) if *member == bob_leaf_index));

            assert!(staged_commit.self_removed());
            // Merge staged Commit
            bob_group
                .merge_staged_commit(backend, *staged_commit)
                .await
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check that Bob's group is no longer active
        assert!(!bob_group.is_active());

        // Make sure the group contains one member
        assert_eq!(alice_group.members().count(), 1);

        // Check that Alice is the only member of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");

        // === Save the group state ===

        // Create a new KeyPackageBundle for Bob
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            backend,
            bob_credential,
            &bob_signer,
        )
        .await;

        // Add Bob to the group
        let (_queued_message, welcome, _group_info) = alice_group
            .add_members(backend, &alice_signer, vec![bob_key_package.into()])
            .await
            .expect("Could not add Bob");

        // Test saving & loading the group state when there is a pending commit
        alice_group
            .save(backend)
            .await
            .expect("Could not save group state.");

        let _test_group = MlsGroup::load(&group_id, backend)
            .await
            .expect("Could not load the group state.");

        // Merge Commit
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
        .expect("Could not create group from Welcome");

        assert_eq!(
            alice_group.export_secret(backend, "before load", &[], 32),
            bob_group.export_secret(backend, "before load", &[], 32)
        );

        // Check that the state flag gets reset when saving
        assert_eq!(bob_group.state_changed(), InnerState::Changed);

        bob_group
            .save(backend)
            .await
            .expect("Could not write group state to file");

        // Check that the state flag gets reset when saving
        assert_eq!(bob_group.state_changed(), InnerState::Persisted);

        let bob_group = MlsGroup::load(&group_id, backend)
            .await
            .expect("Could not load group from file");

        // Make sure the state is still the same
        assert_eq!(
            alice_group.export_secret(backend, "after load", &[], 32),
            bob_group.export_secret(backend, "after load", &[], 32)
        );
    }
}

#[apply(ciphersuites_and_backends)]
async fn test_empty_input_errors(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credentials with keys
    let (alice_credential, alice_signer) =
        new_credential(backend, b"Alice", ciphersuite.signature_algorithm()).await;

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &alice_signer,
        &mls_group_config,
        group_id,
        alice_credential,
    )
    .await
    .expect("An unexpected error occurred.");

    assert!(matches!(
        alice_group
            .add_members(backend, &alice_signer, vec![])
            .await
            .expect_err("No EmptyInputError when trying to pass an empty slice to `add_members`."),
        AddMembersError::EmptyInput(EmptyInputError::AddMembers)
    ));
    assert!(matches!(
        alice_group
            .remove_members(backend, &alice_signer, &[])
            .await
            .expect_err(
                "No EmptyInputError when trying to pass an empty slice to `remove_members`."
            ),
        RemoveMembersError::EmptyInput(EmptyInputError::RemoveMembers)
    ));
}

// This tests the ratchet tree extension usage flag in the configuration
#[apply(ciphersuites_and_backends)]
async fn mls_group_ratchet_tree_extension(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let group_id = GroupId::from_slice(b"Test Group");

        // === Positive case: using the ratchet tree extension ===

        // Generate credentials
        let (alice_credential, alice_signer) =
            new_credential(backend, b"Alice", ciphersuite.signature_algorithm()).await;

        let (bob_credential, bob_signer) =
            new_credential(backend, b"Bob", ciphersuite.signature_algorithm()).await;

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            backend,
            bob_credential,
            &bob_signer,
        )
        .await;

        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(*wire_format_policy)
            .use_ratchet_tree_extension(true)
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &alice_signer,
            &mls_group_config,
            group_id.clone(),
            alice_credential.clone(),
        )
        .await
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let (_queued_message, welcome, _group_info) = alice_group
            .add_members(backend, &alice_signer, vec![bob_key_package.into()])
            .await
            .unwrap();

        // === Bob joins using the ratchet tree extension ===
        let _bob_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome.into_welcome().expect("Unexpected message type."),
            None,
        )
        .await
        .expect("Error creating group from Welcome");

        // === Negative case: not using the ratchet tree extension ===

        // Generate credentials with keys
        let (alice_credential, alice_signer) =
            new_credential(backend, b"Alice", ciphersuite.signature_algorithm()).await;

        let (bob_credential, bob_signer) =
            new_credential(backend, b"Bob", ciphersuite.signature_algorithm()).await;

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            backend,
            bob_credential,
            &bob_signer,
        )
        .await;

        let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &alice_signer,
            &mls_group_config,
            group_id,
            alice_credential.clone(),
        )
        .await
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let (_queued_message, welcome, _group_info) = alice_group
            .add_members(backend, &alice_signer, vec![bob_key_package.into()])
            .await
            .unwrap();

        // === Bob tries to join without the ratchet tree extension ===
        let error = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome.into_welcome().expect("Unexpected message type."),
            None,
        )
        .await
        .expect_err("Could join a group without a ratchet tree");

        assert!(matches!(error, WelcomeError::MissingRatchetTree));
    }
}

#[apply(ciphersuites_and_backends)]
async fn addition_order(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let group_id = GroupId::from_slice(b"Test Group");
        // Generate credentials with keys
        let sc = ciphersuite.signature_algorithm();
        let (alice_credential, alice_signer) = new_credential(backend, b"Alice", sc).await;
        let (bob_credential, bob_signer) = new_credential(backend, b"Bob", sc).await;
        let (charlie_credential, charlie_signer) = new_credential(backend, b"Charlie", sc).await;

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            backend,
            bob_credential.clone(),
            &bob_signer,
        )
        .await;
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            backend,
            charlie_credential.clone(),
            &charlie_signer,
        )
        .await;

        // Define the MlsGroup configuration

        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(*wire_format_policy)
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &alice_signer,
            &mls_group_config,
            group_id.clone(),
            alice_credential.clone(),
        )
        .await
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let _welcome = match alice_group
            .add_members(
                backend,
                &alice_signer,
                vec![bob_key_package.into(), charlie_key_package.into()],
            )
            .await
        {
            Ok((_, welcome, _)) => welcome,
            Err(e) => panic!("Could not add member to group: {e:?}"),
        };

        // Check that the proposals are in the right order in the staged commit.
        if let Some(staged_commit) = alice_group.pending_commit() {
            let mut add_proposals = staged_commit.add_proposals();
            let add_bob = add_proposals.next().expect("Expected a proposal.");
            // Check that Bob is first
            assert_eq!(
                add_bob
                    .add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential(),
                &bob_credential.credential
            );
            let add_charlie = add_proposals.next().expect("Expected a proposal.");
            // Check that Charlie is second
            assert_eq!(
                add_charlie
                    .add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential(),
                &charlie_credential.credential
            );
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit(backend)
            .await
            .expect("error merging pending commit");

        // Check that the members got added in the same order as the KeyPackages
        // in the original API call. After merging, bob should be at index 1 and
        // charlie at index 2.
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[1].credential.identity(), b"Bob");
        assert_eq!(members[1].index, LeafNodeIndex::new(1));
        assert_eq!(members[2].credential.identity(), b"Charlie");
        assert_eq!(members[2].index, LeafNodeIndex::new(2));
    }
}
