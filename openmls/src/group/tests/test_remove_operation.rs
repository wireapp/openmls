//! This module tests the classification of remove operations with RemoveOperation

use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{credentials::*, framing::*, group::*, prelude::LeaveGroupError, test_utils::*, *};

use super::utils::{generate_credential_bundle, generate_key_package_bundle};

// Tests the different variants of the RemoveOperation enum.
#[apply(ciphersuites_and_backends)]
async fn test_remove_operation_variants(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // We define three test cases:
    // - one where the member is removed by another member
    // - one where the member leaves the group on its own
    // - one where the member leaves the group on its own and also removes others
    enum TestCase {
        Remove,
        Leave,
        LeaveAndRemoveOthers,
    }

    for test_case in [
        TestCase::Remove,
        TestCase::Leave,
        TestCase::LeaveAndRemoveOthers,
    ] {
        let group_id = GroupId::from_slice(b"Test Group");

        // Generate credential bundles
        let alice_credential = generate_credential_bundle(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .await
        .expect("An unexpected error occurred.");

        let bob_credential = generate_credential_bundle(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .await
        .expect("An unexpected error occurred.");

        let charlie_credential = generate_credential_bundle(
            "Charlie".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .await
        .expect("An unexpected error occurred.");

        // Generate KeyPackages
        let alice_key_package =
            generate_key_package_bundle(&[ciphersuite], &alice_credential, vec![], backend)
                .await
                .expect("An unexpected error occurred.");
        let bob_key_package =
            generate_key_package_bundle(&[ciphersuite], &bob_credential, vec![], backend)
                .await
                .expect("An unexpected error occurred.");
        let charlie_key_package =
            generate_key_package_bundle(&[ciphersuite], &charlie_credential, vec![], backend)
                .await
                .expect("An unexpected error occurred.");

        // Define the MlsGroup configuration
        let mls_group_config = MlsGroupConfig::default();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new(
            backend,
            &mls_group_config,
            group_id,
            alice_key_package
                .hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage.")
                .as_slice(),
        )
        .await
        .expect("An unexpected error occurred.");

        // === Alice adds Bob & Charlie ===

        let (_message, welcome) = alice_group
            .add_members(backend, &[bob_key_package, charlie_key_package])
            .await
            .expect("An unexpected error occurred.");
        alice_group
            .merge_pending_commit()
            .expect("error merging pending commit");

        let mut bob_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome.clone(),
            Some(alice_group.export_ratchet_tree()),
        )
        .await
        .expect("Error creating group from Welcome");

        let mut charlie_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome,
            Some(alice_group.export_ratchet_tree()),
        )
        .await
        .expect("Error creating group from Welcome");

        // === Remove operation ===

        let alice_kpr = *alice_group
            .key_package_ref()
            .expect("An unexpected error occurred.");
        let mut bob_kpr = *bob_group
            .key_package_ref()
            .expect("An unexpected error occurred.");
        let charlie_kpr = *charlie_group
            .key_package_ref()
            .expect("An unexpected error occurred.");

        // We differentiate between the three test cases here
        let (message, _welcome) = match test_case {
            // Alice removes Bob
            TestCase::Remove => alice_group
                .remove_members(backend, &[bob_kpr])
                .await
                .expect("Could not remove members."),
            // Bob leaves
            TestCase::Leave => {
                // Bob leaves the group
                let message = bob_group
                    .leave_group(backend)
                    .await
                    .expect("Could not leave group.");

                // Alice & Charlie store the pending proposal
                for group in [&mut alice_group, &mut charlie_group] {
                    let unverified_message = group
                        .parse_message(message.clone().into(), backend)
                        .expect("Could not parse message.");
                    let processed_message = group
                        .process_unverified_message(unverified_message, None, backend)
                        .await
                        .expect("Could not process unverified message.");

                    match processed_message {
                        ProcessedMessage::ProposalMessage(proposal) => {
                            group.store_pending_proposal(*proposal);
                        }
                        _ => unreachable!(),
                    }
                }

                // Alice commits to Bob's proposal
                alice_group
                    .commit_to_pending_proposals(backend)
                    .await
                    .expect("An unexpected error occurred.")
            }
            // Bob leaves and removes Charlie
            TestCase::LeaveAndRemoveOthers => {
                // Bob cannot remove himself in a commit
                let bob_tries_to_remove_self = bob_group
                    .leave_group_and_remove_others(backend, &[bob_kpr])
                    .await;
                assert_eq!(
                    bob_tries_to_remove_self.unwrap_err(),
                    LeaveGroupError::AttemptToRemoveSelf
                );

                // Bob leaves the group and also removes Charlie
                let (bob_remove_proposal, charlie_remove_commit) = bob_group
                    .leave_group_and_remove_others(backend, &[charlie_kpr])
                    .await
                    .expect("Could not leave group.");

                // Proposal must be for next epoch
                assert_eq!(
                    charlie_remove_commit.epoch().as_u64() + 1,
                    bob_remove_proposal.epoch().as_u64()
                );

                // Alice & Charlie process the commit
                for group in [&mut alice_group, &mut charlie_group] {
                    let unverified_message = group
                        .parse_message(charlie_remove_commit.clone().into(), backend)
                        .expect("Could not parse message.");
                    let processed_message = group
                        .process_unverified_message(unverified_message, None, backend)
                        .await
                        .expect("Could not process unverified message.");

                    match processed_message {
                        ProcessedMessage::StagedCommitMessage(commit) => {
                            group.merge_staged_commit(*commit).unwrap();
                        }
                        _ => unreachable!(),
                    }
                }

                // Charlie is no longer active
                assert!(!charlie_group.is_active());

                // Manually restore proposals in Bob's store
                let previous_bob_proposals =
                    bob_group.pending_proposals().cloned().collect::<Vec<_>>();
                bob_group.merge_pending_commit().unwrap();

                // Later used and since Bob merged the commit removing Charlie, Bob's KeyPackage
                // is likely to have changed
                bob_kpr = *bob_group.key_package_ref().unwrap();

                // Charlie is no longer in the group
                assert_eq!(bob_group.members().len(), 2);
                previous_bob_proposals
                    .into_iter()
                    .for_each(|p| bob_group.store_pending_proposal(p));

                // Alice store the pending proposal
                let unverified_message = alice_group
                    .parse_message(bob_remove_proposal.clone().into(), backend)
                    .expect("Could not parse message.");
                let processed_message = alice_group
                    .process_unverified_message(unverified_message, None, backend)
                    .await
                    .expect("Could not process unverified message.");

                match processed_message {
                    ProcessedMessage::ProposalMessage(proposal) => {
                        alice_group.store_pending_proposal(*proposal);
                    }
                    _ => unreachable!(),
                }

                // Alice commits to Bob's proposal
                alice_group
                    .commit_to_pending_proposals(backend)
                    .await
                    .expect("An unexpected error occurred.")
            }
        };

        // === Remove operation from Alice's perspective ===

        let alice_staged_commit = alice_group.pending_commit().expect("No pending commit.");

        let remove_proposal = alice_staged_commit
            .remove_proposals()
            .next()
            .expect("An unexpected error occurred.");

        let remove_operation = RemoveOperation::new(remove_proposal, &alice_group)
            .expect("An unexpected Error occurred.");

        match test_case {
            TestCase::Remove => {
                // We expect this variant, since Alice removed Bob
                match remove_operation {
                    RemoveOperation::WeRemovedThem(removed) => {
                        // Check that it was indeed Bob who was removed
                        assert_eq!(removed, bob_kpr);
                    }
                    _ => unreachable!(),
                }
            }
            TestCase::Leave | TestCase::LeaveAndRemoveOthers => {
                // We expect this variant, since Bob left
                match remove_operation {
                    RemoveOperation::TheyLeft(removed) => {
                        // Check that it was indeed Bob who left
                        assert_eq!(removed, bob_kpr);
                    }
                    _ => unreachable!(),
                }
            }
        }

        // === Remove operation from Bob's perspective ===

        let unverified_message = bob_group
            .parse_message(message.clone().into(), backend)
            .expect("Could not parse message.");
        let bob_processed_message = bob_group
            .process_unverified_message(unverified_message, None, backend)
            .await
            .expect("Could not process unverified message.");

        match bob_processed_message {
            ProcessedMessage::StagedCommitMessage(bob_staged_commit) => {
                let remove_proposal = bob_staged_commit
                    .remove_proposals()
                    .next()
                    .expect("An unexpected error occurred.");

                let remove_operation = RemoveOperation::new(remove_proposal, &bob_group)
                    .expect("An unexpected Error occurred.");

                match test_case {
                    TestCase::Remove => {
                        // We expect this variant, since Alice removed Bob
                        match remove_operation {
                            RemoveOperation::WeWereRemovedBy(sender) => {
                                // Make sure Alice is indeed a member
                                assert!(sender.is_member());
                                // Check Bob was removed
                                assert!(bob_staged_commit.self_removed());
                                match sender {
                                    Sender::Member(member) => {
                                        // Check that it was Alice who removed Bob
                                        assert_eq!(member, alice_kpr);
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    TestCase::Leave | TestCase::LeaveAndRemoveOthers => {
                        // We expect this variant, since Bob left
                        match remove_operation {
                            RemoveOperation::WeLeft => {
                                // Check that Bob is no longer part of the group
                                assert!(bob_staged_commit.self_removed());
                            }
                            _ => unreachable!(),
                        }
                    }
                }
            }
            _ => unreachable!(),
        }

        // === Remove operation from Charlie's perspective ===

        match test_case {
            TestCase::Remove | TestCase::Leave => {
                let unverified_message = charlie_group
                    .parse_message(message.into(), backend)
                    .expect("Could not parse message.");
                let charlie_processed_message = charlie_group
                    .process_unverified_message(unverified_message, None, backend)
                    .await
                    .expect("Could not process unverified message.");

                match charlie_processed_message {
                    ProcessedMessage::StagedCommitMessage(charlie_staged_commit) => {
                        let remove_proposal = charlie_staged_commit
                            .remove_proposals()
                            .next()
                            .expect("An unexpected error occurred.");

                        let remove_operation =
                            RemoveOperation::new(remove_proposal, &charlie_group)
                                .expect("An unexpected Error occurred.");

                        match test_case {
                            TestCase::Remove => {
                                // We expect this variant, since Alice removed Bob
                                match remove_operation {
                                    RemoveOperation::TheyWereRemovedBy((removed, sender)) => {
                                        // Make sure Alice is indeed a member
                                        assert!(sender.is_member());
                                        // Check that it was indeed Bob who was removed
                                        assert_eq!(removed, bob_kpr);
                                        match sender {
                                            Sender::Member(member) => {
                                                // Check that it was Alice who removed Bob
                                                assert_eq!(member, alice_kpr);
                                            }
                                            _ => unreachable!(),
                                        }
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            TestCase::Leave => {
                                // We expect this variant, since Bob left
                                match remove_operation {
                                    RemoveOperation::TheyLeft(removed) => {
                                        // Check that it was indeed Bob who left
                                        assert_eq!(removed, bob_kpr);
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            TestCase::LeaveAndRemoveOthers => unreachable!(),
                        }
                    }
                    _ => unreachable!(),
                }
            }
            TestCase::LeaveAndRemoveOthers => {
                // In this scenario Charlie's group is already inactive
                assert!(!charlie_group.is_active());
            }
        }
    }
}
