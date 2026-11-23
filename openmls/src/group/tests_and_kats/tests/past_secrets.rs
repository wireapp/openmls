//! This module contains tests regarding the use of [`MessageSecretsStore`] in [`MlsGroup`]

use crate::framing::SecretTreeError;
use crate::group::tests_and_kats::utils::{generate_credential_with_key, generate_key_package};
use crate::{
    credentials::NewSignerBundle,
    framing::{MessageDecryptionError, MlsMessageIn, ProcessedMessageContent},
    group::*,
    treesync::LeafNodeParameters,
};

#[openmls_test::openmls_test]
fn test_past_secrets_in_group<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) {
    let alice_provider = &mut Provider::default();
    let bob_provider = &mut Provider::default();

    // Test this for different parameters
    for max_epochs in (0..10usize).step_by(2) {
        let group_id = GroupId::random(alice_provider.rand());

        // Generate credentials
        let alice_credential_with_keys = generate_credential_with_key(
            b"Alice".to_vec(),
            ciphersuite.signature_algorithm(),
            alice_provider,
        );
        let bob_credential_with_keys = generate_credential_with_key(
            b"Bob".to_vec(),
            ciphersuite.signature_algorithm(),
            bob_provider,
        );

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            bob_provider,
            bob_credential_with_keys,
        );

        // Define the MlsGroup configuration
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .max_past_epochs(max_epochs / 2)
            .ciphersuite(ciphersuite)
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            alice_provider,
            &alice_credential_with_keys.signer,
            &mls_group_create_config,
            group_id.clone(),
            alice_credential_with_keys.credential_with_key.clone(),
        )
        .expect("An unexpected error occurred.");

        // Alice adds Bob
        let (_message, welcome, _group_info) = alice_group
            .add_members(
                alice_provider,
                &alice_credential_with_keys.signer,
                core::slice::from_ref(bob_key_package.key_package()),
            )
            .expect("An unexpected error occurred.");

        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging pending commit");

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected message to be a welcome");

        let mut bob_group = StagedWelcome::new_from_welcome(
            bob_provider,
            mls_group_create_config.join_config(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating staged join from Welcome")
        .into_group(bob_provider)
        .expect("Error creating group from staged join");

        // Generate application message for different epochs

        let mut application_messages = Vec::new();
        let mut update_commits = Vec::new();

        for _ in 0..max_epochs {
            let application_message = alice_group
                .create_message(
                    alice_provider,
                    &alice_credential_with_keys.signer,
                    &[1, 2, 3],
                )
                .expect("An unexpected error occurred.");

            application_messages.push(application_message.into_protocol_message().unwrap());

            let (message, _welcome, _group_info) = alice_group
                .self_update(
                    alice_provider,
                    &alice_credential_with_keys.signer,
                    LeafNodeParameters::default(),
                )
                .expect("An unexpected error occurred.")
                .into_contents();

            update_commits.push(message.clone());

            alice_group
                .merge_pending_commit(alice_provider)
                .expect("error merging pending commit");
        }

        // Bob processes all update commits

        for update_commit in update_commits {
            let bob_processed_message = bob_group
                .process_message(bob_provider, update_commit.into_protocol_message().unwrap())
                .expect("An unexpected error occurred.");

            if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                bob_processed_message.into_content()
            {
                bob_group
                    .merge_staged_commit(bob_provider, *staged_commit)
                    .expect("Error merging commit.");
            } else {
                unreachable!("Expected a StagedCommit.");
            }
        }

        // === Test application messages from older epochs ===

        let mut bob_group = MlsGroup::load(bob_provider.storage(), &group_id)
            .expect("error re-loading bob's group")
            .expect("no such group");

        // The first messages should fail
        for application_message in application_messages.iter().take(max_epochs / 2) {
            let err = bob_group
                .process_message(bob_provider, application_message.clone())
                .expect_err("An unexpected error occurred.");
            assert!(matches!(
                err,
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)
                ),)
            ));
        }

        // The last messages should not fail
        for application_message in application_messages.iter().skip(max_epochs / 2) {
            let bob_processed_message = bob_group
                .process_message(bob_provider, application_message.clone())
                .expect("An unexpected error occurred.");

            if let ProcessedMessageContent::ApplicationMessage(application_message) =
                bob_processed_message.into_content()
            {
                assert_eq!(application_message.into_bytes(), &[1, 2, 3]);
            } else {
                unreachable!("Expected an ApplicationMessage.");
            }
        }
    }
}

/// The signature key of a message from a past epoch is the key the sender had
/// in that epoch, not the one they have since rotated to.
#[openmls_test::openmls_test]
fn past_epoch_message_reports_the_signature_key_of_its_epoch<
    Provider: crate::storage::OpenMlsProvider,
>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let alice_old = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let alice_new = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let bob_credential_with_keys = generate_credential_with_key(
        b"Bob".to_vec(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        bob_provider,
        bob_credential_with_keys,
    );

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .max_past_epochs(1)
        .ciphersuite(ciphersuite)
        .build();

    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_old.signer,
        &mls_group_create_config,
        alice_old.credential_with_key.clone(),
    )
    .expect("error creating group");
    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_old.signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .expect("error adding bob");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    let welcome = MlsMessageIn::from(welcome)
        .into_welcome()
        .expect("expected a welcome");
    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("error staging welcome")
    .into_group(bob_provider)
    .expect("error creating group from welcome");

    // Alice sends a message, then rotates her signature key.
    let old_epoch_message = alice_group
        .create_message(alice_provider, &alice_old.signer, b"old")
        .expect("error creating message")
        .into_protocol_message()
        .expect("expected a protocol message");
    let commit = alice_group
        .self_update_with_new_signer(
            alice_provider,
            &alice_old.signer,
            NewSignerBundle {
                signer: &alice_new.signer,
                credential_with_key: alice_new.credential_with_key.clone(),
            },
            LeafNodeParameters::default(),
        )
        .expect("error rotating signature key")
        .into_commit();
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");
    let new_epoch_message = alice_group
        .create_message(alice_provider, &alice_new.signer, b"new")
        .expect("error creating message")
        .into_protocol_message()
        .expect("expected a protocol message");

    let processed = bob_group
        .process_message(
            bob_provider,
            MlsMessageIn::from(commit)
                .into_protocol_message()
                .expect("expected a protocol message"),
        )
        .expect("error processing commit");
    assert_eq!(
        processed.signature_key(),
        &alice_old.credential_with_key.signature_key
    );
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) = processed.into_content()
    else {
        unreachable!("expected a staged commit");
    };
    bob_group
        .merge_staged_commit(bob_provider, *staged_commit)
        .expect("error merging commit");

    let processed = bob_group
        .process_message(bob_provider, old_epoch_message)
        .expect("error processing message from the past epoch");
    assert_eq!(
        processed.signature_key(),
        &alice_old.credential_with_key.signature_key
    );

    let processed = bob_group
        .process_message(bob_provider, new_epoch_message)
        .expect("error processing message from the current epoch");
    assert_eq!(
        processed.signature_key(),
        &alice_new.credential_with_key.signature_key
    );
}
