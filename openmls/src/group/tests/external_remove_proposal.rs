use openmls_rust_crypto::OpenMlsRustCrypto;
use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    framing::*,
    group::{config::CryptoConfig, errors::*, *},
    messages::external_proposals::*,
    prelude::ProtocolVersion,
};

use openmls_traits::types::Ciphersuite;

use super::utils::*;

// Creates a standalone group
fn new_test_group(
    identity: &str,
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let credential_with_keys =
        generate_credential_bundle(identity.into(), ciphersuite.signature_algorithm(), backend);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    (
        MlsGroup::new_with_group_id(
            backend,
            &credential_with_keys.signer,
            &mls_group_config,
            group_id,
            credential_with_keys.credential_with_key.clone(),
        )
        .unwrap(),
        credential_with_keys,
    )
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> MlsGroup {
    // === Alice creates a group ===
    let (mut alice_group, alice_signer_with_keys) =
        new_test_group("Alice", wire_format_policy, ciphersuite, backend);

    let bob_credential_bundle =
        generate_credential_bundle("Bob".into(), ciphersuite.signature_algorithm(), backend);

    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        backend,
        bob_credential_bundle,
    );

    alice_group
        .add_members(backend, &alice_signer_with_keys.signer, &[bob_key_package])
        .expect("error adding Bob to group");

    alice_group
        .merge_pending_commit(backend)
        .expect("error merging pending commit");

    alice_group
}

#[apply(ciphersuites_and_backends)]
fn external_remove_proposal_should_remove_member(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credential bundles
    let credential =
        generate_credential_bundle("Alice".into(), ciphersuite.signature_algorithm(), backend);

    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_bundle = generate_credential_bundle(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .crypto_config(CryptoConfig {
            ciphersuite,
            version: ProtocolVersion::default(),
        })
        .external_senders(vec![ExternalSender::new(
            ds_credential_bundle
                .credential_with_key
                .signature_key
                .clone(),
            ds_credential_bundle.credential_with_key.credential.clone(),
        )])
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &credential.signer,
        &mls_group_config,
        group_id,
        credential.credential_with_key.clone(),
    )
    .unwrap();

    // DS is an allowed external sender of the group
    assert!(alice_group
         .group()
         .group_context_extensions()
         .iter()
         .any(|e| matches!(e, Extension::ExternalSenders(senders) if senders.iter().any(|s| s.credential() == &ds_credential_bundle.credential_with_key.credential) )));

    // Generate credential bundles
    let bob_credential =
        generate_credential_bundle("Bob".into(), ciphersuite.signature_algorithm(), backend);

    // Generate KeyPackages
    let bob_key_package =
        generate_key_package(ciphersuite, Extensions::empty(), backend, bob_credential);

    // Adding Bob to the group
    let (_, welcome, _) = alice_group
        .add_members(backend, &credential.signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();

    // Alice & Bob are in the group
    assert_eq!(alice_group.members().count(), 2);

    let bob_group = MlsGroup::new_from_welcome(
        backend,
        &MlsGroupConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree()),
    )
    .unwrap();
    assert_eq!(bob_group.members().count(), 2);
    // Bob has external senders after joining from Welcome message
    assert!(bob_group
         .group()
         .group_context_extensions()
         .iter()
         .any(|e| matches!(e, Extension::ExternalSenders(senders) if senders.iter().any(|s| s.credential() == &ds_credential_bundle.credential_with_key.credential))));

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find_map(|member| {
            if member.credential.identity() == b"Bob" {
                Some(member.index)
            } else {
                None
            }
        })
        .unwrap();
    // Now Delivery Service wants to (already) remove Bob
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_bundle.signer,
        0,
    )
    .unwrap()
    .into();

    // Alice validates the message
    let processed_message = alice_group
        .process_message(backend, bob_external_remove_proposal)
        .unwrap();
    // commit the proposal
    let ProcessedMessageContent::ProposalMessage(remove_proposal) = processed_message.into_content() else { panic!("Not a remove proposal");};
    alice_group.store_pending_proposal(*remove_proposal);
    alice_group
        .commit_to_pending_proposals(backend, &credential.signer)
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();

    // Trying to do an external remove proposal of Bob now should fail as he no longer is in the group
    let invalid_bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        // Bob is no longer in the group
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_bundle.signer,
        0,
    )
    .unwrap()
    .into();
    let processed_message = alice_group
        .process_message(backend, invalid_bob_external_remove_proposal)
        .unwrap();
    // commit the proposal
    let ProcessedMessageContent::ProposalMessage(remove_proposal) = processed_message.into_content() else { panic!("Not a remove proposal");};
    alice_group.store_pending_proposal(*remove_proposal);
    assert_eq!(
        alice_group
            .commit_to_pending_proposals(backend, &credential.signer)
            .unwrap_err(),
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::UnknownMemberRemoval
            )
        )
    );
}

#[apply(ciphersuites_and_backends)]
fn external_remove_proposal_should_fail_with_invalid_external_senders_index(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credential bundles
    let credential =
        generate_credential_bundle("Alice".into(), ciphersuite.signature_algorithm(), backend);

    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_bundle = generate_credential_bundle(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .crypto_config(CryptoConfig {
            ciphersuite,
            version: ProtocolVersion::default(),
        })
        .external_senders(vec![ExternalSender::new(
            ds_credential_bundle
                .credential_with_key
                .signature_key
                .clone(),
            ds_credential_bundle.credential_with_key.credential.clone(),
        )])
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &credential.signer,
        &mls_group_config,
        group_id,
        credential.credential_with_key.clone(),
    )
    .unwrap();

    // Generate credential bundles
    let bob_credential =
        generate_credential_bundle("Bob".into(), ciphersuite.signature_algorithm(), backend);

    // Generate KeyPackages
    let bob_key_package =
        generate_key_package(ciphersuite, Extensions::empty(), backend, bob_credential);

    // Adding Bob to the group
    alice_group
        .add_members(backend, &credential.signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find_map(|member| {
            if member.credential.identity() == b"Bob" {
                Some(member.index)
            } else {
                None
            }
        })
        .unwrap();
    // Now Delivery Service wants to (already) remove Bob with invalid sender index
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_bundle.signer,
        10, // invalid sender index
    )
    .unwrap()
    .into();

    // Alice tries to validate the message and should fail as sender is invalid
    let error = alice_group
        .process_message(backend, bob_external_remove_proposal)
        .unwrap_err();
    assert_eq!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnauthorizedExternalSender)
    );
}

#[apply(ciphersuites_and_backends)]
fn external_remove_proposal_should_fail_with_invalid_external_senders(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credential bundles
    let credential =
        generate_credential_bundle("Alice".into(), ciphersuite.signature_algorithm(), backend);

    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_bundle = generate_credential_bundle(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    let ds_invalid_credential_bundle = generate_credential_bundle(
        "delivery-service-invalid".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .crypto_config(CryptoConfig {
            ciphersuite,
            version: ProtocolVersion::default(),
        })
        .external_senders(vec![ExternalSender::new(
            ds_credential_bundle
                .credential_with_key
                .signature_key
                .clone(),
            ds_credential_bundle.credential_with_key.credential.clone(),
        )])
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &credential.signer,
        &mls_group_config,
        group_id,
        credential.credential_with_key.clone(),
    )
    .unwrap();

    // Generate credential bundles
    let bob_credential =
        generate_credential_bundle("Bob".into(), ciphersuite.signature_algorithm(), backend);

    // Generate KeyPackages
    let bob_key_package =
        generate_key_package(ciphersuite, Extensions::empty(), backend, bob_credential);

    // Adding Bob to the group
    alice_group
        .add_members(backend, &credential.signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find_map(|member| {
            if member.credential.identity() == b"Bob" {
                Some(member.index)
            } else {
                None
            }
        })
        .unwrap();
    // Now Delivery Service wants to (already) remove Bob with invalid sender index
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_invalid_credential_bundle.signer,
        0,
    )
    .unwrap()
    .into();

    // Alice tries to validate the message and should fail as sender is invalid
    let error = alice_group
        .process_message(backend, bob_external_remove_proposal)
        .unwrap_err();
    assert_eq!(
        error,
        ProcessMessageError::ValidationError(ValidationError::InvalidSignature)
    );
}

#[apply(ciphersuites_and_backends)]
fn external_remove_proposal_should_fail_with_no_external_senders(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let mut alice_group =
        validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);
    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_bundle = generate_credential_bundle(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find_map(|member| {
            if member.credential.identity() == b"Bob" {
                Some(member.index)
            } else {
                None
            }
        })
        .unwrap();
    // Now Delivery Service wants to remove Bob with invalid sender index but there's no extension
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_bundle.signer,
        1, // invalid sender index
    )
    .unwrap()
    .into();

    // Alice tries to validate the message and should fail as sender is invalid
    let error = alice_group
        .process_message(backend, bob_external_remove_proposal)
        .unwrap_err();
    assert_eq!(
        error,
        ProcessMessageError::ValidationError(ValidationError::NoExternalSendersExtension)
    );
}
