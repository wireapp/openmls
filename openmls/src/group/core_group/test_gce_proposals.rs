use crate::{
    ciphersuite::signable::Signable,
    credentials::CredentialBundle,
    extensions::{Extension, ExtensionType, RequiredCapabilitiesExtension},
    framing::{
        FramingParameters, MlsMessageIn, MlsPlaintext, MlsPlaintextContentType, ProcessedMessage,
        VerifiableMlsPlaintext, WireFormat,
    },
    group::{errors::*, proposals::QueuedProposal, GroupId, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
    key_packages::{errors::KeyPackageExtensionSupportError, KeyPackageBundle},
    messages::proposals::Proposal,
    prelude::{
        CapabilitiesExtension, CreateCommitError, ExternalProposal, ExternalSendersExtension,
        GroupContextExtensionProposal, MlsGroup, MlsGroupConfig, ProposalOrRef, ProposalType,
        RatchetTreeExtension,
    },
    test_utils::*,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::Ciphersuite, OpenMlsCryptoProvider};
use std::borrow::BorrowMut;
use tls_codec::{Deserialize, Serialize};

use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

#[apply(ciphersuites_and_backends)]
async fn gce_are_forwarded_in_welcome(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities, ExtensionType::ExternalSenders],
        CapabilitiesExtension::default().proposals(),
    );
    // Bob has been created from a welcome message
    let (alice_group, bob_group, ..) = group_setup(
        ciphersuite.clone(),
        &[Extension::RequiredCapabilities(
            required_capabilities.clone(),
        )],
        vec![Extension::ExternalSenders(ExternalSendersExtension::from(
            &[],
        ))],
        backend,
    )
    .await;
    assert_eq!(
        alice_group.group_context_extensions(),
        &[
            Extension::RequiredCapabilities(required_capabilities),
            Extension::ExternalSenders(ExternalSendersExtension::from(&[]))
        ]
    );
    assert_eq!(
        alice_group.group_context_extensions(),
        bob_group.group_context_extensions()
    );
}

#[should_panic]
#[apply(ciphersuites_and_backends)]
async fn cannot_create_group_when_keypackage_lacks_required_capability(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    #[cfg(target_family = "wasm")]
    return;

    let required_capabilities = RequiredCapabilitiesExtension::new(
        // External senders is required...
        &[ExtensionType::Capabilities, ExtensionType::ExternalSenders],
        CapabilitiesExtension::default().proposals(),
    );
    let _ = group_setup(
        ciphersuite,
        &[Extension::RequiredCapabilities(required_capabilities)],
        // ...but not present in keypackage extensions
        vec![],
        backend,
    )
    .await;
}

#[apply(ciphersuites_and_backends)]
async fn gce_fails_when_it_contains_unsupported_extensions(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities],
        CapabilitiesExtension::default().proposals(),
    );
    // Bob has been created from a welcome message
    let (mut alice_group, mut bob_group, ..) = group_setup(
        ciphersuite.clone(),
        &[Extension::RequiredCapabilities(
            required_capabilities.clone(),
        )],
        vec![],
        backend,
    )
    .await;
    // Alice tries to add a required capability she doesn't support herself.
    let required_key_id = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[ExtensionType::ExternalSenders],
        &[],
    ));
    let e = alice_group.propose_extension(backend, &[required_key_id.clone()]).await
        .expect_err("Alice was able to create a gce proposal with a required extensions she doesn't support.");
    assert_eq!(
        e,
        CreateGroupContextExtProposalError::KeyPackageExtensionSupport(
            KeyPackageExtensionSupportError::UnsupportedExtension
        )
    );
    // Now Bob wants the ExternalSenders extension to be required.
    // This should fail because Alice doesn't support it.
    let e = bob_group
        .propose_extension(backend, &[required_key_id]).await
        .expect_err("Bob was able to create a gce proposal for an extension not supported by all other parties.");
    assert_eq!(
        e,
        CreateGroupContextExtProposalError::KeyPackageExtensionSupport(
            KeyPackageExtensionSupportError::UnsupportedExtension
        )
    );
}

#[apply(ciphersuites_and_backends)]
async fn gce_proposal_should_overwrite_previous(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let old_required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities, ExtensionType::ExternalSenders],
        &[
            ProposalType::Add,
            ProposalType::Update,
            ProposalType::Remove,
            ProposalType::Presharedkey,
            ProposalType::GroupContextExtensions,
        ],
    );
    let new_required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities, ExtensionType::Lifetime],
        &[
            ProposalType::Add,
            ProposalType::Update,
            ProposalType::Remove,
            ProposalType::Reinit,
            ProposalType::GroupContextExtensions,
        ],
    );

    let (mut alice_group, ..) = group_setup(
        ciphersuite.clone(),
        &[Extension::RequiredCapabilities(old_required_capabilities)],
        vec![Extension::ExternalSenders(ExternalSendersExtension::from(
            &[],
        ))],
        backend,
    )
    .await;

    // Alice adds a required capability.
    let new_extensions = [
        Extension::RequiredCapabilities(new_required_capabilities),
        Extension::RatchetTree(RatchetTreeExtension::new(vec![])),
    ];
    alice_group
        .propose_extension(backend, &new_extensions.clone())
        .await
        .unwrap();
    alice_group
        .commit_to_pending_proposals(backend)
        .await
        .unwrap();
    alice_group.merge_pending_commit().unwrap();
    assert_eq!(alice_group.group_context_extensions(), new_extensions);
}

#[apply(ciphersuites_and_backends)]
async fn gce_proposal_can_roundtrip(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities],
        CapabilitiesExtension::default().proposals(),
    );
    let (mut alice_group, mut bob_group, ..) = group_setup(
        ciphersuite.clone(),
        &[Extension::RequiredCapabilities(required_capabilities)],
        vec![],
        backend,
    )
    .await;

    // Alice adds an extension
    let new_extensions = [Extension::RatchetTree(RatchetTreeExtension::new(vec![]))];
    let (gce_proposal, ..) = alice_group
        .propose_extension(backend, &new_extensions.clone())
        .await
        .unwrap();
    let unverified_message = bob_group
        .parse_message(gce_proposal.clone().into(), backend)
        .unwrap();
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .await
        .unwrap();
    bob_group.store_pending_proposal(
        QueuedProposal::from_mls_message(ciphersuite, backend, gce_proposal.mls_message).unwrap(),
    );
    let (commit, ..) = bob_group
        .commit_to_pending_proposals(backend)
        .await
        .unwrap();
    bob_group.merge_pending_commit().unwrap();
    assert_eq!(bob_group.group_context_extensions(), new_extensions);

    let unverified_message = alice_group.parse_message(commit.into(), backend).unwrap();
    let message = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .await
        .unwrap();
    if let ProcessedMessage::StagedCommitMessage(staged_commit) = message {
        alice_group.merge_staged_commit(*staged_commit).unwrap()
    }
    assert_eq!(alice_group.group_context_extensions(), new_extensions);
}

#[apply(ciphersuites_and_backends)]
async fn creating_commit_with_more_than_one_gce_proposal_should_fail(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities],
        CapabilitiesExtension::default().proposals(),
    );
    let (mut alice_group, ..) = group_setup(
        ciphersuite.clone(),
        &[Extension::RequiredCapabilities(required_capabilities)],
        vec![],
        backend,
    )
    .await;

    // Alice creates a commit with 2 GroupContextExtension proposals, should fail
    let ratchet_tree = Extension::RatchetTree(RatchetTreeExtension::new(vec![]));
    alice_group
        .propose_extension(backend, &[ratchet_tree])
        .await
        .unwrap();
    let external_senders = Extension::ExternalSenders(ExternalSendersExtension::from(&[]));
    alice_group
        .propose_extension(backend, &[external_senders])
        .await
        .unwrap();
    assert_eq!(alice_group.pending_proposals().count(), 2);
    let commit = alice_group.commit_to_pending_proposals(backend).await;
    assert_eq!(
        commit.unwrap_err(),
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::TooManyGroupContextExtensions(2)
            )
        )
    );
}

// ValSem115
#[apply(ciphersuites_and_backends)]
async fn validating_commit_with_more_than_one_gce_proposal_should_fail(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities],
        CapabilitiesExtension::default().proposals(),
    );
    let (mut alice_group, mut bob_group, _, bob_credential_bundle, ..) = group_setup(
        ciphersuite.clone(),
        &[Extension::RequiredCapabilities(required_capabilities)],
        vec![],
        backend,
    )
    .await;

    // Alice creates a commit with 2 GroupContextExtension proposals, should fail
    let ratchet_tree = Extension::RatchetTree(RatchetTreeExtension::new(vec![]));
    let (first_gce_proposal, ..) = alice_group
        .propose_extension(backend, &[ratchet_tree])
        .await
        .unwrap();
    bob_group.store_pending_proposal(
        QueuedProposal::from_mls_message(ciphersuite, backend, first_gce_proposal.mls_message)
            .unwrap(),
    );

    // Bob creates a commit with just 1 GCE proposal
    let (commit, ..) = bob_group
        .commit_to_pending_proposals(backend)
        .await
        .unwrap();

    let serialized_commit = VerifiableMlsPlaintext::tls_deserialize(
        &mut commit.tls_serialize_detached().unwrap().as_slice(),
    )
    .unwrap()
    .tls_serialize_detached()
    .unwrap();

    let external_senders = Extension::ExternalSenders(ExternalSendersExtension::from(&[]));
    let second_proposal =
        Proposal::GroupContextExtensions(GroupContextExtensionProposal::new(&[external_senders]));

    // We create a fake commit with 2 GCE proposal by rewriting the commit message
    // because otherwise the library would prevent us to  do so
    let commit_with_2_gce_proposal: MlsMessageIn = add_gce_proposal_to_commit(
        &serialized_commit,
        &bob_group,
        &bob_credential_bundle,
        second_proposal,
        backend,
    )
    .await;

    let unverified_message = alice_group
        .parse_message(commit_with_2_gce_proposal, backend)
        .unwrap();
    let process = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .await;
    // Alice does not accept a commit with 2 GCE proposals
    assert_eq!(
        process.unwrap_err(),
        UnverifiedMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::TooManyGroupContextExtensions(2)
        ))
    );
}

#[apply(ciphersuites_and_backends)]
async fn gce_proposal_must_be_applied_first_then_used_to_validate_other_add_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities],
        CapabilitiesExtension::default().proposals(),
    );
    let external_senders = Extension::ExternalSenders(ExternalSendersExtension::from(&[]));
    // Alice & Bob both support ExternalSenders
    let (mut alice_group, mut bob_group, ..) = group_setup(
        ciphersuite.clone(),
        &[Extension::RequiredCapabilities(required_capabilities)],
        vec![external_senders.clone()],
        backend,
    )
    .await;

    // Propose to add ExternalSenders to RequiredCapabilities
    let new_required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Capabilities, ExtensionType::ExternalSenders],
            CapabilitiesExtension::default().proposals(),
        ));
    let (gce_proposal, ..) = alice_group
        .propose_extension(backend, &[new_required_capabilities])
        .await
        .unwrap();

    // Charlie does not have ExternalSenders in its extensions, hence it should fail to be added to the group
    let (_, charlie_key_package_bundle) =
        setup_client("Charlie", ciphersuite, vec![], backend).await;
    let (charlie_add_proposal, ..) = alice_group
        .propose_add_member(backend, charlie_key_package_bundle.key_package())
        .await
        .unwrap();

    bob_group.store_pending_proposal(
        QueuedProposal::from_mls_message(ciphersuite, backend, charlie_add_proposal.mls_message)
            .unwrap(),
    );
    bob_group.store_pending_proposal(
        QueuedProposal::from_mls_message(ciphersuite, backend, gce_proposal.mls_message).unwrap(),
    );
    assert_eq!(bob_group.pending_proposals().count(), 2);
    let commit = bob_group.commit_to_pending_proposals(backend).await;
    // Bob does not accept the commit since adding Charlie would go against GCE proposal
    assert_eq!(
        commit.unwrap_err(),
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::InsufficientCapabilities
            )
        )
    );
}

#[apply(ciphersuites_and_backends)]
async fn gce_proposal_must_be_applied_first_then_used_to_validate_other_external_add_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities],
        CapabilitiesExtension::default().proposals(),
    );
    let external_senders = Extension::ExternalSenders(ExternalSendersExtension::from(&[]));
    // Alice support ExternalSenders
    let (mut alice_group, ..) = group_setup(
        ciphersuite.clone(),
        &[Extension::RequiredCapabilities(
            required_capabilities.clone(),
        )],
        vec![external_senders.clone()],
        backend,
    )
    .await;

    // Propose to add ExternalSenders to RequiredCapabilities
    let new_required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Capabilities, ExtensionType::ExternalSenders],
            CapabilitiesExtension::default().proposals(),
        ));
    alice_group
        .propose_extension(backend, &[new_required_capabilities])
        .await
        .unwrap();

    // Charlie does not have ExternalSenders in its extensions, hence it should fail to be added to the group
    let (charlie_credential_bundle, charlie_key_package_bundle) =
        setup_client("Charlie", ciphersuite, vec![], backend).await;

    let charlie_add_proposal = ExternalProposal::new_add(
        charlie_key_package_bundle.key_package,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &charlie_credential_bundle,
        backend,
    )
    .unwrap();
    alice_group.store_pending_proposal(
        QueuedProposal::from_mls_message(ciphersuite, backend, charlie_add_proposal.mls_message)
            .unwrap(),
    );
    assert_eq!(alice_group.pending_proposals().count(), 2);
    let commit = alice_group.commit_to_pending_proposals(backend).await;
    // Alice refuses to add Charlie because it does not satisfy GCE proposal
    assert_eq!(
        commit.unwrap_err(),
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::InsufficientCapabilities
            )
        )
    );
}

#[apply(ciphersuites_and_backends)]
async fn gce_proposal_must_be_applied_first_but_ignored_for_remove_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities],
        CapabilitiesExtension::default().proposals(),
    );
    // Alice & Bob have ExternalSenders support even though it is not required
    let external_senders = Extension::ExternalSenders(ExternalSendersExtension::from(&[]));
    let (mut alice_group, mut bob_group, ..) = group_setup(
        ciphersuite.clone(),
        &[Extension::RequiredCapabilities(required_capabilities)],
        vec![external_senders],
        backend,
    )
    .await;

    // Charlie does not have ExternalSenders in its extensions
    let (_, charlie_key_package_bundle) =
        setup_client("Charlie", ciphersuite, vec![], backend).await;
    let (commit, ..) = alice_group
        .add_members(backend, &[charlie_key_package_bundle.key_package().clone()])
        .await
        .unwrap();
    let unverified_message = bob_group.parse_message(commit.into(), backend).unwrap();
    let commit = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .await
        .unwrap();
    if let ProcessedMessage::StagedCommitMessage(commit) = commit {
        bob_group.merge_staged_commit(*commit).unwrap();
    }
    alice_group.merge_pending_commit().unwrap();

    // Propose requiring ExternalSenders, which Charlie does not support
    let new_required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Capabilities, ExtensionType::ExternalSenders],
            CapabilitiesExtension::default().proposals(),
        ));

    let extension_proposal = alice_group
        .propose_extension(backend, &[new_required_capabilities.clone()])
        .await;
    // because group contains Charlie which is incompatible with new extensions
    assert!(extension_proposal.is_err());
    alice_group.clear_pending_proposals();

    let charlie_kpr = charlie_key_package_bundle
        .key_package
        .hash_ref(backend.crypto())
        .unwrap();
    let (charlie_remove_proposal, ..) = alice_group
        .propose_remove_member(backend, &charlie_kpr)
        .await
        .unwrap();

    // Bob is able to process remove proposal
    let unverified_message = bob_group
        .parse_message(charlie_remove_proposal.into(), backend)
        .unwrap();
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .await
        .unwrap();

    let extension_proposal = alice_group
        .propose_extension(backend, &[new_required_capabilities])
        .await;
    assert_eq!(alice_group.pending_proposals().count(), 2);
    // Charlie does not support this extension. But since Charlie is proposed for removal it should not fail.
    assert!(extension_proposal.is_ok());

    // Bob is able to process GCE proposal
    let unverified_message = bob_group
        .parse_message(extension_proposal.unwrap().0.into(), backend)
        .unwrap();
    let gce_message = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .await;
    // Bob accepts GCE proposal since it also has one for removing Charlie
    assert!(gce_message.is_ok());

    // Once validating proposals, it should not fail as even though Charlie does not support the new
    // required extensions, he is going to be removed from the group
    let commit = alice_group.commit_to_pending_proposals(backend).await;
    assert!(commit.is_ok());
    alice_group.merge_pending_commit().unwrap();
    assert_eq!(alice_group.members().len(), 2);
}

#[apply(ciphersuites_and_backends)]
async fn gce_proposal_must_be_applied_first_but_ignored_for_external_remove_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let (debbie_credential_bundle, _) = setup_client("Debbie", ciphersuite, vec![], backend).await;

    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Capabilities],
        CapabilitiesExtension::default().proposals(),
    );
    // Alice & Bob have ExternalSenders support even though it is not required
    let debbie_credential = debbie_credential_bundle.credential();
    let external_senders =
        Extension::ExternalSenders(ExternalSendersExtension::from(&[debbie_credential.clone().into()]));
    let (mut alice_group, ..) = group_setup(
        ciphersuite.clone(),
        &[
            Extension::RequiredCapabilities(required_capabilities),
            external_senders.clone(),
        ],
        vec![external_senders.clone()],
        backend,
    )
    .await;

    // Charlie does not have ExternalSenders in its extensions
    let (_, charlie_key_package_bundle) =
        setup_client("Charlie", ciphersuite, vec![], backend).await;
    alice_group
        .add_members(backend, &[charlie_key_package_bundle.key_package().clone()])
        .await
        .unwrap();
    alice_group.merge_pending_commit().unwrap();
    assert_eq!(alice_group.members().len(), 3);

    // Debbie (external) propose to remove Charlie
    let charlie_kpr = charlie_key_package_bundle
        .key_package
        .hash_ref(backend.crypto())
        .unwrap();
    let charlie_ext_remove_proposal = ExternalProposal::new_remove(
        charlie_kpr,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &debbie_credential_bundle,
        0,
        backend,
    )
    .unwrap();
    let unverified_message = alice_group
        .parse_message(charlie_ext_remove_proposal.clone().into(), backend)
        .unwrap();
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .await
        .unwrap();
    alice_group.store_pending_proposal(
        QueuedProposal::from_mls_message(
            ciphersuite,
            backend,
            charlie_ext_remove_proposal.mls_message,
        )
        .unwrap(),
    );

    // Propose requiring ExternalSenders, which Charlie does not support
    let new_required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Capabilities, ExtensionType::ExternalSenders],
            CapabilitiesExtension::default().proposals(),
        ));
    alice_group
        .propose_extension(backend, &[new_required_capabilities])
        .await
        .unwrap();
    // Once validating proposals, it should not fail as even though Charlie does not support the new
    // required extensions, he is going to be removed from the group
    let commit = alice_group.commit_to_pending_proposals(backend).await;
    assert!(commit.is_ok());
    alice_group.merge_pending_commit().unwrap();
    assert_eq!(alice_group.members().len(), 2);
}

async fn setup_client(
    id: &str,
    ciphersuite: Ciphersuite,
    kp_extensions: Vec<Extension>,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialBundle, KeyPackageBundle) {
    let credential_bundle =
        CredentialBundle::new_basic(id.into(), ciphersuite.signature_algorithm(), backend)
            .expect("An unexpected error occurred.");
    let cbh = credential_bundle
        .credential()
        .signature_key()
        .tls_serialize_detached()
        .unwrap();
    backend
        .key_store()
        .store(&cbh, &credential_bundle)
        .await
        .unwrap();
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, kp_extensions)
            .expect("An unexpected error occurred.");
    let kph = key_package_bundle
        .key_package
        .hash_ref(backend.crypto())
        .unwrap();
    backend
        .key_store()
        .store(kph.as_slice(), &key_package_bundle)
        .await
        .unwrap();
    (credential_bundle, key_package_bundle)
}

async fn group_setup<'a>(
    ciphersuite: Ciphersuite,
    extensions: &'a [Extension],
    kp_extensions: Vec<Extension>,
    backend: &'a impl OpenMlsCryptoProvider,
) -> (
    MlsGroup,
    MlsGroup,
    CredentialBundle,
    CredentialBundle,
    FramingParameters<'a>,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    let (alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, kp_extensions.clone(), backend).await;
    let (bob_credential_bundle, bob_key_package_bundle) =
        setup_client("Bob", ciphersuite, kp_extensions, backend).await;

    let required_capabilities = extensions
        .iter()
        .find_map(|e| e.as_required_capabilities_extension().ok())
        .unwrap()
        .clone();

    let external_senders = extensions
        .iter()
        .find_map(|e| e.as_external_senders_extension().ok())
        .cloned()
        .unwrap_or(ExternalSendersExtension::from(&[]));

    let cfg = MlsGroupConfig {
        wire_format_policy: PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        required_capabilities,
        external_senders,
        ..Default::default()
    };
    let kph = alice_key_package_bundle
        .key_package
        .hash_ref(backend.crypto())
        .unwrap();
    let mut alice_group = MlsGroup::new(backend, &cfg, GroupId::random(backend), kph.as_slice())
        .await
        .unwrap();

    let (_, welcome, ..) = alice_group
        .add_members(backend, &[bob_key_package_bundle.key_package().clone()])
        .await
        .unwrap();
    alice_group.merge_pending_commit().unwrap();
    let bob_group = MlsGroup::new_from_welcome(
        backend,
        &cfg,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .await
    .unwrap();
    (
        alice_group,
        bob_group,
        alice_credential_bundle,
        bob_credential_bundle,
        framing_parameters,
    )
}

async fn add_gce_proposal_to_commit(
    mut commit: &[u8],
    group: &MlsGroup,
    credential_bundle: &CredentialBundle,
    proposal: Proposal,
    backend: &impl OpenMlsCryptoProvider,
) -> MlsMessageIn {
    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut commit).unwrap();
    let old_confirmation_tag = plaintext.confirmation_tag().unwrap().clone();

    if let MlsPlaintextContentType::Commit(commit) = plaintext.tbs.payload.borrow_mut() {
        commit.proposals.push(ProposalOrRef::Proposal(proposal));
    }

    let serialized_context = group
        .export_group_context()
        .tls_serialize_detached()
        .unwrap();
    plaintext.set_context(serialized_context.clone());

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &credential_bundle)
        .unwrap();

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(old_confirmation_tag);

    let membership_key = group.group().message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(backend, &serialized_context, membership_key)
        .unwrap();

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    MlsMessageIn::from(verifiable_plaintext)
}
