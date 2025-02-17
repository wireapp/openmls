use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};

use crate::{
    extensions::{
        errors::ExtensionError, ApplicationIdExtension, Extension, Extensions,
        RequiredCapabilitiesExtension,
    },
    framing::{validation::ProcessedMessageContent, MlsMessageIn},
    group::mls_group::errors::UpdateExtensionsError,
    messages::proposals::ProposalType,
    test_utils::*,
    treesync::{errors::MemberExtensionValidationError, node::leaf_node::Capabilities},
};

use super::test_gce_proposals::{group_setup, DEFAULT_CREDENTIAL_TYPES};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn gce_fails_when_it_contains_unsupported_extensions(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &[], &DEFAULT_CREDENTIAL_TYPES);
    // Bob has been created from a welcome message
    let (mut alice_group, mut bob_group, alice_signer, bob_signer) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        Extensions::empty(),
        Capabilities::default(),
        backend,
    )
    .await;
    // Alice tries to add a required capability she doesn't support herself.
    let required_key_id = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[],
        &[ProposalType::AppAck],
        &[],
    ));
    let e = alice_group.update_extensions(backend, &alice_signer, Extensions::single(required_key_id.clone())).await
        .expect_err("Alice was able to create a gce proposal with a required extensions she doesn't support.");
    matches!(
        e,
        UpdateExtensionsError::MemberExtensionValidationError(
            MemberExtensionValidationError::ExtensionError(ExtensionError::UnsupportedProposalType)
        )
    );
    // Now Bob wants the ExternalSenders extension to be required.
    // This should fail because Alice doesn't support it.
    let e = bob_group
        .update_extensions(backend, &bob_signer, Extensions::single(required_key_id))
        .await
        .expect_err("Bob was able to create a gce proposal for an extension not supported by all other parties.");
    matches!(
        e,
        UpdateExtensionsError::MemberExtensionValidationError(
            MemberExtensionValidationError::ExtensionError(ExtensionError::UnsupportedProposalType)
        )
    );
}

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn gce_commit_can_roundtrip(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &[], &DEFAULT_CREDENTIAL_TYPES);
    let (mut alice_group, mut bob_group, alice_signer, _) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        Extensions::empty(),
        Capabilities::default(),
        backend,
    )
    .await;

    // Alice adds an extension
    let new_extensions = Extensions::single(Extension::ApplicationId(ApplicationIdExtension::new(
        b"test_mls",
    )));
    let (gce_commit, _, _) = alice_group
        .update_extensions(backend, &alice_signer, new_extensions.clone())
        .await
        .unwrap();
    alice_group.merge_pending_commit(backend).await.unwrap();
    assert_eq!(*alice_group.group_context_extensions(), new_extensions);

    // bob should be able to process the commit
    let processed_message = bob_group
        .process_message(backend, MlsMessageIn::from(gce_commit))
        .await
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(gce_commit) = processed_message.into_content()
    else {
        panic!("Not a remove proposal");
    };
    bob_group
        .merge_staged_commit(backend, *gce_commit)
        .await
        .unwrap();
    assert_eq!(*bob_group.group_context_extensions(), new_extensions);
}
