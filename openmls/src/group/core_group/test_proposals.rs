use crate::{
    ciphersuite::{
        hash_ref::{KeyPackageRef, ProposalRef},
        Secret,
    },
    credentials::CredentialBundle,
    extensions::{ExtensionType, RequiredCapabilitiesExtension},
    framing::{sender::Sender, FramingParameters, MlsPlaintext, WireFormat},
    group::{
        errors::*,
        proposals::{ProposalQueue, ProposalStore, QueuedProposal},
        GroupContext, GroupId,
    },
    key_packages::KeyPackageBundle,
    messages::proposals::{AddProposal, Proposal, ProposalOrRef, ProposalType},
    schedule::MembershipKey,
    test_utils::*,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};

use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

use tls_codec::Serialize;

use super::CoreGroup;

fn setup_client(
    id: &str,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialBundle, KeyPackageBundle) {
    let credential_bundle =
        CredentialBundle::new_basic(id.into(), ciphersuite.signature_algorithm(), backend)
            .expect("An unexpected error occurred.");
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, Vec::new())
            .expect("An unexpected error occurred.");
    (credential_bundle, key_package_bundle)
}

/// This test makes sure ProposalQueue works as intended. This functionality is
/// used in `create_commit` to filter the epoch proposals. Expected result:
/// `filtered_queued_proposals` returns only proposals of a certain type
#[apply(ciphersuites_and_backends)]
fn proposal_queue_functions(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);
    // Define identities
    let (alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);
    let (_bob_credential_bundle, bob_key_package_bundle) =
        setup_client("Bob", ciphersuite, backend);

    let alice_kpr = KeyPackageRef::new(
        &alice_key_package_bundle
            .key_package()
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
        ciphersuite,
        backend.crypto(),
    )
    .expect("An unexpected error occurred.");
    let bob_kpr = KeyPackageRef::new(
        &bob_key_package_bundle
            .key_package()
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
        ciphersuite,
        backend.crypto(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let alice_update_key_package = alice_update_key_package_bundle.key_package();
    assert!(alice_update_key_package.verify(backend).is_ok());

    let group_context = GroupContext::new(GroupId::random(backend), 0, vec![], vec![], &[]);

    // Let's create some proposals
    let add_proposal_alice1 = AddProposal {
        key_package: alice_key_package_bundle.key_package().clone(),
    };
    let add_proposal_alice2 = AddProposal {
        key_package: alice_key_package_bundle.key_package().clone(),
    };
    let add_proposal_bob1 = AddProposal {
        key_package: bob_key_package.clone(),
    };

    let proposal_add_alice1 = Proposal::Add(add_proposal_alice1);
    let proposal_reference_add_alice1 =
        ProposalRef::from_proposal(ciphersuite, backend, &proposal_add_alice1)
            .expect("An unexpected error occurred.");
    let proposal_add_alice2 = Proposal::Add(add_proposal_alice2);
    let proposal_reference_add_alice2 =
        ProposalRef::from_proposal(ciphersuite, backend, &proposal_add_alice2)
            .expect("An unexpected error occurred.");
    let proposal_add_bob1 = Proposal::Add(add_proposal_bob1);
    let proposal_reference_add_bob1 =
        ProposalRef::from_proposal(ciphersuite, backend, &proposal_add_bob1)
            .expect("An unexpected error occurred.");

    // Test proposal types
    assert!(proposal_add_alice1.is_type(ProposalType::Add));
    assert!(!proposal_add_alice1.is_type(ProposalType::Update));
    assert!(!proposal_add_alice1.is_type(ProposalType::Remove));

    // Frame proposals in MlsPlaintext
    let mls_plaintext_add_alice1 = MlsPlaintext::member_proposal(
        framing_parameters,
        &alice_kpr,
        proposal_add_alice1,
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None).expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");
    let mls_plaintext_add_alice2 = MlsPlaintext::member_proposal(
        framing_parameters,
        &bob_kpr,
        proposal_add_alice2,
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None).expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");
    let _mls_plaintext_add_bob1 = MlsPlaintext::member_proposal(
        framing_parameters,
        &bob_kpr,
        proposal_add_bob1,
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None).expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, mls_plaintext_add_alice1)
            .expect("Could not create QueuedProposal."),
    );
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, mls_plaintext_add_alice2)
            .expect("Could not create QueuedProposal."),
    );

    let (proposal_queue, own_update) = ProposalQueue::filter_proposals(
        ciphersuite,
        backend,
        Sender::build_member(&bob_kpr),
        &proposal_store,
        &[],
        &alice_kpr,
    )
    .expect("Could not create ProposalQueue.");

    // Own update should not be required in this case (only add proposals)
    assert!(!own_update);

    // Test if proposals are all covered
    let valid_proposal_reference_list =
        &[proposal_reference_add_alice1, proposal_reference_add_alice2];
    assert!(proposal_queue.contains(valid_proposal_reference_list));

    let invalid_proposal_reference_list = &[
        proposal_reference_add_alice1,
        proposal_reference_add_alice2,
        proposal_reference_add_bob1,
    ];
    assert!(!proposal_queue.contains(invalid_proposal_reference_list));

    // Get filtered proposals
    for filtered_proposal in proposal_queue.filtered_by_type(ProposalType::Add) {
        assert!(filtered_proposal.proposal().is_type(ProposalType::Add));
    }
}

/// Test, that we QueuedProposalQueue is iterated in the right order.
#[apply(ciphersuites_and_backends)]
fn proposal_queue_order(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);
    // Define identities
    let (alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);
    let (_bob_credential_bundle, bob_key_package_bundle) =
        setup_client("Bob", ciphersuite, backend);

    let alice_kpr = KeyPackageRef::new(
        &alice_key_package_bundle
            .key_package()
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
        ciphersuite,
        backend.crypto(),
    )
    .expect("An unexpected error occurred.");
    let bob_kpr = KeyPackageRef::new(
        &bob_key_package_bundle
            .key_package()
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
        ciphersuite,
        backend.crypto(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let alice_update_key_package = alice_update_key_package_bundle.key_package();
    assert!(alice_update_key_package.verify(backend).is_ok());

    let group_context = GroupContext::new(GroupId::random(backend), 0, vec![], vec![], &[]);

    // Let's create some proposals
    let add_proposal_alice1 = AddProposal {
        key_package: alice_key_package_bundle.key_package().clone(),
    };
    let add_proposal_bob1 = AddProposal {
        key_package: bob_key_package.clone(),
    };

    let proposal_add_alice1 = Proposal::Add(add_proposal_alice1);
    let proposal_reference_add_alice1 =
        ProposalRef::from_proposal(ciphersuite, backend, &proposal_add_alice1)
            .expect("An unexpected error occurred.");
    let proposal_add_bob1 = Proposal::Add(add_proposal_bob1);

    // Frame proposals in MlsPlaintext
    let mls_plaintext_add_alice1 = MlsPlaintext::member_proposal(
        framing_parameters,
        &alice_kpr,
        proposal_add_alice1.clone(),
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None /* MLS version */)
                .expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");
    let mls_plaintext_add_bob1 = MlsPlaintext::member_proposal(
        framing_parameters,
        &bob_kpr,
        proposal_add_bob1.clone(),
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None /* MLS version */)
                .expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");

    // This should set the order of the proposals.
    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, mls_plaintext_add_alice1)
            .expect("Could not create QueuedProposal."),
    );
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, mls_plaintext_add_bob1)
            .expect("Could not create QueuedProposal."),
    );

    let proposal_or_refs = vec![
        ProposalOrRef::Proposal(proposal_add_bob1.clone()),
        ProposalOrRef::Reference(proposal_reference_add_alice1),
    ];

    let sender = Sender::build_member(&alice_kpr);

    // And the same should go for proposal queues built from committed
    // proposals. The order here should be dictated by the proposals passed
    // as ProposalOrRefs.
    let proposal_queue = ProposalQueue::from_committed_proposals(
        ciphersuite,
        backend,
        proposal_or_refs,
        &proposal_store,
        &sender,
    )
    .expect("An unexpected error occurred.");

    let proposal_collection: Vec<&QueuedProposal> =
        proposal_queue.filtered_by_type(ProposalType::Add).collect();

    assert_eq!(proposal_collection[0].proposal(), &proposal_add_bob1);
    assert_eq!(proposal_collection[1].proposal(), &proposal_add_alice1);
}

#[apply(ciphersuites_and_backends)]
async fn test_required_unsupported_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let (_alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);

    // Set required capabilities
    let extensions = &[];
    let proposals = &[ProposalType::GroupContextExtensions, ProposalType::AppAck];
    let required_capabilities = RequiredCapabilitiesExtension::new(extensions, proposals);

    // This must fail because we don't actually support AppAck proposals
    let e = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_required_capabilities(required_capabilities)
        .build(backend)
        .await.expect_err(
            "CoreGroup creation must fail because AppAck proposals aren't supported in OpenMLS yet.",
        );
    assert_eq!(e, CoreGroupBuildError::UnsupportedProposalType)
}

#[apply(ciphersuites_and_backends)]
async fn test_required_extension_key_package_mismatch(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    let (alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);
    let (_bob_credential_bundle, bob_key_package_bundle) =
        setup_client("Bob", ciphersuite, backend);
    let bob_key_package = bob_key_package_bundle.key_package();

    // Set required capabilities
    let extensions = &[
        ExtensionType::Capabilities,
        ExtensionType::RequiredCapabilities,
        ExtensionType::ExternalKeyId,
    ];
    let proposals = &[
        ProposalType::GroupContextExtensions,
        ProposalType::Add,
        ProposalType::Remove,
        ProposalType::Update,
    ];
    let required_capabilities = RequiredCapabilitiesExtension::new(extensions, proposals);

    let alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_required_capabilities(required_capabilities)
        .build(backend)
        .await
        .expect("Error creating CoreGroup.");

    let e = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect_err("Proposal was created even though the key package didn't support the required extensions.");
    assert_eq!(e, CreateAddProposalError::UnsupportedExtensions);
}
