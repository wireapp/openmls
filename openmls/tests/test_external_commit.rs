use openmls::{
    credentials::test_utils::new_credential, messages::group_info::VerifiableGroupInfo, prelude::*,
    test_utils::*,
};
use openmls_basic_credential::SignatureKeyPair;

async fn create_alice_group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    use_ratchet_tree_extension: bool,
) -> (MlsGroup, CredentialWithKey, SignatureKeyPair) {
    let group_config = MlsGroupConfigBuilder::new()
        .use_ratchet_tree_extension(use_ratchet_tree_extension)
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    let (credential_with_key, signature_keys) =
        new_credential(backend, b"Alice", ciphersuite.signature_algorithm()).await;

    let group = MlsGroup::new(
        backend,
        &signature_keys,
        &group_config,
        credential_with_key.clone(),
    )
    .await
    .expect("An unexpected error occurred.");

    (group, credential_with_key, signature_keys)
}

#[apply(ciphersuites_and_backends)]
async fn test_external_commit(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Alice creates a new group ...
    let (alice_group, _, alice_signer) = create_alice_group(ciphersuite, backend, false).await;

    // ... and exports a group info (with ratchet_tree).
    let verifiable_group_info = {
        let group_info = alice_group
            .export_group_info(backend, &alice_signer, true)
            .unwrap();

        let serialized_group_info = group_info.tls_serialize_detached().unwrap();

        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_in.into_verifiable_group_info().unwrap()
    };

    let verifiable_group_info_broken = {
        let group_info = alice_group
            .export_group_info(backend, &alice_signer, true)
            .unwrap();

        let serialized_group_info = {
            let mut tmp = group_info.tls_serialize_detached().unwrap();

            // Simulate a bit-flip in the signature.
            let last = tmp.len().checked_sub(1).unwrap();
            tmp[last] ^= 1;

            tmp
        };

        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_in.into_verifiable_group_info().unwrap()
    };

    // ---------------------------------------------------------------------------------------------

    // Now, Bob wants to join Alice' group by an external commit. (Positive case.)
    {
        let (bob_credential, bob_signature_keys) =
            new_credential(backend, b"Bob", ciphersuite.signature_algorithm()).await;

        let (mut bob_group, _, _) = MlsGroup::join_by_external_commit(
            backend,
            &bob_signature_keys,
            None,
            verifiable_group_info,
            &MlsGroupConfigBuilder::new()
                .crypto_config(CryptoConfig::with_default_version(ciphersuite))
                .build(),
            b"",
            bob_credential,
        )
        .await
        .unwrap();
        bob_group.merge_pending_commit(backend).await.unwrap();
    }

    // Now, Bob wants to join Alice' group by an external commit. (Negative case, broken signature.)
    {
        let (bob_credential, bob_signature_keys) =
            new_credential(backend, b"Bob", ciphersuite.signature_algorithm()).await;

        let got_error = MlsGroup::join_by_external_commit(
            backend,
            &bob_signature_keys,
            None,
            verifiable_group_info_broken,
            &MlsGroupConfigBuilder::new()
                .crypto_config(CryptoConfig::with_default_version(ciphersuite))
                .build(),
            b"",
            bob_credential,
        )
        .await
        .unwrap_err();

        assert_eq!(
            got_error,
            ExternalCommitError::PublicGroupError(
                CreationFromExternalError::InvalidGroupInfoSignature
            )
        );
    }
}

#[apply(ciphersuites_and_backends)]
async fn test_group_info(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Alice creates a new group ...
    let (mut alice_group, _, alice_signer) = create_alice_group(ciphersuite, backend, true).await;

    // Self update Alice's to get a group info from a commit
    let (.., group_info) = alice_group
        .self_update(backend, &alice_signer)
        .await
        .unwrap();
    alice_group.merge_pending_commit(backend).await.unwrap();

    // Bob wants to join
    let (bob_credential, bob_signature_keys) =
        new_credential(backend, b"Bob", ciphersuite.signature_algorithm()).await;

    let verifiable_group_info = {
        let serialized_group_info = group_info.unwrap().tls_serialize_detached().unwrap();

        VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap()
    };
    let (mut bob_group, msg, group_info) = MlsGroup::join_by_external_commit(
        backend,
        &bob_signature_keys,
        None,
        verifiable_group_info,
        &MlsGroupConfigBuilder::new()
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build(),
        b"",
        bob_credential,
    )
    .await
    .map(|(group, msg, group_info)| (group, MlsMessageIn::from(msg), group_info))
    .unwrap();
    bob_group.merge_pending_commit(backend).await.unwrap();

    // let alice process bob's new client
    let msg = alice_group
        .process_message(backend, msg)
        .await
        .unwrap()
        .into_content();
    match msg {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            alice_group
                .merge_staged_commit(backend, *commit)
                .await
                .unwrap();
        }
        _ => panic!("Unexpected message type"),
    }

    // bob sends a message to alice
    let message: MlsMessageIn = bob_group
        .create_message(backend, &bob_signature_keys, b"Hello Alice")
        .unwrap()
        .into();

    let msg = alice_group.process_message(backend, message).await.unwrap();
    let decrypted = match msg.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => msg.into_bytes(),
        _ => panic!("Not an ApplicationMessage"),
    };
    assert_eq!(decrypted, b"Hello Alice");

    // check that the returned group info from the external join is valid
    // Bob wants to join with another client
    let (bob_credential, bob_signature_keys) =
        new_credential(backend, b"Bob 2", ciphersuite.signature_algorithm()).await;
    let verifiable_group_info = {
        let serialized_group_info = group_info.unwrap().tls_serialize_detached().unwrap();

        VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap()
    };
    let (mut bob_group, ..) = MlsGroup::join_by_external_commit(
        backend,
        &bob_signature_keys,
        None,
        verifiable_group_info,
        &MlsGroupConfigBuilder::new()
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build(),
        b"",
        bob_credential,
    )
    .await
    .unwrap();
    bob_group.merge_pending_commit(backend).await.unwrap();
}

#[apply(ciphersuites_and_backends)]
async fn test_not_present_group_info(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Alice creates a new group ...
    let (mut alice_group, _, alice_signer) = create_alice_group(ciphersuite, backend, false).await;

    // Self update Alice's to get a group info from a commit
    let (.., group_info) = alice_group
        .self_update(backend, &alice_signer)
        .await
        .unwrap();
    alice_group.merge_pending_commit(backend).await.unwrap();

    assert!(group_info.is_none());
}
