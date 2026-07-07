//! End-to-end MLS group lifecycle tests over the official SHAKE256 PQ
//! ciphersuites (0xF001-0xF009). This is the proof that these suites actually
//! work as suites, not just as a pile of primitives that pass their own KATs.
//!
//! Each test runs one ciphersuite through the whole thing:
//!   1. Alice creates a group
//!   2. Alice adds Bob (Add + Commit + Welcome)
//!   3. Bob joins from the Welcome
//!   4. Alice sends an application message, Bob decrypts it and checks the plaintext
//!   5. Alice removes Bob (Remove + Commit)
//!   6. Both process the commit, the epoch advances, Bob is out

use openmls::{
    prelude::{config::CryptoConfig, test_utils::new_credential, *},
    test_utils::*,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{key_store::OpenMlsKeyStore, signatures::Signer, OpenMlsCryptoProvider};

// ---------------------------------------------------------------------------
// Helper: build a KeyPackage for the given credential / ciphersuite, advertising
// that ciphersuite in its capabilities
// ---------------------------------------------------------------------------

async fn make_key_package<KeyStore: OpenMlsKeyStore>(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    credential_with_key: CredentialWithKey,
    signer: &impl Signer,
) -> KeyPackage {
    // Advertise only the ciphersuite being tested.  In a real deployment a
    // client would list all suites it supports; for the test, listing just
    // this one is sufficient (and avoids pulling in default_ciphersuites()).
    let capabilities = Capabilities::new(
        None, // default versions (MLS 1.0)
        Some(&[ciphersuite]),
        None, // no extra extension types
        None, // default proposal types
        None, // default credential types
    );

    KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
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

// ---------------------------------------------------------------------------
// Core lifecycle helper - runs the full create/add/commit/app-msg/remove cycle
// ---------------------------------------------------------------------------

async fn run_pq_shake256_lifecycle(ciphersuite: Ciphersuite, backend: &OpenMlsRustCrypto) {
    // -----------------------------------------------------------------------
    // 1. Generate credentials + signers
    // -----------------------------------------------------------------------
    let (alice_cred, alice_signer) =
        new_credential(backend, b"Alice", ciphersuite.signature_algorithm()).await;
    let (bob_cred, bob_signer) =
        new_credential(backend, b"Bob", ciphersuite.signature_algorithm()).await;

    // Bob's key package (needed for the Add proposal)
    let bob_key_package =
        make_key_package(ciphersuite, backend, bob_cred.clone(), &bob_signer).await;

    // -----------------------------------------------------------------------
    // 2. Configure the group
    //
    // We must advertise the experimental ciphersuite in Alice's own leaf
    // capabilities, otherwise the leaf node update (path computation) panics
    // when it checks that the local leaf supports the group's ciphersuite.
    // -----------------------------------------------------------------------
    let leaf_caps = Capabilities::new(
        None, // default versions
        Some(&[ciphersuite]),
        None, // no extra extension types
        None, // default proposals
        None, // default credentials
    );

    let group_config = MlsGroupConfig::builder()
        .wire_format_policy(WireFormatPolicy::default())
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .leaf_capabilities(leaf_caps)
        .build();

    // -----------------------------------------------------------------------
    // 3. Alice creates a group
    // -----------------------------------------------------------------------
    let mut alice_group = MlsGroup::new(backend, &alice_signer, &group_config, alice_cred.clone())
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not create group: {e:?}"));

    let epoch_after_create = alice_group.epoch();

    // -----------------------------------------------------------------------
    // 4. Alice adds Bob (returns a commit + welcome)
    // -----------------------------------------------------------------------
    let (_, welcome, _) = alice_group
        .add_members(backend, &alice_signer, vec![bob_key_package.into()])
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not add Bob: {e:?}"));

    alice_group
        .merge_pending_commit(backend)
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not merge add-commit: {e:?}"));

    let epoch_after_add = alice_group.epoch();
    assert!(
        epoch_after_add > epoch_after_create,
        "[{ciphersuite}] epoch should advance after add-commit"
    );
    assert_eq!(
        alice_group.members().count(),
        2,
        "[{ciphersuite}] group should have 2 members after add"
    );

    // -----------------------------------------------------------------------
    // 5. Bob joins from the Welcome
    // -----------------------------------------------------------------------
    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &group_config,
        welcome
            .into_welcome()
            .unwrap_or_else(|| panic!("[{ciphersuite}] expected a Welcome message")),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .await
    .unwrap_or_else(|e| panic!("[{ciphersuite}] Bob could not join from Welcome: {e:?}"));

    // Both views must be consistent
    assert!(
        alice_group.members().eq(bob_group.members()),
        "[{ciphersuite}] member lists diverge after join"
    );
    assert_eq!(
        alice_group.epoch_authenticator().as_slice(),
        bob_group.epoch_authenticator().as_slice(),
        "[{ciphersuite}] epoch authenticators differ after join"
    );

    // -----------------------------------------------------------------------
    // 6. Alice sends an application message; Bob decrypts and checks plaintext
    // -----------------------------------------------------------------------
    let plaintext = b"pq-shake256 lifecycle test";
    let app_msg = alice_group
        .create_message(backend, &alice_signer, plaintext)
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not create app message: {e:?}"));

    let processed = bob_group
        .process_message(
            backend,
            app_msg
                .into_protocol_message()
                .expect("unexpected message type"),
        )
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Bob could not process app message: {e:?}"));

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => {
            assert_eq!(
                m.into_bytes(),
                plaintext,
                "[{ciphersuite}] decrypted plaintext mismatch"
            );
        }
        other => panic!("[{ciphersuite}] expected ApplicationMessage, got {other:?}"),
    }

    // -----------------------------------------------------------------------
    // 7. Alice removes Bob (Remove + Commit)
    // -----------------------------------------------------------------------
    let bob_leaf_index = bob_group.own_leaf_index();
    let (remove_commit, _, _) = alice_group
        .remove_members(backend, &alice_signer, &[bob_leaf_index])
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not remove Bob: {e:?}"));

    // Bob processes the removal commit
    let bob_processed_remove = bob_group
        .process_message(
            backend,
            remove_commit
                .into_protocol_message()
                .expect("unexpected message type"),
        )
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Bob could not process remove commit: {e:?}"));

    match bob_processed_remove.into_content() {
        ProcessedMessageContent::StagedCommitMessage(sc) => {
            bob_group
                .merge_staged_commit(backend, *sc)
                .await
                .unwrap_or_else(|e| {
                    panic!("[{ciphersuite}] Bob could not merge remove commit: {e:?}")
                });
        }
        other => panic!("[{ciphersuite}] expected StagedCommit for remove, got {other:?}"),
    }

    // Alice merges the remove commit
    alice_group
        .merge_pending_commit(backend)
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not merge remove commit: {e:?}"));

    // -----------------------------------------------------------------------
    // 8. Post-remove assertions
    // -----------------------------------------------------------------------
    let epoch_after_remove = alice_group.epoch();
    assert!(
        epoch_after_remove > epoch_after_add,
        "[{ciphersuite}] epoch should advance after remove-commit"
    );

    // Bob's group should now be inactive (he was removed)
    assert!(
        !bob_group.is_active(),
        "[{ciphersuite}] Bob's group should be inactive after removal"
    );

    // Alice's group should have exactly 1 member (herself)
    assert_eq!(
        alice_group.members().count(),
        1,
        "[{ciphersuite}] Alice's group should have 1 member after removal"
    );
}

// ---------------------------------------------------------------------------
// Helper: drive a group up to "Alice + Bob both joined, consistent state" and
// hand back the two groups plus Alice's signer for further (negative) testing.
// ---------------------------------------------------------------------------

async fn join_pair(
    ciphersuite: Ciphersuite,
    backend: &OpenMlsRustCrypto,
) -> (MlsGroup, MlsGroup, SignatureKeyPair) {
    let (alice_cred, alice_signer) =
        new_credential(backend, b"Alice", ciphersuite.signature_algorithm()).await;
    let (bob_cred, bob_signer) =
        new_credential(backend, b"Bob", ciphersuite.signature_algorithm()).await;
    let bob_key_package =
        make_key_package(ciphersuite, backend, bob_cred.clone(), &bob_signer).await;

    let leaf_caps = Capabilities::new(None, Some(&[ciphersuite]), None, None, None);
    let group_config = MlsGroupConfig::builder()
        .wire_format_policy(WireFormatPolicy::default())
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .leaf_capabilities(leaf_caps)
        .build();

    let mut alice_group = MlsGroup::new(backend, &alice_signer, &group_config, alice_cred.clone())
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not create group: {e:?}"));
    let (_, welcome, _) = alice_group
        .add_members(backend, &alice_signer, vec![bob_key_package.into()])
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not add Bob: {e:?}"));
    alice_group
        .merge_pending_commit(backend)
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not merge add-commit: {e:?}"));

    let bob_group = MlsGroup::new_from_welcome(
        backend,
        &group_config,
        welcome
            .into_welcome()
            .unwrap_or_else(|| panic!("[{ciphersuite}] expected a Welcome message")),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .await
    .unwrap_or_else(|e| panic!("[{ciphersuite}] Bob could not join from Welcome: {e:?}"));

    (alice_group, bob_group, alice_signer)
}

// ---------------------------------------------------------------------------
// Negative test: an application message is cryptographically bound to its epoch
// secrets. A clean message decrypts; once Alice rotates to a new epoch (via a
// self-update commit Bob never receives), a message from that new epoch must NOT
// be decryptable by Bob, who is still at the old epoch. This proves the lifecycle
// test isn't passing merely because decryption is a no-op.
//
// (We deliberately test epoch binding rather than a raw AEAD bit-flip: upstream
// openmls trips a debug_assert!(false, "Ciphertext decryption failed") on AEAD
// failure, so a tampered ciphertext panics under debug_assertions instead of
// returning Err. The wrong-epoch path returns a graceful Err.)
// ---------------------------------------------------------------------------

async fn run_pq_shake256_wrong_epoch_rejected(
    ciphersuite: Ciphersuite,
    backend: &OpenMlsRustCrypto,
) {
    let (mut alice_group, mut bob_group, alice_signer) = join_pair(ciphersuite, backend).await;
    let plaintext = b"pq-shake256 epoch-binding test";

    // 1. A clean message decrypts at the shared epoch
    let good = alice_group
        .create_message(backend, &alice_signer, plaintext)
        .unwrap_or_else(|e| panic!("[{ciphersuite}] create_message failed: {e:?}"));
    let good_in = MlsMessageIn::tls_deserialize_exact(good.to_bytes().unwrap()).unwrap();
    let processed = bob_group
        .process_message(backend, Into::<ProtocolMessage>::into(good_in))
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] untampered message should decrypt: {e:?}"));
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => {
            assert_eq!(
                m.into_bytes(),
                plaintext,
                "[{ciphersuite}] plaintext mismatch"
            );
        }
        other => panic!("[{ciphersuite}] expected ApplicationMessage, got {other:?}"),
    }

    // 2. Alice rotates the epoch with a self-update commit that Bob never receives
    let _ = alice_group
        .self_update(backend, &alice_signer)
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice self-update failed: {e:?}"));
    alice_group
        .merge_pending_commit(backend)
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not merge self-update: {e:?}"));

    // 3. A message from the new epoch must NOT be accepted by Bob (old epoch)
    let post = alice_group
        .create_message(backend, &alice_signer, plaintext)
        .unwrap_or_else(|e| panic!("[{ciphersuite}] create_message failed: {e:?}"));
    let post_in = MlsMessageIn::tls_deserialize_exact(post.to_bytes().unwrap()).unwrap();
    let result = bob_group
        .process_message(backend, Into::<ProtocolMessage>::into(post_in))
        .await;
    assert!(
        result.is_err(),
        "[{ciphersuite}] a new-epoch message must not be accepted at the old epoch"
    );
}

// ---------------------------------------------------------------------------
// Negative test: once removed, a member must not be able to decrypt messages
// sent in the post-removal epoch (removal effectiveness / forward secrecy).
// ---------------------------------------------------------------------------

async fn run_pq_shake256_removed_member_cannot_decrypt(
    ciphersuite: Ciphersuite,
    backend: &OpenMlsRustCrypto,
) {
    let (mut alice_group, mut bob_group, alice_signer) = join_pair(ciphersuite, backend).await;

    // Remove Bob; both sides advance to the new epoch.
    let bob_leaf_index = bob_group.own_leaf_index();
    let (remove_commit, _, _) = alice_group
        .remove_members(backend, &alice_signer, &[bob_leaf_index])
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not remove Bob: {e:?}"));
    let bob_processed = bob_group
        .process_message(
            backend,
            remove_commit
                .into_protocol_message()
                .expect("unexpected message type"),
        )
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Bob could not process remove commit: {e:?}"));
    match bob_processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(sc) => {
            bob_group
                .merge_staged_commit(backend, *sc)
                .await
                .unwrap_or_else(|e| panic!("[{ciphersuite}] Bob could not merge remove: {e:?}"));
        }
        other => panic!("[{ciphersuite}] expected StagedCommit, got {other:?}"),
    }
    alice_group
        .merge_pending_commit(backend)
        .await
        .unwrap_or_else(|e| panic!("[{ciphersuite}] Alice could not merge remove: {e:?}"));
    assert!(
        !bob_group.is_active(),
        "[{ciphersuite}] Bob should be inactive after removal"
    );

    // Alice sends a message in the post-removal epoch; the removed Bob must not decrypt it.
    let secret = b"after Bob is gone";
    let post_msg = alice_group
        .create_message(backend, &alice_signer, secret)
        .unwrap_or_else(|e| panic!("[{ciphersuite}] create_message failed: {e:?}"));
    let post_in = MlsMessageIn::tls_deserialize_exact(post_msg.to_bytes().unwrap()).unwrap();
    let result = bob_group
        .process_message(backend, Into::<ProtocolMessage>::into(post_in))
        .await;
    assert!(
        result.is_err(),
        "[{ciphersuite}] removed member must not decrypt a post-removal message"
    );
}

#[tokio::test]
async fn pq_shake256_wrong_epoch_rejected_f001_ed25519() {
    run_pq_shake256_wrong_epoch_rejected(
        Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

#[tokio::test]
async fn pq_shake256_wrong_epoch_rejected_f008_mldsa65() {
    run_pq_shake256_wrong_epoch_rejected(
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

#[tokio::test]
async fn pq_shake256_removed_member_cannot_decrypt_f001_ed25519() {
    run_pq_shake256_removed_member_cannot_decrypt(
        Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

#[tokio::test]
async fn pq_shake256_removed_member_cannot_decrypt_f008_mldsa65() {
    run_pq_shake256_removed_member_cannot_decrypt(
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Per-suite tests - one per KEM family + both ML-DSA suites
// ---------------------------------------------------------------------------

/// 0xF001 - X-Wing (MlKem768 + X25519) / Ed25519 / AES-128-GCM / SHA-256
#[tokio::test]
async fn pq_shake256_lifecycle_f001_mlkem768x25519_ed25519() {
    run_pq_shake256_lifecycle(
        Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

/// 0xF002 - X-Wing (MlKem768 + X25519) / Ed25519 / AES-256-GCM / SHA-384
#[tokio::test]
async fn pq_shake256_lifecycle_f002_mlkem768x25519_ed25519() {
    run_pq_shake256_lifecycle(
        Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

/// 0xF003 - MlKem768P256 / P-256 / AES-128-GCM / SHA-256
#[tokio::test]
async fn pq_shake256_lifecycle_f003_mlkem768p256_p256() {
    run_pq_shake256_lifecycle(
        Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

/// 0xF004 - MlKem768P256 / P-256 / AES-256-GCM / SHA-384
#[tokio::test]
async fn pq_shake256_lifecycle_f004_mlkem768p256_p256() {
    run_pq_shake256_lifecycle(
        Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

/// 0xF005 - MlKem1024P384 / P-384 / AES-256-GCM / SHA-384
#[tokio::test]
async fn pq_shake256_lifecycle_f005_mlkem1024p384_p384() {
    run_pq_shake256_lifecycle(
        Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

/// 0xF006 - pure MlKem768 / P-256 / AES-256-GCM / SHA-384
#[tokio::test]
async fn pq_shake256_lifecycle_f006_mlkem768_p256() {
    run_pq_shake256_lifecycle(
        Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

/// 0xF007 - pure MlKem1024 / P-384 / AES-256-GCM / SHA-384
#[tokio::test]
async fn pq_shake256_lifecycle_f007_mlkem1024_p384() {
    run_pq_shake256_lifecycle(
        Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

/// 0xF008 - MlKem768 / ML-DSA-65 / AES-256-GCM / SHA-384
#[tokio::test]
async fn pq_shake256_lifecycle_f008_mlkem768_mldsa65() {
    run_pq_shake256_lifecycle(
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}

/// 0xF009 - MlKem1024 / ML-DSA-87 / AES-256-GCM / SHA-384
#[tokio::test]
async fn pq_shake256_lifecycle_f009_mlkem1024_mldsa87() {
    run_pq_shake256_lifecycle(
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        &OpenMlsRustCrypto::default(),
    )
    .await;
}
