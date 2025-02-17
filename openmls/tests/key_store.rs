//! A couple of simple tests on how to interact with the key store.
use openmls::{prelude::*, test_utils::*};
use openmls_basic_credential::SignatureKeyPair;

#[apply(ciphersuites_and_backends)]
async fn test_store_key_package(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // ANCHOR: key_store_store
    // First we generate a credential and key package for our user.
    let credential = Credential::new_basic(b"User ID".to_vec());
    let signature_keys = SignatureKeyPair::new(
        ciphersuite.into(),
        &mut *backend.rand().borrow_rand().unwrap(),
    )
    .unwrap();

    let key_package = KeyPackage::builder()
        .build(
            CryptoConfig::with_default_version(ciphersuite),
            backend,
            &signature_keys,
            CredentialWithKey {
                credential,
                signature_key: signature_keys.to_public_vec().into(),
            },
        )
        .await
        .unwrap();
    // ANCHOR_END: key_store_store

    // ANCHOR: key_store_delete
    // Delete the key package
    key_package
        .delete(backend)
        .await
        .expect("Error deleting key package");
    // ANCHOR_END: key_store_delete
}
