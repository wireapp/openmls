use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    ciphersuite::{Ciphersuite, Secret},
    test_utils::*,
    versions::ProtocolVersion,
};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn secret_init(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // These two secrets must be incompatible
    let default_secret = Secret::random(ciphersuite, backend, None)
        .await
        .expect("Not enough randomness.");
    let draft_secret = Secret::random(ciphersuite, backend, ProtocolVersion::Mls10Draft11)
        .await
        .expect("Not enough randomness.");

    let derived_default_secret = default_secret.derive_secret(backend, "my_test_label");
    let derived_draft_secret = draft_secret.derive_secret(backend, "my_test_label");
    assert_ne!(derived_default_secret, derived_draft_secret);
}

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
pub async fn secret_incompatible(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // These two secrets must be incompatible
    let default_secret = Secret::random(ciphersuite, backend, None)
        .await
        .expect("Not enough randomness.");
    let draft_secret = Secret::random(ciphersuite, backend, ProtocolVersion::Mls10Draft11)
        .await
        .expect("Not enough randomness.");

    // This must panic because the two secrets have incompatible MLS versions.
    assert!(default_secret.hkdf_extract(backend, &draft_secret).is_err());
}
