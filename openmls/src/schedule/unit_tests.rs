//! Key Schedule Unit Tests

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

use super::PskSecret;
use crate::{
    ciphersuite::Secret,
    schedule::psk::{store::ResumptionPskStore, *},
    test_utils::*,
    versions::ProtocolVersion,
};
use futures::{stream, StreamExt};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn test_psks(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Create a new PSK secret from multiple PSKs.
    let prng = backend.rand();

    let psk_ids = stream::iter(0..33)
        .then(|_| async {
            let id = prng
                .random_vec(12)
                .await
                .expect("An unexpected error occurred.");
            PreSharedKeyId::new(
                ciphersuite,
                backend.rand(),
                Psk::External(ExternalPsk::new(id)),
            )
            .await
            .expect("An unexpected error occurred.")
        })
        .collect::<Vec<PreSharedKeyId>>()
        .await;
    let secrets_with_psk_ids = stream::iter(0..33)
        .then(|_| async {
            Secret::from_slice(
                &prng
                    .random_vec(55)
                    .await
                    .expect("An unexpected error occurred."),
                ProtocolVersion::Mls10,
                ciphersuite,
            )
        })
        .zip(stream::iter(psk_ids.clone()))
        .collect::<Vec<(Secret, PreSharedKeyId)>>()
        .await;
    for (secret, psk_id) in secrets_with_psk_ids.iter() {
        psk_id
            .write_to_key_store(backend, ciphersuite, secret.as_slice())
            .await
            .unwrap();
    }

    let _psk_secret = {
        let resumption_psk_store = ResumptionPskStore::new(1024);

        let psks = load_psks(backend.key_store(), &resumption_psk_store, &psk_ids)
            .await
            .unwrap();

        PskSecret::new(backend, ciphersuite, psks).await.unwrap()
    };
}
