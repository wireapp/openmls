use criterion::{
    async_executor::FuturesExecutor, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use futures::executor;
use openmls::prelude::{config::CryptoConfig, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider};

fn criterion_benchmark(c: &mut Criterion) {
    let backend = OpenMlsRustCrypto::default();
    for &ciphersuite in backend.crypto().supported_ciphersuites().iter() {
        let mut rng = executor::block_on(backend.rand().borrow_rand());
        let credential = Credential::new_basic(vec![1, 2, 3]);
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm(), &mut *rng).unwrap();
        let credential_with_key = CredentialWithKey {
            credential,
            signature_key: signer.to_public_vec().into(),
        };

        c.bench_with_input(
            BenchmarkId::new(
                "KeyPackage create bundle with ciphersuite".to_string(),
                ciphersuite,
            ),
            &(&backend, signer, credential_with_key),
            |b, (crypto, signer, credential_with_key)| {
                b.to_async(FuturesExecutor).iter(|| {
                    KeyPackage::builder().build(
                        CryptoConfig {
                            ciphersuite,
                            version: ProtocolVersion::default(),
                        },
                        *crypto,
                        signer,
                        credential_with_key.clone(),
                    )
                })
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
