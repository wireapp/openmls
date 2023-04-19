use criterion::{
    async_executor::FuturesExecutor, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use openmls::prelude::{config::CryptoConfig, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider};

fn criterion_benchmark(c: &mut Criterion) {
    let backend = OpenMlsRustCrypto::default();
    for &ciphersuite in backend.crypto().supported_ciphersuites().iter() {
        let credential = Credential::new(vec![1, 2, 3], CredentialType::Basic).unwrap();
        let signer = SignatureKeyPair::new(
            ciphersuite.signature_algorithm(),
            &mut *backend.rand().borrow_rand().unwrap(),
        )
        .unwrap();
        let credential_with_key = CredentialWithKey {
            credential,
            signature_key: signer.to_public_vec().into(),
        };

        c.bench_with_input(
            BenchmarkId::new(
                format!("KeyPackage create bundle with ciphersuite"),
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
