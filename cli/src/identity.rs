use openmls::prelude::{config::CryptoConfig, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

pub struct Identity {
    pub(crate) kp: KeyPackage,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) signer: SignatureKeyPair,
}

impl Identity {
    pub(crate) async fn new(
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustCrypto,
        id: &[u8],
    ) -> Self {
        let credential = Credential::new_basic(id.to_vec());
        let signature_keys = SignatureKeyPair::new(
            ciphersuite.signature_algorithm(),
            &mut *crypto.rand().borrow_rand().unwrap(),
        )
        .unwrap();
        let credential_with_key = CredentialWithKey {
            credential,
            signature_key: signature_keys.to_public_vec().into(),
        };
        signature_keys.store(crypto.key_store()).await.unwrap();

        let key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                crypto,
                &signature_keys,
                credential_with_key.clone(),
            )
            .await
            .unwrap();

        Self {
            kp: key_package,
            credential_with_key,
            signer: signature_keys,
        }
    }

    /// Get the plain identity as byte vector.
    pub fn identity(&self) -> &[u8] {
        self.credential_with_key.credential.identity()
    }
}
