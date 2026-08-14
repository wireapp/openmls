use log::{debug, info, warn};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};
use serde::{self, Deserialize, Serialize};
use tls_codec::Deserialize as TlsDeserialize;

use crate::{
    framing::{MlsMessageIn, MlsMessageInBody, ProcessedMessageContent},
    group::{config::CryptoConfig, *},
    key_packages::*,
    schedule::psk::PreSharedKeyId,
    test_utils::*,
    treesync::{
        node::encryption_keys::{EncryptionKeyPair, EncryptionPrivateKey},
        RatchetTreeIn,
    },
};

const TEST_VECTORS_PATH_READ: &[&str] = &[
    "test_vectors/passive-client-welcome.json",
    "test_vectors/passive-client-random.json",
    "test_vectors/passive-client-handling-commit.json",
];

/// ```json
/// {
///   "cipher_suite": /* uint16 */,
///
///   "key_package": /* serialized KeyPackage */,
///   "signature_priv":  /* hex-encoded binary data */,
///   "encryption_priv": /* hex-encoded binary data */,
///   "init_priv": /* hex-encoded binary data */,
///
///   "welcome":  /* serialized MLSMessage (Welcome) */,
///   "initial_epoch_authenticator":  /* hex-encoded binary data */,
///
///   "epochs": [
///     {
///       "proposals": [
///         /* serialized MLSMessage (PublicMessage or PrivateMessage) */,
///         /* serialized MLSMessage (PublicMessage or PrivateMessage) */,
///       ],
///       "commit": /* serialized MLSMessage (PublicMessage or PrivateMessage) */,
///       "epoch_authenticator": /* hex-encoded binary data */,
///     },
///     // ...
///   ]
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PassiveClientWelcomeTestVector {
    cipher_suite: u16,
    external_psks: Vec<ExternalPskTest>,

    #[serde(with = "hex::serde")]
    key_package: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    encryption_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    init_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    welcome: Vec<u8>,
    ratchet_tree: Option<VecU8>,
    #[serde(with = "hex::serde")]
    initial_epoch_authenticator: Vec<u8>,
    epochs: Vec<TestEpoch>,
}

// Helper to avoid writing a custom deserializer.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VecU8(#[serde(with = "hex::serde")] Vec<u8>);

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ExternalPskTest {
    #[serde(with = "hex::serde")]
    psk_id: Vec<u8>,
    #[serde(with = "hex::serde")]
    psk: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TestEpoch {
    proposals: Vec<TestProposal>,
    #[serde(with = "hex::serde")]
    commit: Vec<u8>,
    #[serde(with = "hex::serde")]
    epoch_authenticator: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TestProposal(#[serde(with = "hex::serde")] Vec<u8>);

#[async_std::test]
async fn test_read_vectors() {
    for file in TEST_VECTORS_PATH_READ {
        let scenario: Vec<PassiveClientWelcomeTestVector> = read(file);

        info!("# {file}");
        for (i, test_vector) in scenario.into_iter().enumerate() {
            info!("## {i:04} START");
            run_test_vector(test_vector).await;
            info!("## {i:04} END");
        }
    }
}

pub async fn run_test_vector(test_vector: PassiveClientWelcomeTestVector) {
    let _ = pretty_env_logger::try_init();

    let backend = OpenMlsRustCrypto::default();
    let cipher_suite = test_vector.cipher_suite.try_into().unwrap();
    if backend.crypto().supports(cipher_suite).is_err() {
        warn!("Skipping {}", cipher_suite);
        return;
    }
    info!("Ciphersuite: {cipher_suite}");

    let group_config = MlsGroupConfig::builder()
        .crypto_config(CryptoConfig::with_default_version(cipher_suite))
        .use_ratchet_tree_extension(true)
        .wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .number_of_resumption_psks(16)
        .build();

    let mut passive_client =
        PassiveClient::new(group_config, test_vector.external_psks.clone()).await;

    passive_client
        .inject_key_package(
            test_vector.key_package,
            test_vector.signature_priv,
            test_vector.encryption_priv,
            test_vector.init_priv,
        )
        .await;

    let ratchet_tree: Option<RatchetTreeIn> = test_vector
        .ratchet_tree
        .as_ref()
        .map(|bytes| RatchetTreeIn::tls_deserialize_exact(bytes.0.as_slice()).unwrap());

    passive_client
        .join_by_welcome(
            MlsMessageIn::tls_deserialize_exact(&test_vector.welcome).unwrap(),
            ratchet_tree,
        )
        .await;

    debug!(
        "Group ID {}",
        bytes_to_hex(passive_client.group.as_ref().unwrap().group_id().as_slice())
    );

    assert_eq!(
        test_vector.initial_epoch_authenticator,
        passive_client.epoch_authenticator()
    );

    for (i, epoch) in test_vector.epochs.into_iter().enumerate() {
        info!("Epoch #{}", i);

        for proposal in epoch.proposals {
            let message = MlsMessageIn::tls_deserialize_exact(&proposal.0).unwrap();
            debug!("Proposal: {message:?}");
            passive_client.process_message(message).await;
        }

        let message = MlsMessageIn::tls_deserialize_exact(&epoch.commit).unwrap();
        debug!("Commit: {message:#?}");
        passive_client.process_message(message).await;

        assert_eq!(
            epoch.epoch_authenticator,
            passive_client.epoch_authenticator()
        );
    }
}

struct PassiveClient {
    backend: OpenMlsRustCrypto,
    group_config: MlsGroupConfig,
    group: Option<MlsGroup>,
}

impl PassiveClient {
    async fn new(group_config: MlsGroupConfig, psks: Vec<ExternalPskTest>) -> Self {
        let backend = OpenMlsRustCrypto::default();

        // Load all PSKs into key store.
        for psk in psks.into_iter() {
            // TODO: Better API?
            // We only construct this to easily save the PSK in the keystore.
            // The nonce is not saved, so it can be empty...
            let psk_id = PreSharedKeyId::external(psk.psk_id, vec![]);
            psk_id
                .write_to_key_store(&backend, group_config.crypto_config.ciphersuite, &psk.psk)
                .await
                .unwrap();
        }

        Self {
            backend,
            group_config,
            group: None,
        }
    }

    async fn inject_key_package(
        &self,
        key_package: Vec<u8>,
        _signature_priv: Vec<u8>,
        encryption_priv: Vec<u8>,
        init_priv: Vec<u8>,
    ) {
        let key_package: KeyPackage = {
            let mls_message_key_package = MlsMessageIn::tls_deserialize_exact(key_package).unwrap();

            match mls_message_key_package.body {
                MlsMessageInBody::KeyPackage(key_package) => key_package.into(),
                _ => panic!(),
            }
        };

        let init_priv = HpkePrivateKey::from(init_priv);

        let key_package_bundle = KeyPackageBundle {
            key_package: key_package.clone(),
            private_key: init_priv,
        };

        // Store key package.
        self.backend
            .key_store()
            .store(
                key_package
                    .hash_ref(self.backend.crypto())
                    .unwrap()
                    .as_slice(),
                &key_package,
            )
            .await
            .unwrap();

        // Store init key.
        self.backend
            .key_store()
            .store::<HpkePrivateKey>(
                key_package.hpke_init_key().as_slice(),
                key_package_bundle.private_key(),
            )
            .await
            .unwrap();

        // Store encryption key
        let key_pair = EncryptionKeyPair::from((
            key_package.leaf_node().encryption_key().clone(),
            EncryptionPrivateKey::from(encryption_priv),
        ));

        key_pair.write_to_key_store(&self.backend).await.unwrap();
    }

    async fn join_by_welcome(
        &mut self,
        mls_message_welcome: MlsMessageIn,
        ratchet_tree: Option<RatchetTreeIn>,
    ) {
        let group = MlsGroup::new_from_welcome(
            &self.backend,
            &self.group_config,
            mls_message_welcome.into_welcome().unwrap(),
            ratchet_tree,
        )
        .await
        .unwrap();

        self.group = Some(group);
    }

    async fn process_message(&mut self, message: MlsMessageIn) {
        let processed_message = self
            .group
            .as_mut()
            .unwrap()
            .process_message(&self.backend, message.into_protocol_message().unwrap())
            .await
            .unwrap();

        match processed_message.into_content() {
            ProcessedMessageContent::ProposalMessage(queued_proposal) => {
                self.group
                    .as_mut()
                    .unwrap()
                    .store_pending_proposal(*queued_proposal);
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.group
                    .as_mut()
                    .unwrap()
                    .merge_staged_commit(&self.backend, *staged_commit)
                    .await
                    .unwrap();
            }
            _ => unimplemented!(),
        }
    }

    fn epoch_authenticator(&self) -> Vec<u8> {
        self.group
            .as_ref()
            .unwrap()
            .epoch_authenticator()
            .as_slice()
            .to_vec()
    }
}
