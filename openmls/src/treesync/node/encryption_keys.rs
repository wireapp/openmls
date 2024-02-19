use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore},
    OpenMlsCryptoProvider,
    types::{Ciphersuite, HpkeCiphertext, HpkeKeyPair},
};

use crate::{
    ciphersuite::{hpke, HpkePrivateKey, HpkePublicKey, Secret},
    error::LibraryError,
    group::config::CryptoConfig,
    versions::ProtocolVersion,
};
use crate::prelude::{GroupEpoch, GroupId, LeafNodeIndex};

/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// path secrets in MLS commits.
#[derive(
    Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize, PartialEq, Eq, Hash,
)]
pub struct EncryptionKey {
    key: HpkePublicKey,
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.key.as_slice().to_vec()))
    }
}

impl EncryptionKey {
    /// Return the internal [`HpkePublicKey`].
    pub(crate) fn key(&self) -> &HpkePublicKey {
        &self.key
    }

    /// Return the internal [`HpkePublicKey`] as slice.
    pub fn as_slice(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// Encrypt to this HPKE public key.
    pub(crate) fn encrypt(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext, LibraryError> {
        hpke::encrypt_with_label(
            self.as_slice(),
            "UpdatePathNode",
            context,
            plaintext,
            ciphersuite,
            backend.crypto(),
        )
        .map_err(|_| LibraryError::custom("Encryption failed. A serialization issue really"))
    }
}

#[derive(Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct EncryptionPrivateKey {
    key: HpkePrivateKey,
}

impl Debug for EncryptionPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("EncryptionPrivateKey");

        #[cfg(feature = "crypto-debug")]
        ds.field("key", &self.key);
        #[cfg(not(feature = "crypto-debug"))]
        ds.field("key", &"***");

        ds.finish()
    }
}

impl From<Vec<u8>> for EncryptionPrivateKey {
    fn from(key: Vec<u8>) -> Self {
        Self { key: key.into() }
    }
}

impl From<HpkePrivateKey> for EncryptionPrivateKey {
    fn from(key: HpkePrivateKey) -> Self {
        Self { key }
    }
}

impl EncryptionPrivateKey {
    /// Decrypt a given `HpkeCiphertext` using this [`EncryptionPrivateKey`] and
    /// `group_context`.
    ///
    /// Returns the decrypted [`Secret`]. Returns an error if the decryption was
    /// unsuccessful.
    pub(crate) fn decrypt(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
        ciphertext: &HpkeCiphertext,
        group_context: &[u8],
    ) -> Result<Secret, hpke::Error> {
        // ValSem203: Path secrets must decrypt correctly
        hpke::decrypt_with_label(
            &self.key,
            "UpdatePathNode",
            group_context,
            ciphertext,
            ciphersuite,
            backend.crypto(),
        )
        .map(|secret_bytes| Secret::from_slice(&secret_bytes, version, ciphersuite))
    }
}

#[cfg(test)]
impl EncryptionPrivateKey {
    #[allow(dead_code)]
    pub(crate) fn key(&self) -> &HpkePrivateKey {
        &self.key
    }
}

impl From<HpkePublicKey> for EncryptionKey {
    fn from(key: HpkePublicKey) -> Self {
        Self { key }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct EncryptionKeyPair {
    public_key: EncryptionKey,
    private_key: EncryptionPrivateKey,
}

impl EncryptionKeyPair {
    /// Write the [`EncryptionKeyPair`] to the key store of the `backend`. This
    /// function is meant to store standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns a key store error if access to the key store fails.
    pub(crate) async fn write_to_key_store<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<(), KeyStore::Error> {
        backend
            .key_store()
            .store(self.public_key().as_slice(), self)
            .await
    }

    /// Read the [`EncryptionKeyPair`] from the key store of the `backend`. This
    /// function is meant to read standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns `None` if the keypair cannot be read from the store.
    pub(crate) async fn read_from_key_store(
        backend: &impl OpenMlsCryptoProvider,
        encryption_key: &EncryptionKey,
    ) -> Option<EncryptionKeyPair> {
        backend.key_store().read(encryption_key.as_slice()).await
    }

    /// Delete the [`EncryptionKeyPair`] from the key store of the `backend`.
    /// This function is meant to delete standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns a key store error if access to the key store fails.
    pub(crate) async fn delete_from_key_store<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<(), KeyStore::Error> {
        backend
            .key_store()
            .delete::<Self>(self.public_key().as_slice())
            .await
    }

    pub(crate) fn public_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    pub(crate) fn private_key(&self) -> &EncryptionPrivateKey {
        &self.private_key
    }

    pub(crate) fn random(
        backend: &impl OpenMlsCryptoProvider,
        config: CryptoConfig,
    ) -> Result<Self, LibraryError> {
        let ikm = Secret::random(config.ciphersuite, backend, config.version)
            .map_err(LibraryError::unexpected_crypto_error)?;
        let kp: Self = backend
            .crypto()
            .derive_hpke_keypair(config.ciphersuite.hpke_config(), ikm.as_slice())
            .map_err(LibraryError::unexpected_crypto_error)?
            .into();
        Ok(kp)
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;

    pub async fn read_keys_from_key_store(
        backend: &impl OpenMlsCryptoProvider,
        encryption_key: &EncryptionKey,
    ) -> HpkeKeyPair {
        let keys = EncryptionKeyPair::read_from_key_store(backend, encryption_key)
            .await
            .unwrap();

        HpkeKeyPair {
            private: keys.private_key.key,
            public: keys.public_key.key.as_slice().to_vec(),
        }
    }

    pub async fn write_keys_from_key_store(
        backend: &impl OpenMlsCryptoProvider,
        encryption_key: HpkeKeyPair,
    ) {
        let keypair = EncryptionKeyPair::from(encryption_key);

        keypair.write_to_key_store(backend).await.unwrap();
    }
}

#[cfg(test)]
impl EncryptionKeyPair {
    /// Build a key pair from raw bytes for testing.
    pub(crate) fn from_raw(public_key: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self {
            public_key: EncryptionKey {
                key: public_key.into(),
            },
            private_key: EncryptionPrivateKey {
                key: private_key.into(),
            },
        }
    }
}

impl From<(HpkePublicKey, HpkePrivateKey)> for EncryptionKeyPair {
    fn from((public_key, private_key): (HpkePublicKey, HpkePrivateKey)) -> Self {
        Self {
            public_key: public_key.into(),
            private_key: private_key.into(),
        }
    }
}

impl From<HpkeKeyPair> for EncryptionKeyPair {
    fn from(hpke_keypair: HpkeKeyPair) -> Self {
        let public_bytes: VLBytes = hpke_keypair.public.into();
        let private_bytes = hpke_keypair.private;
        Self {
            public_key: public_bytes.into(),
            private_key: private_bytes.into(),
        }
    }
}

impl From<(EncryptionKey, EncryptionPrivateKey)> for EncryptionKeyPair {
    fn from((public_key, private_key): (EncryptionKey, EncryptionPrivateKey)) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}

impl MlsEntity for EncryptionKeyPair {
    const ID: MlsEntityId = MlsEntityId::EncryptionKeyPair;
}

/// Composite key for key material of a client within an epoch
pub struct EpochKeypairId(Vec<u8>);

impl EpochKeypairId {
    pub fn new(group_id: &GroupId, epoch: GroupEpoch, leaf_index: LeafNodeIndex) -> Self {
        Self(
            [
                group_id.as_slice(),
                &leaf_index.u32().to_be_bytes(),
                &epoch.as_u64().to_be_bytes(),
            ]
            .concat(),
        )
    }
}

impl std::ops::Deref for EpochKeypairId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct EpochEncryptionKeyPair(pub(crate) Vec<EncryptionKeyPair>);

impl MlsEntity for EpochEncryptionKeyPair {
    const ID: MlsEntityId = MlsEntityId::EpochEncryptionKeyPair;
}

impl From<Vec<EncryptionKeyPair>> for EpochEncryptionKeyPair {
    fn from(keypairs: Vec<EncryptionKeyPair>) -> Self {
        Self(keypairs)
    }
}

impl std::ops::Deref for EpochEncryptionKeyPair {
    type Target = Vec<EncryptionKeyPair>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for EpochEncryptionKeyPair {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
