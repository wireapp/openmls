//! # OpenMLS Key Store Trait

/// Sealed list of struct openmls manages (create/read/delete) through [OpenMlsKeyStore]
#[derive(PartialEq)]
pub enum MlsEntityId {
    SignatureKeyPair,
    HpkePrivateKey,
    KeyPackage,
    PskBundle,
    EncryptionKeyPair,
    EpochEncryptionKeyPair,
    GroupState,
}

/// To implement by any struct owned by openmls aiming to be persisted in [OpenMlsKeyStore]
pub trait MlsEntity: serde::Serialize + serde::de::DeserializeOwned {
    /// Identifier used to downcast the actual entity within an [OpenMlsKeyStore] method.
    /// In case for example you need to select a SQL table depending on the entity type
    const ID: MlsEntityId;

    fn downcast<T: MlsEntity>(&self) -> Option<&T> {
        if T::ID == Self::ID {
            self.downcast()
        } else {
            None
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
/// The Key Store trait
pub trait OpenMlsKeyStore: Send + Sync {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error: std::error::Error + std::fmt::Debug;

    /// Store a value `v` that implements the [`MlsEntity`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    async fn store<V: MlsEntity + Sync>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Read and return a value stored for ID `k` that implements the
    /// [`MlsEntity`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    async fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized;

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    async fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error>;
}
