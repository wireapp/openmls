//! # OpenMLS Key Store Trait

use std::fmt::Debug;

/// Sealed list of struct openmls manages (create/read/delete) through [OpenMlsKeyStore]
pub enum MlsEntityId {
    KeyPackageBundle,
    CredentialBundle,
    PskBundle,
}

/// To implement by any struct owned by openmls aiming to be persisted in [OpenMlsKeyStore]
pub trait MlsEntity: serde::Serialize + serde::de::DeserializeOwned {
    /// Identifier used to downcast the actual entity within an [OpenMlsKeyStore] method.
    /// In case for example you need to select a SQL table depending on the entity type
    const ID: MlsEntityId;

    fn key(&self) -> &[u8];
}

/// The Key Store trait
pub trait OpenMlsKeyStore: Send + Sync {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error: std::error::Error + Debug;

    /// Delegated serde Deserializer
    type Deserializer<'de>;
    /// Delegated serde Serializer
    type Serializer;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Read and return a value stored for ID `k` that implements the
    /// [`serde::de::Deserialize`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<V: MlsEntity>(&self, k: &[u8]) -> Result<Option<V>, Self::Error>
    where
        Self: Sized;

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete(&self, k: &[u8]) -> Result<(), Self::Error>;

    /// Create a new serializer instance
    fn serializer() -> Self::Serializer;

    /// Create a new deserializer instance
    fn deserializer(bytes: &[u8]) -> Self::Deserializer<'_>;
}
