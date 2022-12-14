//! # OpenMLS Key Store Trait

use std::fmt::Debug;

pub enum MlsEntityType {
    KeyPackageBundle,
    CredentialBundle,
    PskBundle,
}

pub trait MlsEntity: serde::Serialize + serde::de::DeserializeOwned {
    const ID: MlsEntityType;

    fn key(&self) -> &[u8];
}

/// The Key Store trait
pub trait OpenMlsKeyStore: Send + Sync {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error: std::error::Error + Debug;

    type Deserializer<'de>;
    type Serializer;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Read and return a value stored for ID `k` that implements the
    /// [`FromKeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<V: MlsEntity>(&self, key: &[u8]) -> Option<V>
    where
        Self: Sized;

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<V: MlsEntity>(&self, entity: V) -> Result<(), Self::Error>;
    // fn delete(&self, k: &[u8]) -> Result<(), Self::Error>;

    fn deserializer<'de>(bytes: &'de [u8]) -> Self::Deserializer<'de>;
    fn serializer() -> Self::Serializer;
}
