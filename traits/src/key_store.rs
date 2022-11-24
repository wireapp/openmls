//! # OpenMLS Key Store Trait

pub trait FromKeyStoreValue: Sized {
    type Error: std::error::Error + Send + Sync + 'static;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error>;
}

pub trait ToKeyStoreValue: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error>;
}

pub trait MlsEntity
where
    Self: serde::Serialize,
    for<'de> Self: serde::Deserialize<'de>,
    Self: Sized,
    Self: Sync,
{
    type Error: std::error::Error;

    fn store<D>(&self, keystore: &D) -> Result<(), Self::Error>
    where
        D: OpenMlsKeyStore + ?Sized;

    fn read<D>(keystore: &D) -> Result<Option<Self>, Self::Error>
    where
        D: OpenMlsKeyStore + ?Sized;

    fn delete(&self, keystore: &impl OpenMlsKeyStore) -> Result<(), Self::Error>;
}

/*/// The Key Store trait
#[cfg_attr(not(feature = "single-threaded"), async_trait::async_trait)]
#[cfg_attr(feature = "single-threaded", async_trait::async_trait(?Send))]
pub trait OpenMlsKeyStore: Sized {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error: std::error::Error + Send + Sync + 'static;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    async fn store<V: ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>;

    /// Read and return a value stored for ID `k` that implements the
    /// [`FromKeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    async fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Option<V>;

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    async fn delete<V: ToKeyStoreValue>(&self, k: &[u8]) -> Result<(), Self::Error>;
}*/

/// TODO
#[cfg_attr(not(feature = "single-threaded"), async_trait::async_trait)]
#[cfg_attr(feature = "single-threaded", async_trait::async_trait(?Send))]
pub trait OpenMlsKeyStore {
    /// TODO
    type Error: std::error::Error;

    /// TODO
    async fn store(&self, k: &[u8], v: &impl MlsEntity) -> Result<(), Self::Error>;

    /// TODO
    async fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V>;

    /// TODO
    async fn delete(&self, k: &[u8]) -> Result<(), Self::Error>;
}
