//! # OpenMLS Key Store Trait

pub trait FromKeyStoreValue: Sized {
    type Error: std::error::Error + Send + Sync + 'static;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error>;
}

pub trait ToKeyStoreValue: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error>;
}

/// The Key Store trait
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
}
