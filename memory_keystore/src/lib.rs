use async_lock::RwLock;
use openmls_traits::key_store::{MlsEntity, OpenMlsKeyStore};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl OpenMlsKeyStore for MemoryKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = MemoryKeyStoreError;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    async fn store<V: MlsEntity + Sync>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let value = serde_json::to_vec(v).map_err(|_| MemoryKeyStoreError::SerializationError)?;
        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().await;
        values.insert(k.to_vec(), value);
        Ok(())
    }

    /// Read and return a value stored for ID `k` that implements the
    /// [`FromKeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    async fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package_bundle`) only
        // hold the lock very briefly and should not panic during that period.
        let values = self.values.read().await;
        if let Some(value) = values.get(k) {
            serde_json::from_slice(value).ok()
        } else {
            None
        }
    }

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    async fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        // We just delete both ...
        let mut values = self.values.write().await;
        values.remove(k);
        Ok(())
    }
}

/// Errors thrown by the key store.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryKeyStoreError {
    #[error("The key store does not allow storing serialized values.")]
    UnsupportedValueTypeBytes,
    #[error("Updating is not supported by this key store.")]
    UnsupportedMethod,
    #[error("Error serializing value.")]
    SerializationError,
}
