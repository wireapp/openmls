use openmls_traits::key_store::{MlsEntity, OpenMlsKeyStore};
use serde_json::de::SliceRead;
use std::{collections::HashMap, sync::RwLock};

#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl OpenMlsKeyStore for MemoryKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = Error;

    type Deserializer<'de> = serde_json::Deserializer<SliceRead<'de>>;
    type Serializer = serde_json::Serializer<Vec<u8>>;

    /// Store a value `v` that implements the [`KeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let mut serializer = Self::serializer();

        v.serialize(&mut serializer).unwrap();
        let value = serializer.into_inner();

        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().unwrap();
        values.insert(k.to_vec(), value);
        Ok(())
    }

    /// Read and return a value stored for ID `k` that implements the
    /// [`KeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<V: MlsEntity>(&self, key: &[u8]) -> Option<V> {
        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package_bundle`) only
        // hold the lock very briefly and should not panic during that period.
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(key) {
            V::deserialize(&mut Self::deserializer(&value)).ok()
        } else {
            None
        }
    }

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<V: MlsEntity>(&self, entity: V) -> Result<(), Self::Error> {
        // We just delete both ...
        let mut values = self.values.write().unwrap();
        values.remove(entity.key());
        Ok(())
    }

    fn deserializer<'de>(bytes: &'de [u8]) -> Self::Deserializer<'de> {
        serde_json::Deserializer::from_slice(bytes)
    }

    fn serializer() -> Self::Serializer {
        serde_json::Serializer::new(Vec::with_capacity(128))
    }
}

/// Errors thrown by the key store.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("The key store does not allow storing serialized values.")]
    UnsupportedValueTypeBytes,
    #[error("Updating is not supported by this key store.")]
    UnsupportedMethod,
    #[error("Error serializing value.")]
    SerializationError,
}
