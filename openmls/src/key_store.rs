//! Serialization for key store objects.

use openmls_memory_keystore::MemoryKeyStore;
use crate::{
    credentials::CredentialBundle, key_packages::KeyPackageBundle, schedule::psk::PskBundle,
};

use openmls_traits::key_store::{FromKeyStoreValue, MlsEntity, OpenMlsKeyStore, ToKeyStoreValue};

// === OpenMLS Key Store Types

impl MlsEntity<MemoryKeyStore> for KeyPackageBundle {
    type Error = anyhow::Error;

    async fn store(&self, keystore: &MemoryKeyStore) -> Result<(), Self::Error> {
        keystore.values.write().unwrap().insert(self.)
    }

    async fn read(keystore: &MemoryKeyStore) -> Result<Option<Self>, Self::Error> {
        todo!()
    }

    async fn delete(&self, keystore: &MemoryKeyStore) -> Result<(), Self::Error> {
        todo!()
    }
}

impl FromKeyStoreValue for CredentialBundle {
    type Error = serde_json::Error;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(ksv)
    }
}

impl ToKeyStoreValue for KeyPackageBundle {
    type Error = serde_json::Error;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(self)
    }
}

impl ToKeyStoreValue for CredentialBundle {
    type Error = serde_json::Error;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(self)
    }
}

// PSKs

impl FromKeyStoreValue for PskBundle {
    type Error = serde_json::Error;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(ksv)
    }
}

impl ToKeyStoreValue for PskBundle {
    type Error = serde_json::Error;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(self)
    }
}
