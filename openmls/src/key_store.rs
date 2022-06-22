//! Serialization for key store objects.

use crate::{
    credentials::CredentialBundle, key_packages::KeyPackageBundle, schedule::psk::PskBundle,
};

use openmls_traits::key_store::{FromKeyStoreValue, ToKeyStoreValue};

// === OpenMLS Key Store Types

impl FromKeyStoreValue for KeyPackageBundle {
    type Error = serde_json::Error;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(ksv)
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
