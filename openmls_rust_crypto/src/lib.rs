//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

pub use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
use openmls_traits::OpenMlsCryptoProvider;

mod provider;
pub use provider::*;

#[derive(Debug)]
pub struct DummyAuthenticationService;

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl openmls_traits::authentication_service::AuthenticationServiceDelegate
    for DummyAuthenticationService
{
    fn validate_credential<'a>(
        &'a self,
        _credential: openmls_traits::authentication_service::CredentialRef<'a>,
    ) -> openmls_traits::authentication_service::CredentialAuthenticationStatus {
        openmls_traits::authentication_service::CredentialAuthenticationStatus::Valid
    }
}

#[derive(Default, Debug)]
pub struct OpenMlsRustCrypto {
    crypto: RustCrypto,
    key_store: MemoryStorage,
}

impl OpenMlsCryptoProvider for OpenMlsRustCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = MemoryStorage;
    type AuthenticationServiceProvider = DummyAuthenticationService;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }

    fn authentication_service(&self) -> &Self::AuthenticationServiceProvider {
        &DummyAuthenticationService
    }
}
