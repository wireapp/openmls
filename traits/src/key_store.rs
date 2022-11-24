//! # OpenMLS Key Store Trait

#[cfg_attr(not(feature = "single-threaded"), async_trait::async_trait)]
#[cfg_attr(feature = "single-threaded", async_trait::async_trait(?Send))]
pub trait MlsEntity<D>
where
    Self: serde::Serialize + Sized + Sync,
    for<'de> Self: serde::Deserialize<'de>,
    D: OpenMlsKeyStore + ?Sized,
{
    type Error: std::error::Error;

    async fn store(&self, keystore: &D) -> Result<(), Self::Error>;

    async fn read(keystore: &D) -> Result<Option<Self>, Self::Error>;

    async fn delete(&self, keystore: &D) -> Result<(), Self::Error>;
}

/// TODO
pub trait OpenMlsKeyStore {}
