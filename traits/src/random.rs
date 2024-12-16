//! # Randomness Source for OpenMLS
//!
//! The [`OpenMlsRand`] trait defines the functionality required by OpenMLS to
//! source randomness.

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait OpenMlsRand {
    type Error: std::error::Error + std::fmt::Debug;
    type RandImpl: rand_core::CryptoRngCore;
    type BorrowTarget<'a>: std::ops::DerefMut<Target = Self::RandImpl>
    where
        Self: 'a;

    async fn borrow_rand(&self) -> Self::BorrowTarget<'_>;

    /// Fill an array with random bytes.
    async fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error>;

    /// Fill a vector of length `len` with bytes.
    async fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error>;
}
