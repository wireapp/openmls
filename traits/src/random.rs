//! # Randomness Source for OpenMLS
//!
//! The [`OpenMlsRand`] trait defines the functionality required by OpenMLS to
//! source randomness.

pub trait OpenMlsRand {
    type Error: std::error::Error + std::fmt::Debug;
    type RandImpl: rand_core::CryptoRngCore;
    type BorrowTarget<'a>: std::ops::DerefMut<Target = Self::RandImpl>
    where
        Self: 'a;

    fn borrow_rand(&self) -> Result<Self::BorrowTarget<'_>, Self::Error>;

    /// Fill an array with random bytes.
    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error>;

    /// Fill a vector of length `len` with bytes.
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error>;
}
