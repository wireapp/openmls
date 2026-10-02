//! ML-DSA helpers.
//!

use crate::types::CryptoError;
use ml_dsa::{
    Generate as _, KeyInit, MlDsaParams, Seed, Signature, SignatureEncoding as _, SigningKey,
    VerifyingKey,
};
use zeroize::Zeroizing;

/// Generates a key pair. The private half returned is the 32-byte seed.
pub fn key_gen<P: MlDsaParams>(
    rng: &mut impl rand_core::CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let signing_key = SigningKey::<P>::generate_from_rng(rng);
    let private = signing_key.as_seed().to_vec();
    let public = signing_key.expanded_key().verifying_key().encode().to_vec();
    Ok((private, public))
}

/// Signs deterministically, with an empty context string.
pub fn sign<P: MlDsaParams>(payload: &[u8], seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let seed = Zeroizing::new(Seed::try_from(seed).map_err(|_| CryptoError::InvalidKey)?);
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let signature = signing_key
        .expanded_key()
        .sign_deterministic(payload, &[])
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(signature.to_vec())
}

/// Verifies a signature made with an empty context string.
pub fn verify<P: MlDsaParams>(
    payload: &[u8],
    public: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let verifying_key = <VerifyingKey<P> as KeyInit>::new_from_slice(public)
        .map_err(|_| CryptoError::InvalidKey)?;
    let signature =
        Signature::<P>::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify_with_context(payload, &[], &signature)
        .ok_or(CryptoError::InvalidSignature)
}

/// Checks that a seed derives the supplied public key.
pub fn keypair_matches<P: MlDsaParams>(seed: &[u8], public: &[u8]) -> Result<(), CryptoError> {
    let seed = Zeroizing::new(Seed::try_from(seed).map_err(|_| CryptoError::InvalidKey)?);
    let derived = SigningKey::<P>::from_seed(&seed)
        .expanded_key()
        .verifying_key()
        .encode();
    (derived.as_slice() == public).ok_or(CryptoError::MismatchKeypair)
}
