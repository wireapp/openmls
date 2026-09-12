//! ML-DSA helpers.

use crate::types::CryptoError;
use ml_dsa::{
    KeyInit, MlDsaParams, Signature, SignatureEncoding as _, SigningKey, VerifyingKey, B32,
};
use zeroize::Zeroizing;

pub const SEED_LEN: usize = 32;

/// Generates a key pair. The private half returned is the 32-byte seed.
pub fn key_gen<P: MlDsaParams>(
    rng: &mut impl rand_core::CryptoRng,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CryptoError> {
    let mut seed = Zeroizing::new(B32::default());
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| CryptoError::InsufficientRandomness)?;
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let public = signing_key.expanded_key().verifying_key().encode().to_vec();
    Ok((Zeroizing::new(seed.to_vec()), public))
}

/// Signs deterministically, with an empty context string.
pub fn sign<P: MlDsaParams>(payload: &[u8], seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let seed = Zeroizing::new(B32::try_from(seed).map_err(|_| CryptoError::InvalidKey)?);
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let signature = signing_key
        .expanded_key()
        .sign_deterministic(payload, b"")
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
    if verifying_key.verify_with_context(payload, b"", &signature) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

/// Checks that a public key decodes as a valid verifying key.
pub fn validate_key<P: MlDsaParams>(public: &[u8]) -> Result<(), CryptoError> {
    <VerifyingKey<P> as KeyInit>::new_from_slice(public).map_err(|_| CryptoError::InvalidKey)?;
    Ok(())
}

/// Checks that a seed derives the supplied public key.
pub fn keypair_matches<P: MlDsaParams>(seed: &[u8], public: &[u8]) -> Result<(), CryptoError> {
    let seed = Zeroizing::new(B32::try_from(seed).map_err(|_| CryptoError::InvalidKey)?);
    let derived = SigningKey::<P>::from_seed(&seed)
        .expanded_key()
        .verifying_key()
        .encode();
    if derived.as_slice() == public {
        Ok(())
    } else {
        Err(CryptoError::MismatchKeypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_round_trips_through_sign_and_verify() {
        let mut rng = rand::rng();
        let (seed, public) = key_gen::<ml_dsa::MlDsa65>(&mut rng).unwrap();
        assert_eq!(
            seed.len(),
            SEED_LEN,
            "private key must be the FIPS-204 seed"
        );
        keypair_matches::<ml_dsa::MlDsa65>(&seed, &public).unwrap();
        validate_key::<ml_dsa::MlDsa65>(&public).unwrap();
        let signature = sign::<ml_dsa::MlDsa65>(b"payload", &seed).unwrap();
        verify::<ml_dsa::MlDsa65>(b"payload", &public, &signature).unwrap();
    }

    #[test]
    fn a_short_seed_is_an_invalid_key_not_a_library_error() {
        assert_eq!(
            sign::<ml_dsa::MlDsa65>(b"payload", &[0u8; SEED_LEN - 1]),
            Err(CryptoError::InvalidKey)
        );
    }
}
