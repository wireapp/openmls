//! # Basic Credential
//!
//! An implementation of the basic credential from the MLS spec.
//!
//! For now this credential uses only RustCrypto.

use secrecy::{ExposeSecret, SecretVec};
use std::fmt::Debug;

use openmls_traits::{
    key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore},
    types::{CryptoError, SignatureScheme},
};

/// Generate an ML-DSA key pair for parameter set P.
///
/// The private key is stored as the 32-byte FIPS-204 seed (xi); the public key
/// is the raw FIPS-204 verifying-key encoding. This mirrors
/// openmls_rust_crypto's mldsa_key_gen so that signatures produced from the
/// stored seed verify via the provider's verify_signature.
fn mldsa_key_gen<P: ml_dsa::MlDsaParams>(
    csprng: &mut impl rand_core::CryptoRngCore,
) -> Result<(SecretVec<u8>, Vec<u8>), CryptoError> {
    let mut seed = zeroize::Zeroizing::new(ml_dsa::B32::default());
    csprng
        .try_fill_bytes(&mut seed)
        .map_err(|_| CryptoError::InsufficientRandomness)?;
    let signing_key = ml_dsa::SigningKey::<P>::from_seed(&seed);
    let public = signing_key.expanded_key().verifying_key().encode().to_vec();
    let private: Vec<u8> = seed.to_vec();
    Ok((private.into(), public))
}

/// Confirm a stored ML-DSA private seed (FIPS-204 xi) actually derives the given
/// public verifying key, mirroring `mldsa_key_gen`'s seed-to-public mapping. The
/// reconstructed seed is a secret, so it is scrubbed on drop.
fn mldsa_keypair_matches<P: ml_dsa::MlDsaParams>(
    private: &[u8],
    public: &[u8],
) -> Result<(), CryptoError> {
    let seed = zeroize::Zeroizing::new(
        ml_dsa::B32::try_from(private).map_err(|_| CryptoError::InvalidKey)?,
    );
    let signing_key = ml_dsa::SigningKey::<P>::from_seed(&seed);
    let derived = signing_key.expanded_key().verifying_key().encode();
    if derived.as_slice() != public {
        return Err(CryptoError::MismatchKeypair);
    }
    Ok(())
}

fn expose_sk<S: serde::Serializer>(data: &SecretVec<u8>, ser: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq as _;
    let exposed = data.expose_secret();
    let mut seq = ser.serialize_seq(Some(exposed.len()))?;
    for b in exposed.iter() {
        seq.serialize_element(b)?;
    }
    seq.end()
}

/// A signature key pair for the basic credential.
///
/// This can be used as keys to implement the MLS basic credential. It is a simple
/// private and public key pair with corresponding signature scheme.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SignatureKeyPair {
    #[serde(serialize_with = "expose_sk")]
    private: SecretVec<u8>,
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

#[cfg(feature = "clonable")]
impl Clone for SignatureKeyPair {
    fn clone(&self) -> Self {
        Self {
            private: self.private.expose_secret().clone().into(),
            public: self.public.clone(),
            signature_scheme: self.signature_scheme,
        }
    }
}

impl secrecy::SerializableSecret for SignatureKeyPair {}

impl tls_codec::Size for SignatureKeyPair {
    fn tls_serialized_len(&self) -> usize {
        self.private.expose_secret().tls_serialized_len()
            + self.public.tls_serialized_len()
            + self.signature_scheme.tls_serialized_len()
    }
}

impl tls_codec::Deserialize for SignatureKeyPair {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let private = Vec::<u8>::tls_deserialize(bytes)?.into();
        let public = Vec::<u8>::tls_deserialize(bytes)?;
        let signature_scheme = SignatureScheme::tls_deserialize(bytes)?;
        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }
}

impl tls_codec::Serialize for SignatureKeyPair {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.private.expose_secret().tls_serialize(writer)?;
        written += self.public.tls_serialize(writer)?;
        written += self.signature_scheme.tls_serialize(writer)?;
        Ok(written)
    }
}

impl Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &"***".to_string())
            .field("public", &self.public)
            .field("signature_scheme", &self.signature_scheme)
            .finish()
    }
}

impl openmls_traits::signatures::DefaultSigner for SignatureKeyPair {
    fn private_key(&self) -> &[u8] {
        self.private.expose_secret().as_slice()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

impl MlsEntity for SignatureKeyPair {
    const ID: MlsEntityId = MlsEntityId::SignatureKeyPair;
}

impl SignatureKeyPair {
    /// Generates a fresh signature keypair using the [`SignatureScheme`].
    pub fn new(
        signature_scheme: SignatureScheme,
        csprng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Self, CryptoError> {
        let (private, public): (SecretVec<u8>, Vec<u8>) = match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let sk = p256::ecdsa::SigningKey::random(csprng);
                let pk = sk.verifying_key().to_encoded_point(false).to_bytes().into();
                (sk.to_bytes().to_vec().into(), pk)
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let sk = p384::ecdsa::SigningKey::random(csprng);
                let pk = sk.verifying_key().to_encoded_point(false).to_bytes().into();
                (sk.to_bytes().to_vec().into(), pk)
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let sk = p521::ecdsa::SigningKey::random(csprng);
                let pk = p521::ecdsa::VerifyingKey::from(&sk)
                    .to_encoded_point(false)
                    .to_bytes()
                    .into();
                (sk.to_bytes().to_vec().into(), pk)
            }
            SignatureScheme::ED25519 => {
                let sk = ed25519_dalek::SigningKey::generate(csprng);
                let pk = sk.verifying_key();
                // full key here because we need it to sign...
                let sk_pk: Vec<u8> = sk.to_bytes().into();
                (sk_pk.into(), pk.to_bytes().into())
            }
            SignatureScheme::MLDSA65 => mldsa_key_gen::<ml_dsa::MlDsa65>(csprng)?,
            SignatureScheme::MLDSA87 => mldsa_key_gen::<ml_dsa::MlDsa87>(csprng)?,
            _ => return Err(CryptoError::UnsupportedSignatureScheme),
        };

        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }

    /// Create a new signature key pair from the raw keys.
    pub fn from_raw(signature_scheme: SignatureScheme, private: Vec<u8>, public: Vec<u8>) -> Self {
        Self {
            private: private.into(),
            public,
            signature_scheme,
        }
    }

    /// Create a new KeyPair but verify that the private key actually matches the public key
    pub fn try_from_raw(
        signature_scheme: SignatureScheme,
        private: Vec<u8>,
        public: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        match signature_scheme {
            SignatureScheme::ED25519 => {
                let sk = ed25519_dalek::SigningKey::try_from(
                    &private[..ed25519_dalek::SECRET_KEY_LENGTH],
                )
                .map_err(|_| CryptoError::InvalidKey)?;
                let pk = ed25519_dalek::VerifyingKey::try_from(public.as_slice())
                    .map_err(|_| CryptoError::InvalidKey)?;

                if sk.verifying_key() != pk {
                    return Err(CryptoError::MismatchKeypair);
                }
            }
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let sk = p256::ecdsa::SigningKey::from_slice(&private)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let pk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public)
                    .map_err(|_| CryptoError::InvalidKey)?;

                if sk.verifying_key() != &pk {
                    return Err(CryptoError::MismatchKeypair);
                }
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let sk = p384::ecdsa::SigningKey::from_slice(&private)
                    .map_err(|_| CryptoError::InvalidKey)?;

                let pk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&public)
                    .map_err(|_| CryptoError::InvalidKey)?;

                if sk.verifying_key() != &pk {
                    return Err(CryptoError::MismatchKeypair);
                }
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let sk = p521::ecdsa::SigningKey::from_slice(&private)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let pk = p521::ecdsa::VerifyingKey::from_sec1_bytes(&public)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let sk_pk = p521::ecdsa::VerifyingKey::from(&sk);

                if sk_pk.to_encoded_point(false) != pk.to_encoded_point(false) {
                    return Err(CryptoError::MismatchKeypair);
                }
            }
            SignatureScheme::MLDSA65 => {
                mldsa_keypair_matches::<ml_dsa::MlDsa65>(&private, &public)?
            }
            SignatureScheme::MLDSA87 => {
                mldsa_keypair_matches::<ml_dsa::MlDsa87>(&private, &public)?
            }
            _ => {}
        };

        Ok(Self {
            private: private.into(),
            public,
            signature_scheme,
        })
    }

    /// Store this signature key pair in the key store.
    pub async fn store<T>(&self, key_store: &T) -> Result<(), <T as OpenMlsKeyStore>::Error>
    where
        T: OpenMlsKeyStore,
    {
        key_store.store(&self.public, self).await
    }

    /// Read a signature key pair from the key store.
    pub async fn read(key_store: &impl OpenMlsKeyStore, public_key: &[u8]) -> Option<Self> {
        key_store.read(public_key).await
    }

    /// Get the public key as byte slice.
    pub fn public(&self) -> &[u8] {
        self.public.as_ref()
    }

    /// Get the public key as byte vector.
    pub fn to_public_vec(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Get the [`SignatureScheme`] of this signature key.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    #[cfg(feature = "test-utils")]
    pub fn private(&self) -> &[u8] {
        self.private.expose_secret()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer};

    /// A SignatureKeyPair ML-DSA signature MUST verify via the provider's
    /// verify_signature. This proves sign<->verify interop and that the
    /// private (32-byte seed) / public (raw FIPS-204) representations match
    /// what the provider expects.
    #[test]
    fn mldsa_sign_verifies_via_provider() {
        let provider = openmls_rust_crypto::RustCrypto::default();
        let schemes = [SignatureScheme::MLDSA65, SignatureScheme::MLDSA87];
        let expected_pk_len = [1952usize, 2592usize];

        for (scheme, pk_len) in schemes.into_iter().zip(expected_pk_len) {
            let kp = SignatureKeyPair::new(scheme, &mut rand::thread_rng()).unwrap();

            // Private key is the 32-byte FIPS-204 seed
            assert_eq!(
                kp.private.expose_secret().len(),
                32,
                "{scheme:?} private key must be the 32-byte seed"
            );
            // Public key is the raw FIPS-204 verifying-key encoding
            assert_eq!(
                kp.public.len(),
                pk_len,
                "{scheme:?} public key must be the raw FIPS-204 encoding"
            );

            let msg = b"ml-dsa sign<->provider-verify interop";
            let sig = kp.sign(msg).expect("ML-DSA signing must succeed");

            // The signature MUST verify via the provider
            provider
                .verify_signature(scheme, msg, kp.public(), &sig)
                .unwrap_or_else(|e| panic!("{scheme:?} provider verify must succeed: {e:?}"));

            // Tampering with the message must fail verification
            let mut bad_msg = msg.to_vec();
            bad_msg[0] ^= 0xFF;
            assert!(
                provider
                    .verify_signature(scheme, &bad_msg, kp.public(), &sig)
                    .is_err(),
                "{scheme:?} verify must fail on a tampered message"
            );

            // Tampering with the signature must fail verification
            let mut bad_sig = sig.clone();
            bad_sig[0] ^= 0xFF;
            assert!(
                provider
                    .verify_signature(scheme, msg, kp.public(), &bad_sig)
                    .is_err(),
                "{scheme:?} verify must fail on a tampered signature"
            );
        }
    }

    #[test]
    fn signature_keypair_try_from_raw_should_work() {
        let schemes = [
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::ECDSA_SECP521R1_SHA512,
            SignatureScheme::MLDSA65,
            SignatureScheme::MLDSA87,
        ];
        for scheme in schemes {
            let kp = SignatureKeyPair::new(scheme, &mut rand::thread_rng()).unwrap();
            let sk = kp.private.expose_secret().clone();
            let pk = kp.public.clone();
            SignatureKeyPair::try_from_raw(scheme, sk, pk).unwrap();
        }
    }

    /// `try_from_raw` must reject a private/public pair that does not belong
    /// together - including for the ML-DSA schemes, which previously fell into
    /// the no-op `_ => {}` arm and were accepted without any check.
    #[test]
    fn signature_keypair_try_from_raw_rejects_mismatched_mldsa() {
        for scheme in [SignatureScheme::MLDSA65, SignatureScheme::MLDSA87] {
            let kp1 = SignatureKeyPair::new(scheme, &mut rand::thread_rng()).unwrap();
            let kp2 = SignatureKeyPair::new(scheme, &mut rand::thread_rng()).unwrap();
            let mismatched = SignatureKeyPair::try_from_raw(
                scheme,
                kp1.private.expose_secret().clone(),
                kp2.public.clone(),
            );
            assert!(
                matches!(mismatched, Err(CryptoError::MismatchKeypair)),
                "{scheme:?} try_from_raw must reject a mismatched ML-DSA keypair, got {mismatched:?}"
            );
        }
    }
}
