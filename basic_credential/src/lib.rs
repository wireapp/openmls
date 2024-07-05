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
        key_store.store(&self.public, self)
    }

    /// Read a signature key pair from the key store.
    pub async fn read(key_store: &impl OpenMlsKeyStore, public_key: &[u8]) -> Option<Self> {
        key_store.read(public_key)
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

    #[test]
    fn signature_keypair_try_from_raw_should_work() {
        let schemes = [
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::ECDSA_SECP521R1_SHA512,
        ];
        for scheme in schemes {
            let kp = SignatureKeyPair::new(scheme, &mut rand::thread_rng()).unwrap();
            let sk = kp.private.expose_secret().clone();
            let pk = kp.public.clone();
            SignatureKeyPair::try_from_raw(scheme, sk, pk).unwrap();
        }
    }
}
