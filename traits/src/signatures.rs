use crate::types::{Error, SignatureScheme};

/// Sign the provided payload and return a signature.
pub trait Signer {
    /// Sign the provided payload.
    ///
    /// Returns a signature on success or an Error.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error>;

    /// The [`SignatureScheme`] of this signer.
    fn signature_scheme(&self) -> SignatureScheme;
}

/// Implement a default signer using the signature crate and:
/// * p256 crate for [SignatureScheme::ECDSA_SECP256R1_SHA256]
/// * p384 crate for [SignatureScheme::ECDSA_SECP384R1_SHA384]
/// * ed25519-dalek crate for [SignatureScheme::ED25519]
pub trait DefaultSigner {
    /// Provides the private key to sign the payload
    fn private_key(&self) -> &[u8];
    /// The [`SignatureScheme`] of this signer.
    fn signature_scheme(&self) -> SignatureScheme;
}

impl<T: DefaultSigner> Signer for T {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        use signature::Signer;
        match self.signature_scheme() {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = p256::ecdsa::SigningKey::from_slice(self.private_key())
                    .map_err(|_| Error::SigningError)?;
                let signature: p256::ecdsa::Signature =
                    k.try_sign(payload).map_err(|_| Error::SigningError)?;
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let k = p384::ecdsa::SigningKey::from_slice(self.private_key())
                    .map_err(|_| Error::SigningError)?;
                let signature: p384::ecdsa::Signature =
                    k.try_sign(payload).map_err(|_| Error::SigningError)?;
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let k = p521::ecdsa::SigningKey::from_slice(self.private_key())
                    .map_err(|_| Error::SigningError)?;
                let signature: p521::ecdsa::Signature =
                    k.try_sign(payload).map_err(|_| Error::SigningError)?;
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = match self.private_key().len() {
                    // Compat layer for legacy keypairs [seed, pk]
                    ed25519_dalek::KEYPAIR_LENGTH => {
                        let mut sk = zeroize::Zeroizing::new([0u8; ed25519_dalek::KEYPAIR_LENGTH]);
                        sk.copy_from_slice(self.private_key());
                        ed25519_dalek::SigningKey::from_keypair_bytes(&sk)
                            .map_err(|_| Error::SigningError)?
                    }
                    ed25519_dalek::SECRET_KEY_LENGTH => {
                        let mut sk =
                            zeroize::Zeroizing::new([0u8; ed25519_dalek::SECRET_KEY_LENGTH]);
                        sk.copy_from_slice(self.private_key());
                        ed25519_dalek::SigningKey::from_bytes(&sk)
                    }
                    _ => return Err(Error::SigningError),
                };

                let signature = k.try_sign(payload).map_err(|_| Error::SigningError)?;
                Ok(signature.to_bytes().into())
            }
            _ => Err(Error::SigningError),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme()
    }
}
