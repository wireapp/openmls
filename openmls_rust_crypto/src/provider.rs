use aes_gcm::aead;
use rand_core::{SeedableRng, TryRng as _};
use std::sync::RwLock;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, KeyInit,
};
use chacha20poly1305::ChaCha20Poly1305;
use elliptic_curve::Generate as _;
use hkdf::Hkdf;
use ml_dsa::{
    KeyInit as MlDsaKeyInit, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature as MlDsaSignature,
    SignatureEncoding, SigningKey, VerifyingKey, B32,
};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        self, AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType,
        HpkeConfig, HpkeKdfType, HpkeKemType, SignatureScheme,
    },
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tls_codec::SecretVLBytes;

/// 32-byte raw entropy seed
pub type RawEntropySeed = <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::Seed;

#[derive(Debug, Clone, Default, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
#[repr(transparent)]
/// Wrapped 32-byte entropy seed with bounds check
pub struct EntropySeed(RawEntropySeed);

impl EntropySeed {
    pub const EXPECTED_LEN: usize = std::mem::size_of::<EntropySeed>() / std::mem::size_of::<u8>();

    pub fn try_from_slice(data: &[u8]) -> Result<Self, RandError> {
        if data.len() < Self::EXPECTED_LEN {
            return Err(RandError::EntropySeedLengthError {
                actual: data.len(),
                expected: Self::EXPECTED_LEN,
            });
        }

        let mut inner = RawEntropySeed::default();
        inner.copy_from_slice(&data[..Self::EXPECTED_LEN]);

        Ok(Self(inner))
    }

    pub fn from_raw(raw: RawEntropySeed) -> Self {
        Self(raw)
    }
}

impl std::ops::Deref for EntropySeed {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for EntropySeed {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct RustCrypto {
    rng: RwLock<rand_chacha::ChaCha20Rng>,
}

impl Default for RustCrypto {
    fn default() -> Self {
        let mut seed = RawEntropySeed::default();
        getrandom::fill(&mut seed).expect("system RNG has to work");
        Self::new_with_seed(EntropySeed::from_raw(seed))
    }
}

impl RustCrypto {
    pub fn new_with_seed(seed: EntropySeed) -> Self {
        Self {
            rng: rand_chacha::ChaCha20Rng::from_seed(seed.0).into(),
        }
    }
}

#[inline]
fn normalize_p521_secret_key(sk: &[u8]) -> zeroize::Zeroizing<[u8; 66]> {
    let mut sk_buf = zeroize::Zeroizing::new([0u8; 66]);
    sk_buf[66 - sk.len()..].copy_from_slice(sk);
    sk_buf
}

const MLDSA_SEED_LEN: usize = 32;

/// Generate an ML-DSA key pair, storing the private key as its 32-byte seed.
fn mldsa_key_gen<P: MlDsaParams>(
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Wipe the transient seed on drop.
    let mut seed = zeroize::Zeroizing::new(B32::default());
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| CryptoError::InsufficientRandomness)?;
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let public_key = signing_key.expanded_key().verifying_key().encode().to_vec();
    Ok((seed.to_vec(), public_key))
}

/// Sign with deterministic ML-DSA and an empty context.
fn mldsa_sign<P: MlDsaParams>(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != MLDSA_SEED_LEN {
        return Err(CryptoError::CryptoLibraryError);
    }
    // Wipe the reconstructed seed on drop.
    let seed =
        zeroize::Zeroizing::new(B32::try_from(key).map_err(|_| CryptoError::CryptoLibraryError)?);
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let signature = signing_key
        .expanded_key()
        .sign_deterministic(data, b"")
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(signature.to_vec())
}

/// Verify an ML-DSA signature with an empty context.
fn mldsa_verify<P: MlDsaParams>(
    data: &[u8],
    pk: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let verifying_key = <VerifyingKey<P> as MlDsaKeyInit>::new_from_slice(pk)
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    let signature =
        MlDsaSignature::<P>::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;
    if verifying_key.verify_with_context(data, b"", &signature) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

impl OpenMlsCrypto for RustCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256
            | Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256
            | Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
            | Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44,
        ]
    }

    fn hkdf_extract(
        &self,
        hash_type: openmls_traits::types::HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_384 => Ok(Hkdf::<Sha384>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_512 => Ok(Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().into()),
        }
    }

    fn hkdf_expand(
        &self,
        hash_type: openmls_traits::types::HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

                Ok(okm.into())
            }
            HashType::Sha2_512 => {
                let hkdf = Hkdf::<Sha512>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

                Ok(okm.into())
            }
            HashType::Sha2_384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

                Ok(okm.into())
            }
        }
    }

    fn hash(
        &self,
        hash_type: openmls_traits::types::HashType,
        data: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Sha256::digest(data).as_slice().into()),
            HashType::Sha2_384 => Ok(Sha384::digest(data).as_slice().into()),
            HashType::Sha2_512 => Ok(Sha512::digest(data).as_slice().into()),
        }
    }

    fn aead_encrypt(
        &self,
        alg: openmls_traits::types::AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        // All supported algorithms use the same nonce size of 96 bits, so
        // picking any of them for the generic parameter of Nonce<A> is fine.
        let nonce =
            aead::Nonce::<Aes128Gcm>::try_from(nonce).map_err(|_| CryptoError::InvalidLength)?;

        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;

                aes.encrypt(&nonce, Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadEncryptionError)
            }
            AeadType::Aes256Gcm => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AeadEncryptionError)?;

                aes.encrypt(&nonce, Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadEncryptionError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::AeadEncryptionError)?;

                chacha_poly
                    .encrypt(&nonce, Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadEncryptionError)
            }
        }
    }

    fn aead_decrypt(
        &self,
        alg: openmls_traits::types::AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        // All supported algorithms use the same nonce size of 96 bits, so
        // picking any of them for the generic parameter of Nonce<A> is fine.
        let nonce =
            aead::Nonce::<Aes128Gcm>::try_from(nonce).map_err(|_| CryptoError::InvalidLength)?;

        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(&nonce, Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::Aes256Gcm => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(&nonce, Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .decrypt(&nonce, Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
        }
    }

    fn signature_key_gen(
        &self,
        alg: openmls_traits::types::SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), openmls_traits::types::CryptoError> {
        let mut rng = self
            .rng
            .write()
            .map_err(|_| CryptoError::InsufficientRandomness)?;

        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut *rng);
                let pk = sk.verifying_key().to_sec1_point(false).to_bytes().into();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let sk = p384::ecdsa::SigningKey::generate_from_rng(&mut *rng);
                let pk = sk.verifying_key().to_sec1_point(false).to_bytes().into();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let sk = p521::ecdsa::SigningKey::generate_from_rng(&mut *rng);
                let pk = p521::ecdsa::VerifyingKey::from(&sk)
                    .to_sec1_point(false)
                    .to_bytes()
                    .into();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::generate(&mut *rng);
                let pk = k.verifying_key();
                Ok((k.to_bytes().into(), pk.to_bytes().into()))
            }
            SignatureScheme::MLDSA44 => mldsa_key_gen::<MlDsa44>(&mut rng),
            SignatureScheme::MLDSA65 => mldsa_key_gen::<MlDsa65>(&mut rng),
            SignatureScheme::MLDSA87 => mldsa_key_gen::<MlDsa87>(&mut rng),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn signature_public_key_len(&self, alg: SignatureScheme) -> usize {
        use generic_array::typenum::Unsigned;
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                <p256::NistP256 as p256::elliptic_curve::Curve>::FieldBytesSize::to_usize()
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                <p384::NistP384 as p384::elliptic_curve::Curve>::FieldBytesSize::to_usize()
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                <p521::NistP521 as p521::elliptic_curve::Curve>::FieldBytesSize::to_usize()
            }
            SignatureScheme::ED25519 => ed25519_dalek::PUBLIC_KEY_LENGTH,
            SignatureScheme::ED448 => 57,
            SignatureScheme::MLDSA44 => 1312,
            SignatureScheme::MLDSA65 => 1952,
            SignatureScheme::MLDSA87 => 2592,
        }
    }

    fn verify_signature(
        &self,
        alg: openmls_traits::types::SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), openmls_traits::types::CryptoError> {
        use signature::Verifier as _;
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;

                let signature = p256::ecdsa::DerSignature::from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature)?;

                k.verify(data, &signature)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let k = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;

                let signature = p384::ecdsa::DerSignature::from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature)?;

                k.verify(data, &signature)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let k = p521::ecdsa::VerifyingKey::from_sec1_bytes(pk)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;

                let signature = p521::ecdsa::Signature::from_der(signature)
                    .map_err(|_| CryptoError::InvalidSignature)?;

                k.verify(data, &signature)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::VerifyingKey::try_from(pk)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;

                if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                    return Err(CryptoError::InvalidSignature);
                }

                let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                sig.clone_from_slice(signature);
                k.verify_strict(data, &ed25519_dalek::Signature::from(sig))
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::MLDSA44 => mldsa_verify::<MlDsa44>(data, pk, signature),
            SignatureScheme::MLDSA65 => mldsa_verify::<MlDsa65>(data, pk, signature),
            SignatureScheme::MLDSA87 => mldsa_verify::<MlDsa87>(data, pk, signature),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(
        &self,
        alg: openmls_traits::types::SignatureScheme,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        use signature::Signer as _;

        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = p256::ecdsa::SigningKey::from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: p256::ecdsa::DerSignature = k
                    .try_sign(data)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let k = p384::ecdsa::SigningKey::from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: p384::ecdsa::DerSignature = k
                    .try_sign(data)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let k = p521::ecdsa::SigningKey::from_slice(&*normalize_p521_secret_key(key))
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: p521::ecdsa::DerSignature = <p521::ecdsa::SigningKey as signature::Signer<p521::ecdsa::Signature>>::
                    try_sign(&k, data)
                    .map_err(|_| CryptoError::CryptoLibraryError)?
                    .to_der();
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = match key.len() {
                    // Compat layer for legacy keypairs [seed, pk]
                    ed25519_dalek::KEYPAIR_LENGTH => {
                        let mut sk = zeroize::Zeroizing::new([0u8; ed25519_dalek::KEYPAIR_LENGTH]);
                        sk.copy_from_slice(key);
                        ed25519_dalek::SigningKey::from_keypair_bytes(&sk)
                            .map_err(|_| CryptoError::CryptoLibraryError)?
                    }
                    ed25519_dalek::SECRET_KEY_LENGTH => {
                        let mut sk =
                            zeroize::Zeroizing::new([0u8; ed25519_dalek::SECRET_KEY_LENGTH]);
                        sk.copy_from_slice(key);
                        ed25519_dalek::SigningKey::from_bytes(&sk)
                    }
                    _ => return Err(CryptoError::CryptoLibraryError),
                };
                let signature = k
                    .try_sign(data)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::MLDSA44 => mldsa_sign::<MlDsa44>(data, key),
            SignatureScheme::MLDSA65 => mldsa_sign::<MlDsa65>(data, key),
            SignatureScheme::MLDSA87 => mldsa_sign::<MlDsa87>(data, key),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<types::HpkeCiphertext, CryptoError> {
        let mut rng = self
            .rng
            .write()
            .map_err(|_| CryptoError::HpkeEncryptionError)?;
        match config {
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::ChaCha20Poly1305,
            ) => hpke_core::hpke_seal::<
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::DhKemP256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::DhP256HkdfSha256,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::DhKemP384,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::DhP384HkdfSha384,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::DhKemP521,
                HpkeKdfType::HkdfSha512,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha512,
                hpke::kem::DhP521HkdfSha512,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::XWing>(
                    pk_r, info, aad, ptxt, &mut rng,
                )
            }
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::XWing>(
                    pk_r, info, aad, ptxt, &mut rng,
                )
            }
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::ChaCha20Poly1305,
            ) => hpke_core::hpke_seal::<
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha384,
                hpke::kem::XWing,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::MlKem768P256,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem768P256,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem1024P384,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::HkdfSha384,
                    hpke::kem::MlKem768,
                >(pk_r, info, aad, ptxt, &mut rng)
            }
            HpkeConfig(
                HpkeKemType::MlKem1024,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem1024,
            >(pk_r, info, aad, ptxt, &mut rng),
            _ => Err(CryptoError::UnsupportedKem),
        }
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &types::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let plaintext = match config {
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::ChaCha20Poly1305,
            ) => hpke_core::hpke_open::<
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::DhKemP256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::DhP256HkdfSha256,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::DhKemP384,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::DhP384HkdfSha384,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::DhKemP521,
                HpkeKdfType::HkdfSha512,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha512,
                hpke::kem::DhP521HkdfSha512,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::XWing,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::XWing,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::ChaCha20Poly1305,
            ) => hpke_core::hpke_open::<
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha384,
                hpke::kem::XWing,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::MlKem768P256,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem768P256,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem1024P384,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::HkdfSha384,
                    hpke::kem::MlKem768,
                >(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(
                HpkeKemType::MlKem1024,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem1024,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            _ => return Err(CryptoError::UnsupportedKem),
        };

        Ok(plaintext)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        let mut rng = self
            .rng
            .write()
            .map_err(|_| CryptoError::SenderSetupError)?;
        let (kem_output, export) = match config {
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::ChaCha20Poly1305,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::DhKemP256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::DhP256HkdfSha256,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::DhKemP384,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::DhP384HkdfSha384,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::DhKemP521,
                HpkeKdfType::HkdfSha512,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha512,
                hpke::kem::DhP521HkdfSha512,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::XWing,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::XWing,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::ChaCha20Poly1305,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha384,
                hpke::kem::XWing,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::MlKem768P256,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem768P256,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem1024P384,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::HkdfSha384,
                    hpke::kem::MlKem768,
                >(pk_r, info, exporter_context, exporter_length, &mut rng)?
            }
            HpkeConfig(
                HpkeKemType::MlKem1024,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem1024,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            _ => return Err(CryptoError::UnsupportedKem),
        };

        debug_assert_eq!(export.len(), exporter_length);

        Ok((kem_output, export.into()))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        let export = match config {
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::ChaCha20Poly1305,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::DhKemP256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::DhP256HkdfSha256,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::DhKemP384,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::DhP384HkdfSha384,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::DhKemP521,
                HpkeKdfType::HkdfSha512,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha512,
                hpke::kem::DhP521HkdfSha512,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::XWing,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::XWing,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::ChaCha20Poly1305,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha384,
                hpke::kem::XWing,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::MlKem768P256,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem768P256,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem1024P384,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::HkdfSha384,
                    hpke::kem::MlKem768,
                >(enc, sk_r, info, exporter_context, exporter_length)?
            }
            HpkeConfig(
                HpkeKemType::MlKem1024,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::MlKem1024,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            _ => return Err(CryptoError::UnsupportedKem),
        };

        debug_assert_eq!(export.len(), exporter_length);

        Ok(export.into())
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<types::HpkeKeyPair, CryptoError> {
        match config.0 {
            HpkeKemType::DhKemP256 => {
                hpke_core::hpke_derive_keypair::<hpke::kem::DhP256HkdfSha256>(ikm)
            }
            HpkeKemType::DhKemP384 => {
                hpke_core::hpke_derive_keypair::<hpke::kem::DhP384HkdfSha384>(ikm)
            }
            HpkeKemType::DhKemP521 => {
                hpke_core::hpke_derive_keypair::<hpke::kem::DhP521HkdfSha512>(ikm)
            }
            HpkeKemType::DhKem25519 => {
                hpke_core::hpke_derive_keypair::<hpke::kem::X25519HkdfSha256>(ikm)
            }
            HpkeKemType::MlKem768X25519 => hpke_core::hpke_derive_keypair::<hpke::kem::XWing>(ikm),
            HpkeKemType::MlKem768P256 => {
                hpke_core::hpke_derive_keypair::<hpke::kem::MlKem768P256>(ikm)
            }
            HpkeKemType::MlKem1024P384 => {
                hpke_core::hpke_derive_keypair::<hpke::kem::MlKem1024P384>(ikm)
            }
            HpkeKemType::MlKem768 => hpke_core::hpke_derive_keypair::<hpke::kem::MlKem768>(ikm),
            HpkeKemType::MlKem1024 => hpke_core::hpke_derive_keypair::<hpke::kem::MlKem1024>(ikm),
            _ => Err(CryptoError::UnsupportedKem),
        }
    }
}

mod hpke_core {
    use openmls_traits::types::{CryptoError, HpkeCiphertext, HpkeKeyPair};

    pub fn hpke_open<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        private_key: &[u8],
        kem_output: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let encapped_key = Kem::EncappedKey::from_bytes(kem_output)
            .map_err(|_| CryptoError::HpkeDecryptionError)?;

        // Systematically normalize private keys
        let sk_len = Kem::PrivateKey::size();
        let mut sk_buf = zeroize::Zeroizing::new(Vec::with_capacity(sk_len));
        if private_key.len() < sk_len {
            for _ in 0..(sk_len - private_key.len()) {
                sk_buf.push(0x00);
            }
        }
        sk_buf.extend_from_slice(private_key);
        let key =
            Kem::PrivateKey::from_bytes(&sk_buf).map_err(|_| CryptoError::HpkeDecryptionError)?;

        let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &hpke::OpModeR::Base,
            &key,
            &encapped_key,
            info,
            ciphertext,
            aad,
        )
        .map_err(|_| CryptoError::HpkeDecryptionError)?;

        Ok(plaintext)
    }

    pub fn hpke_seal<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        public_key: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        csprng: &mut impl rand_core::CryptoRng,
    ) -> Result<HpkeCiphertext, CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let key =
            Kem::PublicKey::from_bytes(public_key).map_err(|_| CryptoError::HpkeEncryptionError)?;
        let (encapped, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
            &hpke::OpModeS::Base,
            &key,
            info,
            plaintext,
            aad,
            csprng,
        )
        .map_err(|_| CryptoError::HpkeEncryptionError)?;

        Ok(HpkeCiphertext {
            kem_output: encapped.to_bytes().to_vec().into(),
            ciphertext: ciphertext.into(),
        })
    }

    #[allow(dead_code)]
    pub fn hpke_gen_keypair<Kem: hpke::Kem>(
        csprng: &mut impl rand_core::CryptoRng,
    ) -> Result<HpkeKeyPair, CryptoError> {
        use hpke::Serializable as _;
        let (sk, pk) = Kem::gen_keypair_with_rng(csprng);
        let (private, public) = (sk.to_bytes().to_vec().into(), pk.to_bytes().to_vec());

        Ok(HpkeKeyPair { private, public })
    }

    pub fn hpke_derive_keypair<Kem: hpke::Kem>(ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
        use hpke::Serializable as _;
        let (sk, pk) = Kem::derive_keypair(ikm);
        let (private, public) = (sk.to_bytes().to_vec().into(), pk.to_bytes().to_vec());

        Ok(HpkeKeyPair { private, public })
    }

    pub fn hpke_export_rx<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        encapped_key: &[u8],
        rx_private_key: &[u8],
        info: &[u8],
        export_info: &[u8],
        export_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        use hpke::Deserializable as _;
        let key = Kem::PrivateKey::from_bytes(rx_private_key)
            .map_err(|_| CryptoError::ReceiverSetupError)?;
        let encapped_key = Kem::EncappedKey::from_bytes(encapped_key)
            .map_err(|_| CryptoError::ReceiverSetupError)?;
        let ctx =
            hpke::setup_receiver::<Aead, Kdf, Kem>(&hpke::OpModeR::Base, &key, &encapped_key, info)
                .map_err(|_| CryptoError::ReceiverSetupError)?;

        let mut export = vec![0u8; export_len];

        ctx.export(export_info, &mut export)
            .map_err(|_| CryptoError::ExporterError)?;

        Ok(export)
    }

    pub fn hpke_export_tx<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        tx_public_key: &[u8],
        info: &[u8],
        export_info: &[u8],
        export_len: usize,
        csprng: &mut impl rand_core::CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let key =
            Kem::PublicKey::from_bytes(tx_public_key).map_err(|_| CryptoError::SenderSetupError)?;
        let (kem_output, ctx) =
            hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(&hpke::OpModeS::Base, &key, info, csprng)
                .map_err(|_| CryptoError::SenderSetupError)?;

        let mut export = vec![0u8; export_len];

        ctx.export(export_info, &mut export)
            .map_err(|_| CryptoError::ExporterError)?;

        Ok((kem_output.to_bytes().to_vec(), export))
    }
}

impl OpenMlsRand for RustCrypto {
    type Error = RandError;

    type RandImpl = rand_chacha::ChaCha20Rng;
    type BorrowTarget<'a> = std::sync::RwLockWriteGuard<'a, Self::RandImpl>;

    fn borrow_rand(&self) -> Result<Self::BorrowTarget<'_>, Self::Error> {
        self.rng.write().map_err(|_| Self::Error::LockPoisoned)
    }

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut rng = self.borrow_rand()?;
        let mut out = [0u8; N];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.borrow_rand()?;
        let mut out = vec![0u8; len];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RandError {
    #[error("Rng lock is poisoned.")]
    LockPoisoned,
    #[error("Unable to collect enough randomness.")]
    NotEnoughRandomness,
    #[error(
        "The provided entropy seed has an incorrect length: expected {expected}, found {actual}"
    )]
    EntropySeedLengthError { actual: usize, expected: usize },
}

#[cfg(test)]
mod mldsa_tests {
    use super::*;
    use openmls_traits::crypto::OpenMlsCrypto;

    const MLDSA44: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA44, 1312, 2420);
    const MLDSA65: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA65, 1952, 3309);
    const MLDSA87: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA87, 2592, 4627);

    #[test]
    fn signature_public_key_len_matches_fips204() {
        let provider = RustCrypto::default();
        assert_eq!(provider.signature_public_key_len(MLDSA44.0), MLDSA44.1);
        assert_eq!(provider.signature_public_key_len(MLDSA65.0), MLDSA65.1);
        assert_eq!(provider.signature_public_key_len(MLDSA87.0), MLDSA87.1);
    }

    #[test]
    fn keygen_sign_verify_round_trip() {
        for (scheme, pk_len, sig_len) in [MLDSA44, MLDSA65, MLDSA87] {
            let provider = RustCrypto::default();
            let (private_key, public_key) = provider
                .signature_key_gen(scheme)
                .expect("key generation should succeed");

            assert_eq!(public_key.len(), pk_len, "public key length for {scheme:?}");

            let message = b"the quick brown fox jumps over the lazy dog";
            let signature = provider
                .sign(scheme, message, &private_key)
                .expect("signing should succeed");

            assert_eq!(signature.len(), sig_len, "signature length for {scheme:?}");

            provider
                .verify_signature(scheme, message, &public_key, &signature)
                .expect("verification of a valid signature should succeed");
        }
    }

    #[test]
    fn tampered_message_fails_verification() {
        for (scheme, _, _) in [MLDSA44, MLDSA65, MLDSA87] {
            let provider = RustCrypto::default();
            let (private_key, public_key) = provider.signature_key_gen(scheme).unwrap();

            let message = b"authentic message";
            let signature = provider.sign(scheme, message, &private_key).unwrap();

            let tampered = b"authentic messagE";
            assert!(
                provider
                    .verify_signature(scheme, tampered, &public_key, &signature)
                    .is_err(),
                "tampered message must fail verification for {scheme:?}"
            );
        }
    }

    #[test]
    fn wrong_key_fails_verification() {
        for (scheme, _, _) in [MLDSA44, MLDSA65, MLDSA87] {
            let provider = RustCrypto::default();
            let (private_key, _) = provider.signature_key_gen(scheme).unwrap();
            let (_, other_public_key) = provider.signature_key_gen(scheme).unwrap();

            let message = b"signed under the first key";
            let signature = provider.sign(scheme, message, &private_key).unwrap();

            assert!(
                provider
                    .verify_signature(scheme, message, &other_public_key, &signature)
                    .is_err(),
                "verification under the wrong key must fail for {scheme:?}"
            );
        }
    }

    #[test]
    fn signing_is_deterministic() {
        for (scheme, _, _) in [MLDSA44, MLDSA65, MLDSA87] {
            let provider = RustCrypto::default();
            let (private_key, _) = provider.signature_key_gen(scheme).unwrap();
            let message = b"deterministic";
            let sig_a = provider.sign(scheme, message, &private_key).unwrap();
            let sig_b = provider.sign(scheme, message, &private_key).unwrap();
            assert_eq!(
                sig_a, sig_b,
                "signatures must be deterministic for {scheme:?}"
            );
        }
    }

    #[test]
    fn validate_signature_key_accepts_valid_and_rejects_invalid() {
        for (scheme, pk_len, _) in [MLDSA44, MLDSA65, MLDSA87] {
            let provider = RustCrypto::default();
            let (_, public_key) = provider.signature_key_gen(scheme).unwrap();

            provider
                .validate_signature_key(scheme, &public_key)
                .expect("a freshly generated public key must validate");

            let too_short = vec![0u8; pk_len - 1];
            assert!(
                provider.validate_signature_key(scheme, &too_short).is_err(),
                "an undersized key must be rejected for {scheme:?}"
            );
        }
    }
}
// PQ HPKE round trips; KEM KATs live in the underlying crates.
#[cfg(test)]
mod pq_hpke_tests {
    use super::*;
    use openmls_traits::{
        crypto::OpenMlsCrypto,
        types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType},
    };

    fn pq_configs() -> Vec<(HpkeKemType, HpkeKdfType, HpkeAeadType)> {
        vec![
            (
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ),
            (
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ),
            (
                HpkeKemType::MlKem768P256,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem768,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem1024,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::ChaCha20Poly1305,
            ),
        ]
    }

    /// Expected serialized `(private, public)` key lengths.
    fn expected_key_sizes(kem: HpkeKemType) -> (usize, usize) {
        match kem {
            HpkeKemType::MlKem768X25519 => (32, 1216),
            HpkeKemType::MlKem768P256 => (32, 1249),
            HpkeKemType::MlKem1024P384 => (32, 1665),
            HpkeKemType::MlKem768 => (64, 1184),
            HpkeKemType::MlKem1024 => (64, 1568),
            other => panic!("no expected key sizes for {other:?}"),
        }
    }

    #[test]
    fn pq_hpke_seal_open_round_trip() {
        let provider = RustCrypto::default();
        let plaintext = b"pq-hpke round-trip test";
        let info = b"test-info";
        let aad = b"test-aad";

        for (kem, kdf, aead) in pq_configs() {
            let ikm = vec![0x42u8; 64];
            let kp = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
                .unwrap_or_else(|e| {
                    panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let (expected_sk_len, expected_pk_len) = expected_key_sizes(kem);
            assert_eq!(
                kp.private.len(),
                expected_sk_len,
                "private key size mismatch for ({kem:?},{kdf:?},{aead:?}): \
                 got {} bytes, expected {expected_sk_len}",
                kp.private.len(),
            );
            assert_eq!(
                kp.public.len(),
                expected_pk_len,
                "public key size mismatch for ({kem:?},{kdf:?},{aead:?}): \
                 got {} bytes, expected {expected_pk_len}",
                kp.public.len(),
            );

            let ciphertext = provider
                .hpke_seal(HpkeConfig(kem, kdf, aead), &kp.public, info, aad, plaintext)
                .unwrap_or_else(|e| {
                    panic!("hpke_seal failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let recovered = provider
                .hpke_open(
                    HpkeConfig(kem, kdf, aead),
                    &ciphertext,
                    &kp.private,
                    info,
                    aad,
                )
                .unwrap_or_else(|e| {
                    panic!("hpke_open failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            assert_eq!(
                recovered, plaintext,
                "seal\u{2192}open round-trip mismatch for ({kem:?},{kdf:?},{aead:?})"
            );
        }
    }

    #[test]
    fn pq_hpke_open_rejects_tampered_ciphertext() {
        let provider = RustCrypto::default();
        let plaintext = b"pq-hpke tamper test";
        let info = b"test-info";
        let aad = b"test-aad";

        for (kem, kdf, aead) in pq_configs() {
            let ikm = vec![0x42u8; 64];
            let kp = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
                .unwrap_or_else(|e| {
                    panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let sealed = provider
                .hpke_seal(HpkeConfig(kem, kdf, aead), &kp.public, info, aad, plaintext)
                .unwrap_or_else(|e| {
                    panic!("hpke_seal failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let mut ct_bytes: Vec<u8> = sealed.ciphertext.as_slice().to_vec();
            assert!(
                !ct_bytes.is_empty(),
                "ciphertext is empty for ({kem:?},{kdf:?},{aead:?})"
            );
            ct_bytes[0] ^= 0xff;

            let tampered = openmls_traits::types::HpkeCiphertext {
                kem_output: sealed.kem_output.clone(),
                ciphertext: ct_bytes.into(),
            };

            let result = provider.hpke_open(
                HpkeConfig(kem, kdf, aead),
                &tampered,
                &kp.private,
                info,
                aad,
            );
            assert!(
                result.is_err(),
                "hpke_open must reject a tampered AEAD ciphertext \
                 for ({kem:?},{kdf:?},{aead:?}), but returned Ok"
            );
        }
    }

    #[test]
    fn pq_hpke_open_rejects_wrong_private_key() {
        let provider = RustCrypto::default();
        let plaintext = b"pq-hpke wrong-key test";
        let info = b"test-info";
        let aad = b"test-aad";

        for (kem, kdf, aead) in pq_configs() {
            let ikm_a = vec![0x42u8; 64];
            let kp_a = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm_a)
                .unwrap_or_else(|e| {
                    panic!("derive_hpke_keypair (A) failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let sealed = provider
                .hpke_seal(
                    HpkeConfig(kem, kdf, aead),
                    &kp_a.public,
                    info,
                    aad,
                    plaintext,
                )
                .unwrap_or_else(|e| {
                    panic!("hpke_seal failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let ikm_b = vec![0x99u8; 64];
            let kp_b = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm_b)
                .unwrap_or_else(|e| {
                    panic!("derive_hpke_keypair (B) failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let result = provider.hpke_open(
                HpkeConfig(kem, kdf, aead),
                &sealed,
                &kp_b.private,
                info,
                aad,
            );
            assert!(
                result.is_err(),
                "hpke_open must reject a mismatched private key \
                 for ({kem:?},{kdf:?},{aead:?}), but returned Ok"
            );
        }
    }

    #[test]
    fn pq_hpke_open_rejects_corrupted_kem_output() {
        let provider = RustCrypto::default();
        let plaintext = b"pq-hpke kem-output tamper test";
        let info = b"test-info";
        let aad = b"test-aad";

        for (kem, kdf, aead) in pq_configs() {
            let ikm = vec![0x42u8; 64];
            let kp = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
                .unwrap_or_else(|e| {
                    panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let sealed = provider
                .hpke_seal(HpkeConfig(kem, kdf, aead), &kp.public, info, aad, plaintext)
                .unwrap_or_else(|e| {
                    panic!("hpke_seal failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let mut enc_bytes: Vec<u8> = sealed.kem_output.as_slice().to_vec();
            assert!(
                !enc_bytes.is_empty(),
                "kem_output is empty for ({kem:?},{kdf:?},{aead:?})"
            );
            enc_bytes[0] ^= 0xff;

            let tampered = openmls_traits::types::HpkeCiphertext {
                kem_output: enc_bytes.into(),
                ciphertext: sealed.ciphertext.clone(),
            };

            let result = provider.hpke_open(
                HpkeConfig(kem, kdf, aead),
                &tampered,
                &kp.private,
                info,
                aad,
            );
            assert!(
                result.is_err(),
                "hpke_open must reject a tampered kem_output \
                 for ({kem:?},{kdf:?},{aead:?}), but returned Ok"
            );
        }
    }

    #[test]
    fn pq_hpke_export_sender_receiver_agree() {
        let provider = RustCrypto::default();
        let info = b"export-info";
        let exporter_ctx = b"exporter-context";
        let export_len = 32usize;

        for (kem, kdf, aead) in pq_configs() {
            let ikm = vec![0x37u8; 64];
            let kp = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
                .unwrap_or_else(|e| {
                    panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let (enc, tx_export) = provider
                .hpke_setup_sender_and_export(
                    HpkeConfig(kem, kdf, aead),
                    &kp.public,
                    info,
                    exporter_ctx,
                    export_len,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "hpke_setup_sender_and_export failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"
                    )
                });

            let rx_export = provider
                .hpke_setup_receiver_and_export(
                    HpkeConfig(kem, kdf, aead),
                    &enc,
                    &kp.private,
                    info,
                    exporter_ctx,
                    export_len,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "hpke_setup_receiver_and_export failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"
                    )
                });

            assert_eq!(
                &*tx_export, &*rx_export,
                "sender/receiver export mismatch for ({kem:?},{kdf:?},{aead:?})"
            );
        }
    }

    /// Ensures classical and PQ sender operations use the provider RNG.
    #[test]
    fn hpke_seal_is_deterministic_under_seeded_rng() {
        let seed = EntropySeed::from_raw([0x5Au8; EntropySeed::EXPECTED_LEN]);

        let info = b"determinism-info";
        let aad = b"determinism-aad";
        let plaintext = b"determinism plaintext payload";

        let cases: Vec<(HpkeConfig, Vec<u8>)> = vec![
            (
                HpkeConfig(
                    HpkeKemType::DhKem25519,
                    HpkeKdfType::HkdfSha256,
                    HpkeAeadType::AesGcm128,
                ),
                vec![0x11u8; 64],
            ),
            (
                HpkeConfig(
                    HpkeKemType::MlKem768X25519,
                    HpkeKdfType::HkdfSha384,
                    HpkeAeadType::AesGcm256,
                ),
                vec![0x22u8; 64],
            ),
        ];

        for (config, ikm) in cases {
            let HpkeConfig(kem, kdf, aead) = config;

            let recip = RustCrypto::default()
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
                .unwrap_or_else(|e| panic!("derive_hpke_keypair failed for {kem:?}: {e:?}"));

            let provider_a = RustCrypto::new_with_seed(seed.clone());
            let provider_b = RustCrypto::new_with_seed(seed.clone());

            let ct_a = provider_a
                .hpke_seal(
                    HpkeConfig(kem, kdf, aead),
                    &recip.public,
                    info,
                    aad,
                    plaintext,
                )
                .unwrap_or_else(|e| panic!("hpke_seal A failed for {kem:?}: {e:?}"));
            let ct_b = provider_b
                .hpke_seal(
                    HpkeConfig(kem, kdf, aead),
                    &recip.public,
                    info,
                    aad,
                    plaintext,
                )
                .unwrap_or_else(|e| panic!("hpke_seal B failed for {kem:?}: {e:?}"));

            assert_eq!(
                ct_a.kem_output.as_slice(),
                ct_b.kem_output.as_slice(),
                "kem_output must be deterministic under identical seeded RNG for {kem:?}"
            );
            assert_eq!(
                ct_a.ciphertext.as_slice(),
                ct_b.ciphertext.as_slice(),
                "ciphertext must be deterministic under identical seeded RNG for {kem:?}"
            );

            let ct_next = provider_a
                .hpke_seal(
                    HpkeConfig(kem, kdf, aead),
                    &recip.public,
                    info,
                    aad,
                    plaintext,
                )
                .unwrap_or_else(|e| panic!("second hpke_seal failed for {kem:?}: {e:?}"));
            assert_ne!(
                ct_a.kem_output.as_slice(),
                ct_next.kem_output.as_slice(),
                "successive encapsulations must advance the RNG for {kem:?}"
            );

            let recovered = provider_a
                .hpke_open(HpkeConfig(kem, kdf, aead), &ct_a, &recip.private, info, aad)
                .unwrap_or_else(|e| panic!("hpke_open failed for {kem:?}: {e:?}"));
            assert_eq!(recovered, plaintext, "round-trip mismatch for {kem:?}");
        }
    }

    #[test]
    fn pq_suites_supported() {
        use openmls_traits::crypto::OpenMlsCrypto;
        let provider = RustCrypto::default();
        let pq_suites = [
            Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44,
        ];
        let listed = provider.supported_ciphersuites();
        for cs in pq_suites {
            assert!(provider.supports(cs).is_ok(), "{cs:?} must be supported");
            assert!(
                listed.contains(&cs),
                "{cs:?} must be listed in supported_ciphersuites()"
            );
        }
    }
}
