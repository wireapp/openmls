use rand_core::{RngCore, SeedableRng};
use std::sync::RwLock;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, KeyInit,
};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use ml_dsa::{
    KeyInit as MlDsaKeyInit, MlDsa65, MlDsa87, MlDsaParams, Signature as MlDsaSignature,
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
        Self {
            rng: RwLock::new(rand_chacha::ChaCha20Rng::from_entropy()),
        }
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

/// Length of the 32-byte seed used as the stored ML-DSA private key (FIPS-204 xi)
const MLDSA_SEED_LEN: usize = 32;

/// Generate an ML-DSA key pair for parameter set P.
///
/// The private key is stored as the 32-byte FIPS-204 seed (xi); the signing key is
/// reconstructed from it via SigningKey::from_seed when signing. Returns
/// (private_seed, raw_public_key) with the public key in raw FIPS-204 encoding.
fn mldsa_key_gen<P: MlDsaParams>(
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Wrap the transient FIPS-204 seed (secret entropy) in Zeroizing so the
    // local copy is wiped on drop, consistent with the ed25519/sk_buf paths.
    // (The 32-byte seed is still returned to the caller as the stored key.)
    let mut seed = zeroize::Zeroizing::new(B32::default());
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| CryptoError::InsufficientRandomness)?;
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let public_key = signing_key.expanded_key().verifying_key().encode().to_vec();
    Ok((seed.to_vec(), public_key))
}

/// Sign data with ML-DSA parameter set P using the deterministic, empty-context
/// FIPS-204 variant required by MLS. key is the 32-byte seed produced by keygen.
fn mldsa_sign<P: MlDsaParams>(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != MLDSA_SEED_LEN {
        return Err(CryptoError::CryptoLibraryError);
    }
    // The reconstructed seed is secret key material; scrub it on drop.
    let seed =
        zeroize::Zeroizing::new(B32::try_from(key).map_err(|_| CryptoError::CryptoLibraryError)?);
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let signature = signing_key
        .expanded_key()
        .sign_deterministic(data, b"")
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(signature.to_vec())
}

/// Verify a raw FIPS-204 ML-DSA signature over data for parameter set P with
/// empty context. pk and signature are raw FIPS-204 byte strings.
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
            // Official SHAKE256 PQ suites (0xF001-0xF009): key schedule now driven by the
            // SHAKE256 one-shot KDF (draft-ietf-mls-pq-ciphersuites "One shot KDFs in MLS",
            // PR #21). The bytes are provisional until that PR merges, see openmls pq_kdf.
            | Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256
            | Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256
            | Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 => Ok(()),
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

    fn shake256_kdf_derive(
        &self,
        input: &[u8],
        out_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        let mut out = zeroize::Zeroizing::new(vec![0u8; out_len]);
        reader.read(&mut out);
        Ok(out.as_slice().into())
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
        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;

                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadEncryptionError)
            }
            AeadType::Aes256Gcm => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AeadEncryptionError)?;

                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadEncryptionError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::AeadEncryptionError)?;

                chacha_poly
                    .encrypt(nonce.into(), Payload { msg: data, aad })
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
        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::Aes256Gcm => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .decrypt(nonce.into(), Payload { msg: ct_tag, aad })
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
                let sk = p256::ecdsa::SigningKey::random(&mut *rng);
                let pk = sk.verifying_key().to_encoded_point(false).to_bytes().into();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let sk = p384::ecdsa::SigningKey::random(&mut *rng);
                let pk = sk.verifying_key().to_encoded_point(false).to_bytes().into();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let sk = p521::ecdsa::SigningKey::random(&mut *rng);
                let pk = p521::ecdsa::VerifyingKey::from(&sk)
                    .to_encoded_point(false)
                    .to_bytes()
                    .into();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::generate(&mut *rng);
                let pk = k.verifying_key();
                Ok((k.to_bytes().into(), pk.to_bytes().into()))
            }
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
            // Raw FIPS-204 public key sizes for the two ML-DSA params
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
                let k = p256::ecdsa::SigningKey::from_bytes(key.into())
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: p256::ecdsa::DerSignature = k
                    .try_sign(data)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let k = p384::ecdsa::SigningKey::from_bytes(key.into())
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: p384::ecdsa::DerSignature = k
                    .try_sign(data)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let k = p521::ecdsa::SigningKey::from_slice(&*normalize_p521_secret_key(key))
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: p521::ecdsa::DerSignature = k
                    .try_sign(data)
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
        // Acquire the provider's seeded RNG for the sender (encapsulation) op
        let mut rng = self
            .rng
            .write()
            .map_err(|_| CryptoError::HpkeEncryptionError)?;
        let mut rng = hpke_core::HpkeRng(&mut rng);
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
            // PQ HPKE arms, all on KdfShake256
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm128,
                hpke::kdf::KdfShake256,
                hpke::kem::XWing,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::XWing,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm128,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem768P256,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem768P256,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_seal::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem1024P384,
            >(pk_r, info, aad, ptxt, &mut rng),
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::KdfShake256,
                    hpke::kem::MlKem768,
                >(pk_r, info, aad, ptxt, &mut rng)
            }
            HpkeConfig(HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::KdfShake256,
                    hpke::kem::MlKem1024,
                >(pk_r, info, aad, ptxt, &mut rng)
            }
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
            // PQ HPKE arms, all on KdfShake256
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm128,
                hpke::kdf::KdfShake256,
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
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
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
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm128,
                hpke::kdf::KdfShake256,
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
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
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
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_open::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem1024P384,
            >(
                sk_r,
                input.kem_output.as_slice(),
                info,
                aad,
                input.ciphertext.as_slice(),
            )?,
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::KdfShake256,
                    hpke::kem::MlKem768,
                >(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::KdfShake256,
                    hpke::kem::MlKem1024,
                >(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
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
        // Acquire the provider's seeded RNG for the sender setup (encapsulation)
        let mut rng = self
            .rng
            .write()
            .map_err(|_| CryptoError::SenderSetupError)?;
        let mut rng = hpke_core::HpkeRng(&mut rng);
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
            // PQ HPKE arms, all on KdfShake256
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm128,
                hpke::kdf::KdfShake256,
                hpke::kem::XWing,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::XWing,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm128,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem768P256,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem768P256,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_tx::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem1024P384,
            >(pk_r, info, exporter_context, exporter_length, &mut rng)?,
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::KdfShake256,
                    hpke::kem::MlKem768,
                >(pk_r, info, exporter_context, exporter_length, &mut rng)?
            }
            HpkeConfig(HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::KdfShake256,
                    hpke::kem::MlKem1024,
                >(pk_r, info, exporter_context, exporter_length, &mut rng)?
            }
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
            // PQ HPKE arms, all on KdfShake256
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm128,
                hpke::kdf::KdfShake256,
                hpke::kem::XWing,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::XWing,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm128,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem768P256,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem768P256,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ) => hpke_core::hpke_export_rx::<
                hpke::aead::AesGcm256,
                hpke::kdf::KdfShake256,
                hpke::kem::MlKem1024P384,
            >(enc, sk_r, info, exporter_context, exporter_length)?,
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::KdfShake256,
                    hpke::kem::MlKem768,
                >(enc, sk_r, info, exporter_context, exporter_length)?
            }
            HpkeConfig(HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<
                    hpke::aead::AesGcm256,
                    hpke::kdf::KdfShake256,
                    hpke::kem::MlKem1024,
                >(enc, sk_r, info, exporter_context, exporter_length)?
            }
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
            // PQ KEM keypair derivation
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

    /// Glue between the provider's seeded rand_chacha::ChaCha20Rng (which speaks
    /// rand_core 0.6) and the rand_core 0.10 traits that hpke insists on. The
    /// two versions are gratuitously incompatible.
    ///
    /// In 0.10 the one trait you actually implement is TryRng (with an associated
    /// Error); Rng, the leftover RngCore, and the CryptoRng marker all fall
    /// out of TryRng<Error = Infallible> / TryCryptoRng for free. hpke's
    /// *_with_rng functions want CryptoRng, so we implement TryRng with an
    /// Infallible error and slap on the TryCryptoRng marker. The thing underneath
    /// is a CSPRNG, so calling it crypto-secure isn't a lie. Every method just hands
    /// off to the 0.6 RngCore::fill_bytes, which can't fail.
    pub(super) struct HpkeRng<'a>(pub(super) &'a mut rand_chacha::ChaCha20Rng);

    impl hpke::rand_core::TryRng for HpkeRng<'_> {
        type Error = hpke::rand_core::Infallible;

        #[inline]
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            // rand_core 0.6 RngCore::next_u32 is infallible
            Ok(rand_core::RngCore::next_u32(self.0))
        }

        #[inline]
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(rand_core::RngCore::next_u64(self.0))
        }

        #[inline]
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            // rand_core 0.6 RngCore::fill_bytes is infallible
            rand_core::RngCore::fill_bytes(self.0, dst);
            Ok(())
        }
    }

    // Marker: the inner ChaCha20Rng is a CSPRNG
    impl hpke::rand_core::TryCryptoRng for HpkeRng<'_> {}

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
        rng: &mut HpkeRng<'_>,
    ) -> Result<HpkeCiphertext, CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let key =
            Kem::PublicKey::from_bytes(public_key).map_err(|_| CryptoError::HpkeEncryptionError)?;
        // Hand the sender op the provider's seeded RNG instead of the OS one, so seal
        // stays deterministic under new_with_seed and doesn't blow up on wasm, which
        // has no getrandom to reach for
        let (encapped, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
            &hpke::OpModeS::Base,
            &key,
            info,
            plaintext,
            aad,
            rng,
        )
        .map_err(|_| CryptoError::HpkeEncryptionError)?;

        Ok(HpkeCiphertext {
            kem_output: encapped.to_bytes().to_vec().into(),
            ciphertext: ciphertext.into(),
        })
    }

    #[allow(dead_code)]
    pub fn hpke_gen_keypair<Kem: hpke::Kem>(
        rng: &mut HpkeRng<'_>,
    ) -> Result<HpkeKeyPair, CryptoError> {
        use hpke::Serializable as _;
        // Seeded RNG again, not Kem::gen_keypair() which would grab the OS one
        let (sk, pk) = Kem::gen_keypair_with_rng(rng);
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
        rng: &mut HpkeRng<'_>,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let key =
            Kem::PublicKey::from_bytes(tx_public_key).map_err(|_| CryptoError::SenderSetupError)?;
        // Seeded RNG into the sender setup as well; this used to reach for the OS RNG
        let (kem_output, ctx) =
            hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(&hpke::OpModeS::Base, &key, info, rng)
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

    // (scheme, public key length, signature length) for the two ML-DSA variants
    const MLDSA65: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA65, 1952, 3309);
    const MLDSA87: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA87, 2592, 4627);

    #[test]
    fn signature_public_key_len_matches_fips204() {
        let provider = RustCrypto::default();
        assert_eq!(provider.signature_public_key_len(MLDSA65.0), MLDSA65.1);
        assert_eq!(provider.signature_public_key_len(MLDSA87.0), MLDSA87.1);
    }

    #[test]
    fn keygen_sign_verify_round_trip() {
        for (scheme, pk_len, sig_len) in [MLDSA65, MLDSA87] {
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
        for (scheme, _, _) in [MLDSA65, MLDSA87] {
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
        for (scheme, _, _) in [MLDSA65, MLDSA87] {
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
        // FIPS-204 deterministic variant with empty context: identical inputs
        // must produce identical signatures
        for (scheme, _, _) in [MLDSA65, MLDSA87] {
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
        for (scheme, pk_len, _) in [MLDSA65, MLDSA87] {
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
// ML-DSA known-answer tests (Project Wycheproof v1)
//
// The round-trip, tamper, and determinism tests above are all circular: an
// implementation that's wrong but internally consistent would pass every one of
// them and we'd be none the wiser. These KATs are the antidote, pinning verify
// (and the deterministic seed->sign and seed->public-key mappings) to vectors
// somebody else computed. If our idea of FIPS-204 disagrees with Wycheproof's,
// this is where it blows up.
//
// Pulled verbatim from Project Wycheproof (https://github.com/C2SP/wycheproof),
// branch master:
//   testvectors_v1/mldsa_65_verify_test.json
//   testvectors_v1/mldsa_87_verify_test.json
//   testvectors_v1/mldsa_65_sign_seed_test.json
//   testvectors_v1/mldsa_87_sign_seed_test.json
//
// Every case here is the pure FIPS-204 external interface, empty context, no
// prehash, which is what our verify_with_context(msg, b"", sig) and
// sign_deterministic(msg, b"") do. Public keys are raw FIPS-204 (1952 / 2592
// bytes), signatures raw FIPS-204 (3309 / 4627 bytes), and the private input is
// the 32-byte seed (xi). The hex below is copied byte-for-byte from those files,
// with the tcId noted on each case so you can go look it up.
#[cfg(test)]
mod mldsa_kat_tests {
    use super::*;
    use openmls_traits::crypto::OpenMlsCrypto;

    /// Decode an ASCII hex string into bytes. Tiny local helper so the KATs do
    /// not introduce a hex dependency.
    fn unhex(s: &str) -> Vec<u8> {
        fn nibble(b: u8) -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex digit: {b}"),
            }
        }
        let s = s.as_bytes();
        assert!(s.len() % 2 == 0, "odd-length hex string");
        s.chunks(2)
            .map(|c| (nibble(c[0]) << 4) | nibble(c[1]))
            .collect()
    }

    // ---------- ML-DSA-65 sigVer KATs (mldsa_65_verify_test.json) ----------
    #[test]
    fn wycheproof_mldsa65_sigver_valid_accepted() {
        let provider = RustCrypto::default();
        // tcId 1: baseline (ValidSignature)
        {
            let pk = unhex("f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7eac20c5754255206a178f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe283d106eaef92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7ea9be178be35405683b44367af85d2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413b843b83f3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa855f827049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab29e892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edbafa2747db9bc42f92af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f9568bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d48cc26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb929bee9ff5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7dcbebeb5a239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e0501944409f32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c86744ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b62013965ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb06f9116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bdd0c31e9f1080e8ed8eb99fde66bafb29e3357389fe3785b60c78e229ef073e1b65e34d848bd4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b636afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a842701603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb271416b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a49075767ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf252577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd3375e608e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67acf29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b3024df986391badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa6247342905995233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca3268265c9ce042d50915430a6c455f32277da42f9962fb9163b623231ebc080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd683027bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f8881638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d25733143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480dcbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba3768c55bb1f07aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430268c1492a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776a37a1f56fbf7d08e591f978da49c3870625879f70e2418aec5cba32fa8c346fa9038baebc35ad0068a4d03537aee14c2e71570a87490377fa8dd66f995aa044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867bae249431dcf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455ff47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87173a18dc");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("69da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c2862344713a1e9c086a44f9a870a3ccc14de62d6c12b278c354d7197c4d6d7f83d1422b29b250f5ee3fec118311d905e5db2b4b8b23b8d542202d6652f6dc3f9d7ed51f2463082d3f145cfd0fa7ac548a47e91c1ccb1a55b215e90ab355bfc6d67154287b1dfae0fb530264dbb841a7684b396e5ca0459d795216416a9d232bc89b32e0f9461f53107c78e66c8e876554e8ddd501867b55dcfc1fb33f102e03373cdd192640f1027a08ce277b468f6ed0fe80a9d6cd2d6b2f7a3738c8325d95b0ccc6e7b9fb000c923b92298e0867d4a9f6dd5513e8001033c633bb1641ee66349487224dd43386c7fcc29916332066a868100d46e2c5b8354c28f087a024cba27694afc4c1665e0d72b37686919ad55052cc63a144febe4e2a0c9ae416e064e289f9f69cbb883665d1130826b7b74e30c94a2b98b67b471663e3d66326db3b43bebf958e8665b68eda90e8c5d9494b0c7c9ec48800910dd6d906b1fcd47a0aac462ac87b126d21b5ba150df61f752257ddf5a063b4a5b150371d625535e3b2874b9fe548960ff67931cd6c12496e8213e2ace6fff48e6bdc60310e49389f62579db26b92ad73e9d3f23942cab51784f48b3660b6450caecbb0df2aa4c8e56577f5ea450d2f7f51aacc0b304a62250bf2cae7b99dcd955b6596625d06da1c67f730b706fdba630f00fd891830d251484640b7258ab364d6fd9986878fffa69b7c44b92e43143affae8b098e1d27716850f37553bf266cdfb561abbcdbfeb80752b364434e64b80429b54cc88693ce03dc0fa147f0741b215f0728499bdc25140aafc976ac99e910ba8a8a50d21b7bddaa28626b3b90a93fd44077068357c81d36e735eda4362930adead4951a0baa104f384fc70e842a9f329e1868b07b455e9cc3fecd54805c9052e70f88c3b92fe0fc6a4d7dda18cf5694e5398860e439a1e19d5a66f2fbc0aacdd1a498711bb16054796c015a715395ef6174e37b04eda589b673c4d5dda737817fb52f392caf7a72d7a3e84b2180cb5b75bc8af065bdc05c3e4040435a1b160081352ac43e09cbf2ead6e09c2b0be0e37894888fe2812f68806f957c13fce6ff167bcee21d4f412ec95a4847f3db7bf441223a4d4ca9ed69adb4de8a4b5b01c775f2721226e6c59ff26fc38e1bb78a384b30e7b55f082e264d8f25e31518619ddd6b6a9faf8aa6cdb5eab75ed59a33825d5ef8b93bde5d120ada773fcc0852b918f4f03e2d2a543b15363adb823eb1f6c533b98d940411e1f5c1cf521f9f63d5454697608326625fffe01bf87f44187dad631df2898effd2c291d98222e564abe3b042b75e90c9c54667842fa8ebb68a1244bf8e0c3ae3ee5f97d5ddeefd986c4bd3f99d877c2cc2381a89abdc61713d38cee58bf69805a485c288d21b15843147066b4a74c69dc25de878e21d35fdfe6746feb4c166606bf3219e42cf63581e7e6bd6570f40f8fae590cedf5106fe57037ccb2324b74fca6500f6ed3d0736cdcc67d04f8fa9e80054a5bd7c8459fc1abb1c4c78677d7f6b325af94a0e5c9c7db0a748e12c5265e8724947d9b5c4bab1a8b6faec827cc41ec115ef3c2d7348cddabddfbc8436f3b41765e13f3762b3b45ed23156f085831e726a55d4b83848b3d1d3352aab9edcc0ac2388f2383f6301ad813b917ee3f23734e057832ae4cf65e668c9ddd0bdd0f9d8b6693254649668aa91a1fa5eb7c59859bb6ddd36c25f4a2223f5d688b480d0388fa307ea69298f9bf7737f6b3dbfda87b331affd75cd8d88f0460e98ebc2890b217bd6d11000a3a088cd837f4f8859a43f76afaaab05a0c3007a149d4d6b9155cadc2c9b55003efdec5012b6272b87183694c505f0446ede55f35b8ab201f9eda974ff840eccb0f004fa3acf753acd0613f66e2a6ac82e322199d37b4af83cbb3d98371c31be79bb42331e819644cbad2ce27a04e4c517998692cd8331552892e199a01a6922bda4d38ac4c01f708809e529c3216eaab399ef25b350ea213ba47126f278140e17391ca7139bd13c56f415e6b74aed8dbfbf38c95dc6db366fd72aa863a27fa1ebf198716400b978a3709e35039731930406588ebdffd35fa230a9b75fce41d7acd214ca4f0029896c137495eade0cf4d10fe621c73f01061acb077de72177ff5dbc6f0c5bec681aa34668ca4fcdd727525068b0b0e9072971b84ef6ce11d5c3c6024da40966703dcc2b33ae04f677677635a55db508f34f1403cdbe37960c8577dac3d848b29f3b5c5c6c56fb74f34c8f4634c04b8cce9b218f1760ca00e6de87efd14087c633469c892bf3e319443336733bb60cfb44941bfa25229aa24384d812db90fe74e0f93fda005eea87400736cabc036f71421b6657b1674d4a8f76cbbf3a8b1c0af82f72973927752257c532db439d96762ad64f102551a9d03f9ce3d8cc850c393c128bf8054bb55bb92ea31ec0706f083a9cf90424c617f8ad2a21225d1913c30e8f47a6b7131304d536a85596ebfd987b64b6bf3c51638d6c839214b53c3c10aa52bd9c6eb77fcf80b5e3b724dec1381d0e02207a6adc73ff53d9d1ffcee1c4a28fa5445ce518eee937074ff7a402f5bbcb362ff090415f9dbd93b62ee56dc8c50e4d2e34c6c621650c0dffe311484e95d68de77170c909c815828946aeeec7ede56bcf433e22fc63a33f764ced1f9242f3d26dc7558686e471f30fbe9304d3d56af8b23e72a4088970b24b2f7e968c1d0392eeeb0b0f0ac8c176547a5383d948ed15484b79e21314a1f28ed624f61e5aaecf2269e5b027e1910ffddede52fad4e8da224e8a10b079548fa7cd44172f4991adfd7623d13e5a19c812824bcf990c07c9721ded9093be6ce7bc7da3ac8c932133a64396b822be92b088844991596df893625a4ef24543bf75a10d7d17ff70350ef62ce3a7758aebbf9b3977b08becb9ea28376082f607965f2cded28bbdb39dab7e00833b0488370d221742b66e27d9ee2d9dd07f401bc22a62c8a9d8d3a290c63804991496aafa47a32578f583cfb53d0c2199055973440d7535e0da6cb2957f4e04002ecea68f9c3ff76cade27ed15fd7835989d0abb197fe32f68636139a42710644bb25860ff33f539200e3ccb8a7738422ca0fa0c744b4c19d15c5d4a3cb082e20a78e20b5a4965b043595cbcacad500b5adbb6cd597e6a4b9c5ea6a1f2e653b5474da277f1818048094ac9e0e1e0b20068d1c1ce5a114a4db7195057a6ce4d221c336fdc29190fee8ff855cae8b7f7c02eec21f972c827066d9c6dcc4a4179bc44ea9b88abe5124bf78b071e09e9af43f739a6e1030091fc091e73edc447f25c68bf84b8df7aa8f091ab42662b93e02c27003afc7b0ca69efcfa60bd53d4d78ceb7c4d2c8fd5ed7e8b35024de849e06400ad145fdb28348d22b317ccec704c401f88db1af2a5348223f5cefd914e404c9d73805d0de77211881486f1bf4aadacadd3ae2588f0db7b5e6957fed50a374f541cfe5e4e923c82ec47e5b3d2c70ad6760c79cd5080b490bdc75f9ef5e1d17f0978b1e8770775f902b9463e6980e1683b2454751ba2dad4a2e6460924bd60ff49b03230cb11fcd04a0388e60874c35d3f6cfc4dd487665e1b16578751eaea89e126bf58044596e3188c7a9631017be1f2dcd7d612331832ff8755460dc496aa99a61ea053c78e72607a18213ff9ef4bb880903b91e9a43e0b1f0ed1511b2eca2f4253fcfbd7d0faebf3680fbf0a45df231544882c9c46505c726d56905d02fd046c1652d8fd06d15286a1a8f8b69fbd825ca421fd80f5e9ba1a23f924937ad049adeec60c78fea1adf9b1ef7e8ac4d1ded18f1a801b0bda8fe9a88098825ff3eef5c1fc68cbea143310b39543293f3f5fbcf4773b02054c0bc79f00554947c7604b36389c0c45f597a88f3713456b4cfd83b30cb6520b624aa09c812066a8cd542dc67e19e4c92b562b4e0f6799fe57d9d4f4f3e0b6fabff4b1fc190bf1e78775ebcbe3655d370ca6c08f48decf6153a4989eeab6921f8475f85197f51d651e563994257df57977e5f219b4879751de57ab0374b407a21adb4ba520bb35e7b7508675bf49f4e432190451423cbd529fc79b22baae9cb1d8660c3a49c456ac03bc06c0ef3b02f7d8acd40919315206fb38e715139c9bd6f89a58634fe683df03f5bda719764f6c38131bc5ba1c53244472ef73834ade04b86ca08dd753141ac0a9a230e246735060a044018bc9b75d50134b20e6219c13f8325b5a0201e9453f6f012fe72e829ee1c637fe30037a9212a31c6e713726a6cd4cf2dd66ffdba77f1e2800e717940f231d04aa2e4e88dea084754947d848c0271856bfe659922408449858a81fa6583f062d96898d18ec53664f0067eb9b9c40ad2579ba9802abd8d1bf287e49d94ae397e784db14b5f7010ee4fc42e6e3c8ba80370afc188fcecaf466ea830d7b16362e5c9329980b981decc7174f3ff70a35d8a180ee12ed0cbffd4e8d14eb503387e4959f702d4293109e922eb561371f9ab21475821f8555d92f0aa1c3d841a6f1eabd4e663993636c754ce2b3c3f6a6b6d0b161e777b8296d7dce7fd162970496494d4f60716244a5a7fb7cee40e1d565e6566697e8f9300000000000000000000000005101318212b");
            provider
                .verify_signature(SignatureScheme::MLDSA65, &msg, &pk, &sig)
                .expect("Wycheproof valid ML-DSA-65 vector tcId 1 must verify");
        }
        // tcId 2: empty provided context (ValidSignature)
        {
            let pk = unhex("f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7eac20c5754255206a178f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe283d106eaef92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7ea9be178be35405683b44367af85d2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413b843b83f3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa855f827049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab29e892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edbafa2747db9bc42f92af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f9568bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d48cc26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb929bee9ff5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7dcbebeb5a239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e0501944409f32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c86744ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b62013965ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb06f9116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bdd0c31e9f1080e8ed8eb99fde66bafb29e3357389fe3785b60c78e229ef073e1b65e34d848bd4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b636afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a842701603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb271416b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a49075767ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf252577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd3375e608e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67acf29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b3024df986391badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa6247342905995233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca3268265c9ce042d50915430a6c455f32277da42f9962fb9163b623231ebc080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd683027bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f8881638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d25733143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480dcbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba3768c55bb1f07aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430268c1492a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776a37a1f56fbf7d08e591f978da49c3870625879f70e2418aec5cba32fa8c346fa9038baebc35ad0068a4d03537aee14c2e71570a87490377fa8dd66f995aa044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867bae249431dcf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455ff47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87173a18dc");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("69da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c2862344713a1e9c086a44f9a870a3ccc14de62d6c12b278c354d7197c4d6d7f83d1422b29b250f5ee3fec118311d905e5db2b4b8b23b8d542202d6652f6dc3f9d7ed51f2463082d3f145cfd0fa7ac548a47e91c1ccb1a55b215e90ab355bfc6d67154287b1dfae0fb530264dbb841a7684b396e5ca0459d795216416a9d232bc89b32e0f9461f53107c78e66c8e876554e8ddd501867b55dcfc1fb33f102e03373cdd192640f1027a08ce277b468f6ed0fe80a9d6cd2d6b2f7a3738c8325d95b0ccc6e7b9fb000c923b92298e0867d4a9f6dd5513e8001033c633bb1641ee66349487224dd43386c7fcc29916332066a868100d46e2c5b8354c28f087a024cba27694afc4c1665e0d72b37686919ad55052cc63a144febe4e2a0c9ae416e064e289f9f69cbb883665d1130826b7b74e30c94a2b98b67b471663e3d66326db3b43bebf958e8665b68eda90e8c5d9494b0c7c9ec48800910dd6d906b1fcd47a0aac462ac87b126d21b5ba150df61f752257ddf5a063b4a5b150371d625535e3b2874b9fe548960ff67931cd6c12496e8213e2ace6fff48e6bdc60310e49389f62579db26b92ad73e9d3f23942cab51784f48b3660b6450caecbb0df2aa4c8e56577f5ea450d2f7f51aacc0b304a62250bf2cae7b99dcd955b6596625d06da1c67f730b706fdba630f00fd891830d251484640b7258ab364d6fd9986878fffa69b7c44b92e43143affae8b098e1d27716850f37553bf266cdfb561abbcdbfeb80752b364434e64b80429b54cc88693ce03dc0fa147f0741b215f0728499bdc25140aafc976ac99e910ba8a8a50d21b7bddaa28626b3b90a93fd44077068357c81d36e735eda4362930adead4951a0baa104f384fc70e842a9f329e1868b07b455e9cc3fecd54805c9052e70f88c3b92fe0fc6a4d7dda18cf5694e5398860e439a1e19d5a66f2fbc0aacdd1a498711bb16054796c015a715395ef6174e37b04eda589b673c4d5dda737817fb52f392caf7a72d7a3e84b2180cb5b75bc8af065bdc05c3e4040435a1b160081352ac43e09cbf2ead6e09c2b0be0e37894888fe2812f68806f957c13fce6ff167bcee21d4f412ec95a4847f3db7bf441223a4d4ca9ed69adb4de8a4b5b01c775f2721226e6c59ff26fc38e1bb78a384b30e7b55f082e264d8f25e31518619ddd6b6a9faf8aa6cdb5eab75ed59a33825d5ef8b93bde5d120ada773fcc0852b918f4f03e2d2a543b15363adb823eb1f6c533b98d940411e1f5c1cf521f9f63d5454697608326625fffe01bf87f44187dad631df2898effd2c291d98222e564abe3b042b75e90c9c54667842fa8ebb68a1244bf8e0c3ae3ee5f97d5ddeefd986c4bd3f99d877c2cc2381a89abdc61713d38cee58bf69805a485c288d21b15843147066b4a74c69dc25de878e21d35fdfe6746feb4c166606bf3219e42cf63581e7e6bd6570f40f8fae590cedf5106fe57037ccb2324b74fca6500f6ed3d0736cdcc67d04f8fa9e80054a5bd7c8459fc1abb1c4c78677d7f6b325af94a0e5c9c7db0a748e12c5265e8724947d9b5c4bab1a8b6faec827cc41ec115ef3c2d7348cddabddfbc8436f3b41765e13f3762b3b45ed23156f085831e726a55d4b83848b3d1d3352aab9edcc0ac2388f2383f6301ad813b917ee3f23734e057832ae4cf65e668c9ddd0bdd0f9d8b6693254649668aa91a1fa5eb7c59859bb6ddd36c25f4a2223f5d688b480d0388fa307ea69298f9bf7737f6b3dbfda87b331affd75cd8d88f0460e98ebc2890b217bd6d11000a3a088cd837f4f8859a43f76afaaab05a0c3007a149d4d6b9155cadc2c9b55003efdec5012b6272b87183694c505f0446ede55f35b8ab201f9eda974ff840eccb0f004fa3acf753acd0613f66e2a6ac82e322199d37b4af83cbb3d98371c31be79bb42331e819644cbad2ce27a04e4c517998692cd8331552892e199a01a6922bda4d38ac4c01f708809e529c3216eaab399ef25b350ea213ba47126f278140e17391ca7139bd13c56f415e6b74aed8dbfbf38c95dc6db366fd72aa863a27fa1ebf198716400b978a3709e35039731930406588ebdffd35fa230a9b75fce41d7acd214ca4f0029896c137495eade0cf4d10fe621c73f01061acb077de72177ff5dbc6f0c5bec681aa34668ca4fcdd727525068b0b0e9072971b84ef6ce11d5c3c6024da40966703dcc2b33ae04f677677635a55db508f34f1403cdbe37960c8577dac3d848b29f3b5c5c6c56fb74f34c8f4634c04b8cce9b218f1760ca00e6de87efd14087c633469c892bf3e319443336733bb60cfb44941bfa25229aa24384d812db90fe74e0f93fda005eea87400736cabc036f71421b6657b1674d4a8f76cbbf3a8b1c0af82f72973927752257c532db439d96762ad64f102551a9d03f9ce3d8cc850c393c128bf8054bb55bb92ea31ec0706f083a9cf90424c617f8ad2a21225d1913c30e8f47a6b7131304d536a85596ebfd987b64b6bf3c51638d6c839214b53c3c10aa52bd9c6eb77fcf80b5e3b724dec1381d0e02207a6adc73ff53d9d1ffcee1c4a28fa5445ce518eee937074ff7a402f5bbcb362ff090415f9dbd93b62ee56dc8c50e4d2e34c6c621650c0dffe311484e95d68de77170c909c815828946aeeec7ede56bcf433e22fc63a33f764ced1f9242f3d26dc7558686e471f30fbe9304d3d56af8b23e72a4088970b24b2f7e968c1d0392eeeb0b0f0ac8c176547a5383d948ed15484b79e21314a1f28ed624f61e5aaecf2269e5b027e1910ffddede52fad4e8da224e8a10b079548fa7cd44172f4991adfd7623d13e5a19c812824bcf990c07c9721ded9093be6ce7bc7da3ac8c932133a64396b822be92b088844991596df893625a4ef24543bf75a10d7d17ff70350ef62ce3a7758aebbf9b3977b08becb9ea28376082f607965f2cded28bbdb39dab7e00833b0488370d221742b66e27d9ee2d9dd07f401bc22a62c8a9d8d3a290c63804991496aafa47a32578f583cfb53d0c2199055973440d7535e0da6cb2957f4e04002ecea68f9c3ff76cade27ed15fd7835989d0abb197fe32f68636139a42710644bb25860ff33f539200e3ccb8a7738422ca0fa0c744b4c19d15c5d4a3cb082e20a78e20b5a4965b043595cbcacad500b5adbb6cd597e6a4b9c5ea6a1f2e653b5474da277f1818048094ac9e0e1e0b20068d1c1ce5a114a4db7195057a6ce4d221c336fdc29190fee8ff855cae8b7f7c02eec21f972c827066d9c6dcc4a4179bc44ea9b88abe5124bf78b071e09e9af43f739a6e1030091fc091e73edc447f25c68bf84b8df7aa8f091ab42662b93e02c27003afc7b0ca69efcfa60bd53d4d78ceb7c4d2c8fd5ed7e8b35024de849e06400ad145fdb28348d22b317ccec704c401f88db1af2a5348223f5cefd914e404c9d73805d0de77211881486f1bf4aadacadd3ae2588f0db7b5e6957fed50a374f541cfe5e4e923c82ec47e5b3d2c70ad6760c79cd5080b490bdc75f9ef5e1d17f0978b1e8770775f902b9463e6980e1683b2454751ba2dad4a2e6460924bd60ff49b03230cb11fcd04a0388e60874c35d3f6cfc4dd487665e1b16578751eaea89e126bf58044596e3188c7a9631017be1f2dcd7d612331832ff8755460dc496aa99a61ea053c78e72607a18213ff9ef4bb880903b91e9a43e0b1f0ed1511b2eca2f4253fcfbd7d0faebf3680fbf0a45df231544882c9c46505c726d56905d02fd046c1652d8fd06d15286a1a8f8b69fbd825ca421fd80f5e9ba1a23f924937ad049adeec60c78fea1adf9b1ef7e8ac4d1ded18f1a801b0bda8fe9a88098825ff3eef5c1fc68cbea143310b39543293f3f5fbcf4773b02054c0bc79f00554947c7604b36389c0c45f597a88f3713456b4cfd83b30cb6520b624aa09c812066a8cd542dc67e19e4c92b562b4e0f6799fe57d9d4f4f3e0b6fabff4b1fc190bf1e78775ebcbe3655d370ca6c08f48decf6153a4989eeab6921f8475f85197f51d651e563994257df57977e5f219b4879751de57ab0374b407a21adb4ba520bb35e7b7508675bf49f4e432190451423cbd529fc79b22baae9cb1d8660c3a49c456ac03bc06c0ef3b02f7d8acd40919315206fb38e715139c9bd6f89a58634fe683df03f5bda719764f6c38131bc5ba1c53244472ef73834ade04b86ca08dd753141ac0a9a230e246735060a044018bc9b75d50134b20e6219c13f8325b5a0201e9453f6f012fe72e829ee1c637fe30037a9212a31c6e713726a6cd4cf2dd66ffdba77f1e2800e717940f231d04aa2e4e88dea084754947d848c0271856bfe659922408449858a81fa6583f062d96898d18ec53664f0067eb9b9c40ad2579ba9802abd8d1bf287e49d94ae397e784db14b5f7010ee4fc42e6e3c8ba80370afc188fcecaf466ea830d7b16362e5c9329980b981decc7174f3ff70a35d8a180ee12ed0cbffd4e8d14eb503387e4959f702d4293109e922eb561371f9ab21475821f8555d92f0aa1c3d841a6f1eabd4e663993636c754ce2b3c3f6a6b6d0b161e777b8296d7dce7fd162970496494d4f60716244a5a7fb7cee40e1d565e6566697e8f9300000000000000000000000005101318212b");
            provider
                .verify_signature(SignatureScheme::MLDSA65, &msg, &pk, &sig)
                .expect("Wycheproof valid ML-DSA-65 vector tcId 2 must verify");
        }
    }

    #[test]
    fn wycheproof_mldsa65_sigver_invalid_rejected() {
        let provider = RustCrypto::default();
        // tcId 8: signature with a bit flip in c_tilde (ModifiedSignature)
        {
            let pk = unhex("f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7eac20c5754255206a178f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe283d106eaef92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7ea9be178be35405683b44367af85d2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413b843b83f3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa855f827049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab29e892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edbafa2747db9bc42f92af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f9568bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d48cc26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb929bee9ff5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7dcbebeb5a239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e0501944409f32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c86744ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b62013965ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb06f9116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bdd0c31e9f1080e8ed8eb99fde66bafb29e3357389fe3785b60c78e229ef073e1b65e34d848bd4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b636afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a842701603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb271416b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a49075767ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf252577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd3375e608e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67acf29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b3024df986391badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa6247342905995233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca3268265c9ce042d50915430a6c455f32277da42f9962fb9163b623231ebc080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd683027bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f8881638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d25733143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480dcbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba3768c55bb1f07aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430268c1492a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776a37a1f56fbf7d08e591f978da49c3870625879f70e2418aec5cba32fa8c346fa9038baebc35ad0068a4d03537aee14c2e71570a87490377fa8dd66f995aa044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867bae249431dcf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455ff47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87173a18dc");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("68da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c2862344713a1e9c086a44f9a870a3ccc14de62d6c12b278c354d7197c4d6d7f83d1422b29b250f5ee3fec118311d905e5db2b4b8b23b8d542202d6652f6dc3f9d7ed51f2463082d3f145cfd0fa7ac548a47e91c1ccb1a55b215e90ab355bfc6d67154287b1dfae0fb530264dbb841a7684b396e5ca0459d795216416a9d232bc89b32e0f9461f53107c78e66c8e876554e8ddd501867b55dcfc1fb33f102e03373cdd192640f1027a08ce277b468f6ed0fe80a9d6cd2d6b2f7a3738c8325d95b0ccc6e7b9fb000c923b92298e0867d4a9f6dd5513e8001033c633bb1641ee66349487224dd43386c7fcc29916332066a868100d46e2c5b8354c28f087a024cba27694afc4c1665e0d72b37686919ad55052cc63a144febe4e2a0c9ae416e064e289f9f69cbb883665d1130826b7b74e30c94a2b98b67b471663e3d66326db3b43bebf958e8665b68eda90e8c5d9494b0c7c9ec48800910dd6d906b1fcd47a0aac462ac87b126d21b5ba150df61f752257ddf5a063b4a5b150371d625535e3b2874b9fe548960ff67931cd6c12496e8213e2ace6fff48e6bdc60310e49389f62579db26b92ad73e9d3f23942cab51784f48b3660b6450caecbb0df2aa4c8e56577f5ea450d2f7f51aacc0b304a62250bf2cae7b99dcd955b6596625d06da1c67f730b706fdba630f00fd891830d251484640b7258ab364d6fd9986878fffa69b7c44b92e43143affae8b098e1d27716850f37553bf266cdfb561abbcdbfeb80752b364434e64b80429b54cc88693ce03dc0fa147f0741b215f0728499bdc25140aafc976ac99e910ba8a8a50d21b7bddaa28626b3b90a93fd44077068357c81d36e735eda4362930adead4951a0baa104f384fc70e842a9f329e1868b07b455e9cc3fecd54805c9052e70f88c3b92fe0fc6a4d7dda18cf5694e5398860e439a1e19d5a66f2fbc0aacdd1a498711bb16054796c015a715395ef6174e37b04eda589b673c4d5dda737817fb52f392caf7a72d7a3e84b2180cb5b75bc8af065bdc05c3e4040435a1b160081352ac43e09cbf2ead6e09c2b0be0e37894888fe2812f68806f957c13fce6ff167bcee21d4f412ec95a4847f3db7bf441223a4d4ca9ed69adb4de8a4b5b01c775f2721226e6c59ff26fc38e1bb78a384b30e7b55f082e264d8f25e31518619ddd6b6a9faf8aa6cdb5eab75ed59a33825d5ef8b93bde5d120ada773fcc0852b918f4f03e2d2a543b15363adb823eb1f6c533b98d940411e1f5c1cf521f9f63d5454697608326625fffe01bf87f44187dad631df2898effd2c291d98222e564abe3b042b75e90c9c54667842fa8ebb68a1244bf8e0c3ae3ee5f97d5ddeefd986c4bd3f99d877c2cc2381a89abdc61713d38cee58bf69805a485c288d21b15843147066b4a74c69dc25de878e21d35fdfe6746feb4c166606bf3219e42cf63581e7e6bd6570f40f8fae590cedf5106fe57037ccb2324b74fca6500f6ed3d0736cdcc67d04f8fa9e80054a5bd7c8459fc1abb1c4c78677d7f6b325af94a0e5c9c7db0a748e12c5265e8724947d9b5c4bab1a8b6faec827cc41ec115ef3c2d7348cddabddfbc8436f3b41765e13f3762b3b45ed23156f085831e726a55d4b83848b3d1d3352aab9edcc0ac2388f2383f6301ad813b917ee3f23734e057832ae4cf65e668c9ddd0bdd0f9d8b6693254649668aa91a1fa5eb7c59859bb6ddd36c25f4a2223f5d688b480d0388fa307ea69298f9bf7737f6b3dbfda87b331affd75cd8d88f0460e98ebc2890b217bd6d11000a3a088cd837f4f8859a43f76afaaab05a0c3007a149d4d6b9155cadc2c9b55003efdec5012b6272b87183694c505f0446ede55f35b8ab201f9eda974ff840eccb0f004fa3acf753acd0613f66e2a6ac82e322199d37b4af83cbb3d98371c31be79bb42331e819644cbad2ce27a04e4c517998692cd8331552892e199a01a6922bda4d38ac4c01f708809e529c3216eaab399ef25b350ea213ba47126f278140e17391ca7139bd13c56f415e6b74aed8dbfbf38c95dc6db366fd72aa863a27fa1ebf198716400b978a3709e35039731930406588ebdffd35fa230a9b75fce41d7acd214ca4f0029896c137495eade0cf4d10fe621c73f01061acb077de72177ff5dbc6f0c5bec681aa34668ca4fcdd727525068b0b0e9072971b84ef6ce11d5c3c6024da40966703dcc2b33ae04f677677635a55db508f34f1403cdbe37960c8577dac3d848b29f3b5c5c6c56fb74f34c8f4634c04b8cce9b218f1760ca00e6de87efd14087c633469c892bf3e319443336733bb60cfb44941bfa25229aa24384d812db90fe74e0f93fda005eea87400736cabc036f71421b6657b1674d4a8f76cbbf3a8b1c0af82f72973927752257c532db439d96762ad64f102551a9d03f9ce3d8cc850c393c128bf8054bb55bb92ea31ec0706f083a9cf90424c617f8ad2a21225d1913c30e8f47a6b7131304d536a85596ebfd987b64b6bf3c51638d6c839214b53c3c10aa52bd9c6eb77fcf80b5e3b724dec1381d0e02207a6adc73ff53d9d1ffcee1c4a28fa5445ce518eee937074ff7a402f5bbcb362ff090415f9dbd93b62ee56dc8c50e4d2e34c6c621650c0dffe311484e95d68de77170c909c815828946aeeec7ede56bcf433e22fc63a33f764ced1f9242f3d26dc7558686e471f30fbe9304d3d56af8b23e72a4088970b24b2f7e968c1d0392eeeb0b0f0ac8c176547a5383d948ed15484b79e21314a1f28ed624f61e5aaecf2269e5b027e1910ffddede52fad4e8da224e8a10b079548fa7cd44172f4991adfd7623d13e5a19c812824bcf990c07c9721ded9093be6ce7bc7da3ac8c932133a64396b822be92b088844991596df893625a4ef24543bf75a10d7d17ff70350ef62ce3a7758aebbf9b3977b08becb9ea28376082f607965f2cded28bbdb39dab7e00833b0488370d221742b66e27d9ee2d9dd07f401bc22a62c8a9d8d3a290c63804991496aafa47a32578f583cfb53d0c2199055973440d7535e0da6cb2957f4e04002ecea68f9c3ff76cade27ed15fd7835989d0abb197fe32f68636139a42710644bb25860ff33f539200e3ccb8a7738422ca0fa0c744b4c19d15c5d4a3cb082e20a78e20b5a4965b043595cbcacad500b5adbb6cd597e6a4b9c5ea6a1f2e653b5474da277f1818048094ac9e0e1e0b20068d1c1ce5a114a4db7195057a6ce4d221c336fdc29190fee8ff855cae8b7f7c02eec21f972c827066d9c6dcc4a4179bc44ea9b88abe5124bf78b071e09e9af43f739a6e1030091fc091e73edc447f25c68bf84b8df7aa8f091ab42662b93e02c27003afc7b0ca69efcfa60bd53d4d78ceb7c4d2c8fd5ed7e8b35024de849e06400ad145fdb28348d22b317ccec704c401f88db1af2a5348223f5cefd914e404c9d73805d0de77211881486f1bf4aadacadd3ae2588f0db7b5e6957fed50a374f541cfe5e4e923c82ec47e5b3d2c70ad6760c79cd5080b490bdc75f9ef5e1d17f0978b1e8770775f902b9463e6980e1683b2454751ba2dad4a2e6460924bd60ff49b03230cb11fcd04a0388e60874c35d3f6cfc4dd487665e1b16578751eaea89e126bf58044596e3188c7a9631017be1f2dcd7d612331832ff8755460dc496aa99a61ea053c78e72607a18213ff9ef4bb880903b91e9a43e0b1f0ed1511b2eca2f4253fcfbd7d0faebf3680fbf0a45df231544882c9c46505c726d56905d02fd046c1652d8fd06d15286a1a8f8b69fbd825ca421fd80f5e9ba1a23f924937ad049adeec60c78fea1adf9b1ef7e8ac4d1ded18f1a801b0bda8fe9a88098825ff3eef5c1fc68cbea143310b39543293f3f5fbcf4773b02054c0bc79f00554947c7604b36389c0c45f597a88f3713456b4cfd83b30cb6520b624aa09c812066a8cd542dc67e19e4c92b562b4e0f6799fe57d9d4f4f3e0b6fabff4b1fc190bf1e78775ebcbe3655d370ca6c08f48decf6153a4989eeab6921f8475f85197f51d651e563994257df57977e5f219b4879751de57ab0374b407a21adb4ba520bb35e7b7508675bf49f4e432190451423cbd529fc79b22baae9cb1d8660c3a49c456ac03bc06c0ef3b02f7d8acd40919315206fb38e715139c9bd6f89a58634fe683df03f5bda719764f6c38131bc5ba1c53244472ef73834ade04b86ca08dd753141ac0a9a230e246735060a044018bc9b75d50134b20e6219c13f8325b5a0201e9453f6f012fe72e829ee1c637fe30037a9212a31c6e713726a6cd4cf2dd66ffdba77f1e2800e717940f231d04aa2e4e88dea084754947d848c0271856bfe659922408449858a81fa6583f062d96898d18ec53664f0067eb9b9c40ad2579ba9802abd8d1bf287e49d94ae397e784db14b5f7010ee4fc42e6e3c8ba80370afc188fcecaf466ea830d7b16362e5c9329980b981decc7174f3ff70a35d8a180ee12ed0cbffd4e8d14eb503387e4959f702d4293109e922eb561371f9ab21475821f8555d92f0aa1c3d841a6f1eabd4e663993636c754ce2b3c3f6a6b6d0b161e777b8296d7dce7fd162970496494d4f60716244a5a7fb7cee40e1d565e6566697e8f9300000000000000000000000005101318212b");
            assert!(
                provider
                    .verify_signature(SignatureScheme::MLDSA65, &msg, &pk, &sig)
                    .is_err(),
                "Wycheproof invalid ML-DSA-65 vector tcId 8 must be rejected"
            );
        }
        // tcId 9: signature with a bit flip in z[0] (ModifiedSignature)
        {
            let pk = unhex("f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7eac20c5754255206a178f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe283d106eaef92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7ea9be178be35405683b44367af85d2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413b843b83f3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa855f827049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab29e892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edbafa2747db9bc42f92af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f9568bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d48cc26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb929bee9ff5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7dcbebeb5a239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e0501944409f32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c86744ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b62013965ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb06f9116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bdd0c31e9f1080e8ed8eb99fde66bafb29e3357389fe3785b60c78e229ef073e1b65e34d848bd4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b636afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a842701603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb271416b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a49075767ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf252577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd3375e608e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67acf29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b3024df986391badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa6247342905995233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca3268265c9ce042d50915430a6c455f32277da42f9962fb9163b623231ebc080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd683027bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f8881638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d25733143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480dcbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba3768c55bb1f07aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430268c1492a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776a37a1f56fbf7d08e591f978da49c3870625879f70e2418aec5cba32fa8c346fa9038baebc35ad0068a4d03537aee14c2e71570a87490377fa8dd66f995aa044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867bae249431dcf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455ff47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87173a18dc");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("69da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c2862344713a1e9c086a44f9a870a3ccc14de62d6c12b279c354d7197c4d6d7f83d1422b29b250f5ee3fec118311d905e5db2b4b8b23b8d542202d6652f6dc3f9d7ed51f2463082d3f145cfd0fa7ac548a47e91c1ccb1a55b215e90ab355bfc6d67154287b1dfae0fb530264dbb841a7684b396e5ca0459d795216416a9d232bc89b32e0f9461f53107c78e66c8e876554e8ddd501867b55dcfc1fb33f102e03373cdd192640f1027a08ce277b468f6ed0fe80a9d6cd2d6b2f7a3738c8325d95b0ccc6e7b9fb000c923b92298e0867d4a9f6dd5513e8001033c633bb1641ee66349487224dd43386c7fcc29916332066a868100d46e2c5b8354c28f087a024cba27694afc4c1665e0d72b37686919ad55052cc63a144febe4e2a0c9ae416e064e289f9f69cbb883665d1130826b7b74e30c94a2b98b67b471663e3d66326db3b43bebf958e8665b68eda90e8c5d9494b0c7c9ec48800910dd6d906b1fcd47a0aac462ac87b126d21b5ba150df61f752257ddf5a063b4a5b150371d625535e3b2874b9fe548960ff67931cd6c12496e8213e2ace6fff48e6bdc60310e49389f62579db26b92ad73e9d3f23942cab51784f48b3660b6450caecbb0df2aa4c8e56577f5ea450d2f7f51aacc0b304a62250bf2cae7b99dcd955b6596625d06da1c67f730b706fdba630f00fd891830d251484640b7258ab364d6fd9986878fffa69b7c44b92e43143affae8b098e1d27716850f37553bf266cdfb561abbcdbfeb80752b364434e64b80429b54cc88693ce03dc0fa147f0741b215f0728499bdc25140aafc976ac99e910ba8a8a50d21b7bddaa28626b3b90a93fd44077068357c81d36e735eda4362930adead4951a0baa104f384fc70e842a9f329e1868b07b455e9cc3fecd54805c9052e70f88c3b92fe0fc6a4d7dda18cf5694e5398860e439a1e19d5a66f2fbc0aacdd1a498711bb16054796c015a715395ef6174e37b04eda589b673c4d5dda737817fb52f392caf7a72d7a3e84b2180cb5b75bc8af065bdc05c3e4040435a1b160081352ac43e09cbf2ead6e09c2b0be0e37894888fe2812f68806f957c13fce6ff167bcee21d4f412ec95a4847f3db7bf441223a4d4ca9ed69adb4de8a4b5b01c775f2721226e6c59ff26fc38e1bb78a384b30e7b55f082e264d8f25e31518619ddd6b6a9faf8aa6cdb5eab75ed59a33825d5ef8b93bde5d120ada773fcc0852b918f4f03e2d2a543b15363adb823eb1f6c533b98d940411e1f5c1cf521f9f63d5454697608326625fffe01bf87f44187dad631df2898effd2c291d98222e564abe3b042b75e90c9c54667842fa8ebb68a1244bf8e0c3ae3ee5f97d5ddeefd986c4bd3f99d877c2cc2381a89abdc61713d38cee58bf69805a485c288d21b15843147066b4a74c69dc25de878e21d35fdfe6746feb4c166606bf3219e42cf63581e7e6bd6570f40f8fae590cedf5106fe57037ccb2324b74fca6500f6ed3d0736cdcc67d04f8fa9e80054a5bd7c8459fc1abb1c4c78677d7f6b325af94a0e5c9c7db0a748e12c5265e8724947d9b5c4bab1a8b6faec827cc41ec115ef3c2d7348cddabddfbc8436f3b41765e13f3762b3b45ed23156f085831e726a55d4b83848b3d1d3352aab9edcc0ac2388f2383f6301ad813b917ee3f23734e057832ae4cf65e668c9ddd0bdd0f9d8b6693254649668aa91a1fa5eb7c59859bb6ddd36c25f4a2223f5d688b480d0388fa307ea69298f9bf7737f6b3dbfda87b331affd75cd8d88f0460e98ebc2890b217bd6d11000a3a088cd837f4f8859a43f76afaaab05a0c3007a149d4d6b9155cadc2c9b55003efdec5012b6272b87183694c505f0446ede55f35b8ab201f9eda974ff840eccb0f004fa3acf753acd0613f66e2a6ac82e322199d37b4af83cbb3d98371c31be79bb42331e819644cbad2ce27a04e4c517998692cd8331552892e199a01a6922bda4d38ac4c01f708809e529c3216eaab399ef25b350ea213ba47126f278140e17391ca7139bd13c56f415e6b74aed8dbfbf38c95dc6db366fd72aa863a27fa1ebf198716400b978a3709e35039731930406588ebdffd35fa230a9b75fce41d7acd214ca4f0029896c137495eade0cf4d10fe621c73f01061acb077de72177ff5dbc6f0c5bec681aa34668ca4fcdd727525068b0b0e9072971b84ef6ce11d5c3c6024da40966703dcc2b33ae04f677677635a55db508f34f1403cdbe37960c8577dac3d848b29f3b5c5c6c56fb74f34c8f4634c04b8cce9b218f1760ca00e6de87efd14087c633469c892bf3e319443336733bb60cfb44941bfa25229aa24384d812db90fe74e0f93fda005eea87400736cabc036f71421b6657b1674d4a8f76cbbf3a8b1c0af82f72973927752257c532db439d96762ad64f102551a9d03f9ce3d8cc850c393c128bf8054bb55bb92ea31ec0706f083a9cf90424c617f8ad2a21225d1913c30e8f47a6b7131304d536a85596ebfd987b64b6bf3c51638d6c839214b53c3c10aa52bd9c6eb77fcf80b5e3b724dec1381d0e02207a6adc73ff53d9d1ffcee1c4a28fa5445ce518eee937074ff7a402f5bbcb362ff090415f9dbd93b62ee56dc8c50e4d2e34c6c621650c0dffe311484e95d68de77170c909c815828946aeeec7ede56bcf433e22fc63a33f764ced1f9242f3d26dc7558686e471f30fbe9304d3d56af8b23e72a4088970b24b2f7e968c1d0392eeeb0b0f0ac8c176547a5383d948ed15484b79e21314a1f28ed624f61e5aaecf2269e5b027e1910ffddede52fad4e8da224e8a10b079548fa7cd44172f4991adfd7623d13e5a19c812824bcf990c07c9721ded9093be6ce7bc7da3ac8c932133a64396b822be92b088844991596df893625a4ef24543bf75a10d7d17ff70350ef62ce3a7758aebbf9b3977b08becb9ea28376082f607965f2cded28bbdb39dab7e00833b0488370d221742b66e27d9ee2d9dd07f401bc22a62c8a9d8d3a290c63804991496aafa47a32578f583cfb53d0c2199055973440d7535e0da6cb2957f4e04002ecea68f9c3ff76cade27ed15fd7835989d0abb197fe32f68636139a42710644bb25860ff33f539200e3ccb8a7738422ca0fa0c744b4c19d15c5d4a3cb082e20a78e20b5a4965b043595cbcacad500b5adbb6cd597e6a4b9c5ea6a1f2e653b5474da277f1818048094ac9e0e1e0b20068d1c1ce5a114a4db7195057a6ce4d221c336fdc29190fee8ff855cae8b7f7c02eec21f972c827066d9c6dcc4a4179bc44ea9b88abe5124bf78b071e09e9af43f739a6e1030091fc091e73edc447f25c68bf84b8df7aa8f091ab42662b93e02c27003afc7b0ca69efcfa60bd53d4d78ceb7c4d2c8fd5ed7e8b35024de849e06400ad145fdb28348d22b317ccec704c401f88db1af2a5348223f5cefd914e404c9d73805d0de77211881486f1bf4aadacadd3ae2588f0db7b5e6957fed50a374f541cfe5e4e923c82ec47e5b3d2c70ad6760c79cd5080b490bdc75f9ef5e1d17f0978b1e8770775f902b9463e6980e1683b2454751ba2dad4a2e6460924bd60ff49b03230cb11fcd04a0388e60874c35d3f6cfc4dd487665e1b16578751eaea89e126bf58044596e3188c7a9631017be1f2dcd7d612331832ff8755460dc496aa99a61ea053c78e72607a18213ff9ef4bb880903b91e9a43e0b1f0ed1511b2eca2f4253fcfbd7d0faebf3680fbf0a45df231544882c9c46505c726d56905d02fd046c1652d8fd06d15286a1a8f8b69fbd825ca421fd80f5e9ba1a23f924937ad049adeec60c78fea1adf9b1ef7e8ac4d1ded18f1a801b0bda8fe9a88098825ff3eef5c1fc68cbea143310b39543293f3f5fbcf4773b02054c0bc79f00554947c7604b36389c0c45f597a88f3713456b4cfd83b30cb6520b624aa09c812066a8cd542dc67e19e4c92b562b4e0f6799fe57d9d4f4f3e0b6fabff4b1fc190bf1e78775ebcbe3655d370ca6c08f48decf6153a4989eeab6921f8475f85197f51d651e563994257df57977e5f219b4879751de57ab0374b407a21adb4ba520bb35e7b7508675bf49f4e432190451423cbd529fc79b22baae9cb1d8660c3a49c456ac03bc06c0ef3b02f7d8acd40919315206fb38e715139c9bd6f89a58634fe683df03f5bda719764f6c38131bc5ba1c53244472ef73834ade04b86ca08dd753141ac0a9a230e246735060a044018bc9b75d50134b20e6219c13f8325b5a0201e9453f6f012fe72e829ee1c637fe30037a9212a31c6e713726a6cd4cf2dd66ffdba77f1e2800e717940f231d04aa2e4e88dea084754947d848c0271856bfe659922408449858a81fa6583f062d96898d18ec53664f0067eb9b9c40ad2579ba9802abd8d1bf287e49d94ae397e784db14b5f7010ee4fc42e6e3c8ba80370afc188fcecaf466ea830d7b16362e5c9329980b981decc7174f3ff70a35d8a180ee12ed0cbffd4e8d14eb503387e4959f702d4293109e922eb561371f9ab21475821f8555d92f0aa1c3d841a6f1eabd4e663993636c754ce2b3c3f6a6b6d0b161e777b8296d7dce7fd162970496494d4f60716244a5a7fb7cee40e1d565e6566697e8f9300000000000000000000000005101318212b");
            assert!(
                provider
                    .verify_signature(SignatureScheme::MLDSA65, &msg, &pk, &sig)
                    .is_err(),
                "Wycheproof invalid ML-DSA-65 vector tcId 9 must be rejected"
            );
        }
        // tcId 6: short signature (IncorrectSignatureLength)
        {
            let pk = unhex("f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7eac20c5754255206a178f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe283d106eaef92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7ea9be178be35405683b44367af85d2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413b843b83f3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa855f827049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab29e892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edbafa2747db9bc42f92af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f9568bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d48cc26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb929bee9ff5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7dcbebeb5a239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e0501944409f32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c86744ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b62013965ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb06f9116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bdd0c31e9f1080e8ed8eb99fde66bafb29e3357389fe3785b60c78e229ef073e1b65e34d848bd4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b636afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a842701603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb271416b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a49075767ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf252577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd3375e608e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67acf29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b3024df986391badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa6247342905995233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca3268265c9ce042d50915430a6c455f32277da42f9962fb9163b623231ebc080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd683027bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f8881638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d25733143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480dcbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba3768c55bb1f07aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430268c1492a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776a37a1f56fbf7d08e591f978da49c3870625879f70e2418aec5cba32fa8c346fa9038baebc35ad0068a4d03537aee14c2e71570a87490377fa8dd66f995aa044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867bae249431dcf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455ff47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87173a18dc");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("69da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c2862344713a1e9c086a44f9a870a3ccc14de62d6c12b278c354d7197c4d6d7f83d1422b29b250f5ee3fec118311d905e5db2b4b8b23b8d542202d6652f6dc3f9d7ed51f2463082d3f145cfd0fa7ac548a47e91c1ccb1a55b215e90ab355bfc6d67154287b1dfae0fb530264dbb841a7684b396e5ca0459d795216416a9d232bc89b32e0f9461f53107c78e66c8e876554e8ddd501867b55dcfc1fb33f102e03373cdd192640f1027a08ce277b468f6ed0fe80a9d6cd2d6b2f7a3738c8325d95b0ccc6e7b9fb000c923b92298e0867d4a9f6dd5513e8001033c633bb1641ee66349487224dd43386c7fcc29916332066a868100d46e2c5b8354c28f087a024cba27694afc4c1665e0d72b37686919ad55052cc63a144febe4e2a0c9ae416e064e289f9f69cbb883665d1130826b7b74e30c94a2b98b67b471663e3d66326db3b43bebf958e8665b68eda90e8c5d9494b0c7c9ec48800910dd6d906b1fcd47a0aac462ac87b126d21b5ba150df61f752257ddf5a063b4a5b150371d625535e3b2874b9fe548960ff67931cd6c12496e8213e2ace6fff48e6bdc60310e49389f62579db26b92ad73e9d3f23942cab51784f48b3660b6450caecbb0df2aa4c8e56577f5ea450d2f7f51aacc0b304a62250bf2cae7b99dcd955b6596625d06da1c67f730b706fdba630f00fd891830d251484640b7258ab364d6fd9986878fffa69b7c44b92e43143affae8b098e1d27716850f37553bf266cdfb561abbcdbfeb80752b364434e64b80429b54cc88693ce03dc0fa147f0741b215f0728499bdc25140aafc976ac99e910ba8a8a50d21b7bddaa28626b3b90a93fd44077068357c81d36e735eda4362930adead4951a0baa104f384fc70e842a9f329e1868b07b455e9cc3fecd54805c9052e70f88c3b92fe0fc6a4d7dda18cf5694e5398860e439a1e19d5a66f2fbc0aacdd1a498711bb16054796c015a715395ef6174e37b04eda589b673c4d5dda737817fb52f392caf7a72d7a3e84b2180cb5b75bc8af065bdc05c3e4040435a1b160081352ac43e09cbf2ead6e09c2b0be0e37894888fe2812f68806f957c13fce6ff167bcee21d4f412ec95a4847f3db7bf441223a4d4ca9ed69adb4de8a4b5b01c775f2721226e6c59ff26fc38e1bb78a384b30e7b55f082e264d8f25e31518619ddd6b6a9faf8aa6cdb5eab75ed59a33825d5ef8b93bde5d120ada773fcc0852b918f4f03e2d2a543b15363adb823eb1f6c533b98d940411e1f5c1cf521f9f63d5454697608326625fffe01bf87f44187dad631df2898effd2c291d98222e564abe3b042b75e90c9c54667842fa8ebb68a1244bf8e0c3ae3ee5f97d5ddeefd986c4bd3f99d877c2cc2381a89abdc61713d38cee58bf69805a485c288d21b15843147066b4a74c69dc25de878e21d35fdfe6746feb4c166606bf3219e42cf63581e7e6bd6570f40f8fae590cedf5106fe57037ccb2324b74fca6500f6ed3d0736cdcc67d04f8fa9e80054a5bd7c8459fc1abb1c4c78677d7f6b325af94a0e5c9c7db0a748e12c5265e8724947d9b5c4bab1a8b6faec827cc41ec115ef3c2d7348cddabddfbc8436f3b41765e13f3762b3b45ed23156f085831e726a55d4b83848b3d1d3352aab9edcc0ac2388f2383f6301ad813b917ee3f23734e057832ae4cf65e668c9ddd0bdd0f9d8b6693254649668aa91a1fa5eb7c59859bb6ddd36c25f4a2223f5d688b480d0388fa307ea69298f9bf7737f6b3dbfda87b331affd75cd8d88f0460e98ebc2890b217bd6d11000a3a088cd837f4f8859a43f76afaaab05a0c3007a149d4d6b9155cadc2c9b55003efdec5012b6272b87183694c505f0446ede55f35b8ab201f9eda974ff840eccb0f004fa3acf753acd0613f66e2a6ac82e322199d37b4af83cbb3d98371c31be79bb42331e819644cbad2ce27a04e4c517998692cd8331552892e199a01a6922bda4d38ac4c01f708809e529c3216eaab399ef25b350ea213ba47126f278140e17391ca7139bd13c56f415e6b74aed8dbfbf38c95dc6db366fd72aa863a27fa1ebf198716400b978a3709e35039731930406588ebdffd35fa230a9b75fce41d7acd214ca4f0029896c137495eade0cf4d10fe621c73f01061acb077de72177ff5dbc6f0c5bec681aa34668ca4fcdd727525068b0b0e9072971b84ef6ce11d5c3c6024da40966703dcc2b33ae04f677677635a55db508f34f1403cdbe37960c8577dac3d848b29f3b5c5c6c56fb74f34c8f4634c04b8cce9b218f1760ca00e6de87efd14087c633469c892bf3e319443336733bb60cfb44941bfa25229aa24384d812db90fe74e0f93fda005eea87400736cabc036f71421b6657b1674d4a8f76cbbf3a8b1c0af82f72973927752257c532db439d96762ad64f102551a9d03f9ce3d8cc850c393c128bf8054bb55bb92ea31ec0706f083a9cf90424c617f8ad2a21225d1913c30e8f47a6b7131304d536a85596ebfd987b64b6bf3c51638d6c839214b53c3c10aa52bd9c6eb77fcf80b5e3b724dec1381d0e02207a6adc73ff53d9d1ffcee1c4a28fa5445ce518eee937074ff7a402f5bbcb362ff090415f9dbd93b62ee56dc8c50e4d2e34c6c621650c0dffe311484e95d68de77170c909c815828946aeeec7ede56bcf433e22fc63a33f764ced1f9242f3d26dc7558686e471f30fbe9304d3d56af8b23e72a4088970b24b2f7e968c1d0392eeeb0b0f0ac8c176547a5383d948ed15484b79e21314a1f28ed624f61e5aaecf2269e5b027e1910ffddede52fad4e8da224e8a10b079548fa7cd44172f4991adfd7623d13e5a19c812824bcf990c07c9721ded9093be6ce7bc7da3ac8c932133a64396b822be92b088844991596df893625a4ef24543bf75a10d7d17ff70350ef62ce3a7758aebbf9b3977b08becb9ea28376082f607965f2cded28bbdb39dab7e00833b0488370d221742b66e27d9ee2d9dd07f401bc22a62c8a9d8d3a290c63804991496aafa47a32578f583cfb53d0c2199055973440d7535e0da6cb2957f4e04002ecea68f9c3ff76cade27ed15fd7835989d0abb197fe32f68636139a42710644bb25860ff33f539200e3ccb8a7738422ca0fa0c744b4c19d15c5d4a3cb082e20a78e20b5a4965b043595cbcacad500b5adbb6cd597e6a4b9c5ea6a1f2e653b5474da277f1818048094ac9e0e1e0b20068d1c1ce5a114a4db7195057a6ce4d221c336fdc29190fee8ff855cae8b7f7c02eec21f972c827066d9c6dcc4a4179bc44ea9b88abe5124bf78b071e09e9af43f739a6e1030091fc091e73edc447f25c68bf84b8df7aa8f091ab42662b93e02c27003afc7b0ca69efcfa60bd53d4d78ceb7c4d2c8fd5ed7e8b35024de849e06400ad145fdb28348d22b317ccec704c401f88db1af2a5348223f5cefd914e404c9d73805d0de77211881486f1bf4aadacadd3ae2588f0db7b5e6957fed50a374f541cfe5e4e923c82ec47e5b3d2c70ad6760c79cd5080b490bdc75f9ef5e1d17f0978b1e8770775f902b9463e6980e1683b2454751ba2dad4a2e6460924bd60ff49b03230cb11fcd04a0388e60874c35d3f6cfc4dd487665e1b16578751eaea89e126bf58044596e3188c7a9631017be1f2dcd7d612331832ff8755460dc496aa99a61ea053c78e72607a18213ff9ef4bb880903b91e9a43e0b1f0ed1511b2eca2f4253fcfbd7d0faebf3680fbf0a45df231544882c9c46505c726d56905d02fd046c1652d8fd06d15286a1a8f8b69fbd825ca421fd80f5e9ba1a23f924937ad049adeec60c78fea1adf9b1ef7e8ac4d1ded18f1a801b0bda8fe9a88098825ff3eef5c1fc68cbea143310b39543293f3f5fbcf4773b02054c0bc79f00554947c7604b36389c0c45f597a88f3713456b4cfd83b30cb6520b624aa09c812066a8cd542dc67e19e4c92b562b4e0f6799fe57d9d4f4f3e0b6fabff4b1fc190bf1e78775ebcbe3655d370ca6c08f48decf6153a4989eeab6921f8475f85197f51d651e563994257df57977e5f219b4879751de57ab0374b407a21adb4ba520bb35e7b7508675bf49f4e432190451423cbd529fc79b22baae9cb1d8660c3a49c456ac03bc06c0ef3b02f7d8acd40919315206fb38e715139c9bd6f89a58634fe683df03f5bda719764f6c38131bc5ba1c53244472ef73834ade04b86ca08dd753141ac0a9a230e246735060a044018bc9b75d50134b20e6219c13f8325b5a0201e9453f6f012fe72e829ee1c637fe30037a9212a31c6e713726a6cd4cf2dd66ffdba77f1e2800e717940f231d04aa2e4e88dea084754947d848c0271856bfe659922408449858a81fa6583f062d96898d18ec53664f0067eb9b9c40ad2579ba9802abd8d1bf287e49d94ae397e784db14b5f7010ee4fc42e6e3c8ba80370afc188fcecaf466ea830d7b16362e5c9329980b981decc7174f3ff70a35d8a180ee12ed0cbffd4e8d14eb503387e4959f702d4293109e922eb561371f9ab21475821f8555d92f0aa1c3d841a6f1eabd4e663993636c754ce2b3c3f6a6b6d0b161e777b8296d7dce7fd162970496494d4f60716244a5a7fb7cee40e1d565e6566697e8f930000000000000000000000000510131821");
            assert!(
                provider
                    .verify_signature(SignatureScheme::MLDSA65, &msg, &pk, &sig)
                    .is_err(),
                "Wycheproof invalid ML-DSA-65 vector tcId 6 must be rejected"
            );
        }
    }

    // ---------- ML-DSA-87 sigVer KATs (mldsa_87_verify_test.json) ----------
    #[test]
    fn wycheproof_mldsa87_sigver_valid_accepted() {
        let provider = RustCrypto::default();
        // tcId 1: baseline (ValidSignature)
        {
            let pk = unhex("17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff125469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d012d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa48ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c310d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbbe3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f6953865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56248e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b800d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e805");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("ba4275ff54c22d2d09ea1937a0667362acd44925c6d6965fad350b111d1cbcce68ddbd0e576d1a8810eb4e71623781f32f747d44c8e693749df191682f588906949d97617a4b0ec54ad966818dee88b95f0f28ca24bfc5bfe0c316140b0662c43093ae48b899cc71e5739e9d67095ed987a79b6a0e7aac960c3c4125f0e92bc9435d10bfffae34bb3af05e977ebe0bafcbeb2381c5afe3379667b4c201aebf162dbd0a4bd1baa88fb2f88fa970499a848737d3cf94cc8ce278880a169cad91f304e4e8f1091d4cf39d9a3ab9f88dcc6f3bc4df311a5be0cba290365b3e879527e2a77f0cb6eccc9d85a5e592fb00f3a2e925a26d295a6b82746d7f534c83c35bc4826ee4910216b9a2867032698996fb0e1669b539ccd2ec74d181f4844e8f4d28f9c174316c12dadb54cb1dde7338238a20731c2565bb959f8e3086273ed03abc7ac515728750633083c0b397b29d385d13f5afd2529b32f00dce66c9dc8ea93d99c8b61c5e0ab2fc70de2a8dabdcaf290d53e8fca7561bda8c516ad475e4ec6c7cd2603aa3c8a71d9fa5dc7efc33cf318bebc1f1594e6ea25c69b8f9ce34a65b8ab0ae8dd3538bd267d86c584b8f354d7e4776ed4dd59a73f9e70a1df572f033b69b3eafa5a901e02515472e37258608875ca469de07db71cd6b8dc7edeb3d866ed2d219e44fcb133a066e89d8e3013569ca6f1fee7bf4ae56a6d32a5f3e5a530819c31aadabc8a88503edbea9cdfa3171762e1e8bcebaf9bb6af7e540102d5fc810bbcf1e02ae564e04d9dc55dab0a9392d6c95a317730d9793954da2cb16544d15403d0db01e85881e2d4f1b9b98458e1af0985f98b014f08f200558f2fed7a70c352a27423bedeebb3775c0a1ede9d461d2aea303c09c8b1f73fc37a5b3a01fb24a131574f7eac90c78baa38cebe81e2335dafda20299f76d6a0ba77d2954d11381674f4069f45e133886d64222d92583d5908e3ab6eb6a72cfb41f7dc3e71c1383888f61624bdcaf12fb716de98232ee329af1dd045f30d377234db7bfd11ddab0b3108329e16ce568c8bada39a98df5a5f72a72f063fa4253313a806013f61ce5adbe54cf42180ebf6e496bd4b42aeacf069aaa8e1c231fd037b394d78a69d1742b45bc5784ab8593a198077423c4c357d734f9899cfe9b3b62b6b9c3f4d781b8484a3fd0eea7e8d6945f4ba2b046fee079b7f032bebbc402918daa2aa1c9433dc3bcfbd7f49a5d7a293833c21c1bade3e8a7ec3c83d485529de51b5993cdffe23b770e25acab0ab9fb3059f14952d9464ebfa36a6274d8da317a7b07c2afe38ba28ca942cf7bfaee4020e59911c047b2aa24d1787baae1bc3546364b782358676d75c7698769f1d4a0d5dccade7fcf80e308437f7fc24fdfbf72625abf1b0f534da62cf860da1efd986950e3e19a085999f4d008fce38459c673befcdf2287c1766e106beb4f3175e97812da141330dcb2beb3265e38c8423c19dd50a655c9e8dc969f6367f3383b644d53a26875d53cea26de429266b506e70e7e6832886ed06d81738b0b482bd23bda396eb674ddfdb64803d6c4fae2f040170b5a28923279838b7b876220d02dc7478666f7c3287b1ba4a2f8228e8c491a55ba459805c601b986caea27ee9436f63383351c74d673643b15f6007fc6dc49e337a65a8a96ecd7eef4ad730bf3dc1972fc396703ee26af1156dc4beb46c47d99bb69ebdaf81c2d738d0f70e57a2c7162f5a55242255675f22082aa43f5b3dd862b535b2a15bb815b4e9faf16a302552cd6098d40930dfad7a7c609d6aeade814242a8bf0721c1c26d0d3daa7a638880a6411c6538d80c259d31b639aadaea49563a8d7f5ddb64291d6b086c80d72bfe7d26802cbd20fd6ba5495011e42da1c82483cbe8e37838e73c48f79f65b205476bee600399feda6aaaa939eee12cb34be4e6bdbd18032c85b54a2713551de677a16ca0142ff97b77bc963e8f3c57d91df9b49474b01ca514641842893abc3181caee3f49b635d17daf41bcc4aeb1116ec4b3e78ff1480cf3a5d9c6a154384b88516834d19196976e2ba97cee91f7a0d73f7f8146e58dc0fc8f510511d39d82a7ba531a4abcce6b624035d753a37c5980343cfc7724cf83efb0c33fc4abb5b002241bf57a46b67cb5a4cbd637b2f19bc93b368d97e13c6a62c8443c8222e0a90c3ed1972cc739b824fdf729ed8eca02ad96bd78bf6d2b3d2853e24fa93199ff41635176b31aab2207013d0a9317fa49668dfeb672b8129e6175a2998642ab8e74f0823e3b5480ae80180ca395f5348744a3c7b344891f008aab65914760b5fe852615ad6425216b1c5e777db1a46517cd01a77b277cfa2c6f250c2d68c495fef28feee6e0716817d6b30716f5ca48001805042133eca17a41c2219784ce0f12858ccfd371c77b90966ea04c3996851edf31aef962946628007de5531b06fddf3449f6c552eaf6e16b3e9160e265900b8c8e414732505e02660e123d45a3d6f1b15e56fd759d38e821e27e84967e95c4b0d2a48e008897e655d1b65b76299f1e3074209abe44b37f8786b02df23aa4dcebe512e6312f1a3d6d781d749635247aca897626f5ee688f517df6cfe947ddead820f07fed4bcbe7f1bee3f19117b5666dc123d528f2bf03db346d6afb53804b0681aea98a9479fc6de5ae974d2c0d2055f07ba8a1d2d8b6a7e08a6805bd8634cc190c4988b502f475c36d78c7b3dda0057c818835bbf21c5a7c13bb6fd91cd3cfd76abe4c2ff908a08a3000b9021500ff94b297cec0fb3e51b1cae7026ab4347bfd5b6a641a3d347f45a2a2aacd22e521e00da0c3986c67672c5d7d7e61e7edafc15d42aa42cb37fa8621f79e9096b092efe853ab318b3e4bbd90f20165a1be1d3aa5b3de43751b65abbd952599869778393c4351ab8f534fd49e16547df01c40bfaf56de60b4fb0019bc34177cc8e2236d219fb3c0b84dedae6b88e134280eabd1823420cd1afe6d929774967fd7d885fbad33d89ed9dc5e0eb978eab5d96c50bed5887aa8277880c7b06bf2780cee82ce639a1e3344c88a25102edcc17a4cb48989c4ad6a998726ede31deb0b98107f40858bad7864983f6ecdf0c9761a42751b19d5360daa7fddbbd2e2292638b95c763ca1e747eedef0dd387e9d9ec9e5afee207d8c45703c5befc2de3878d313655ce85ad984250cdf054360f33d41dc193060d42cf9528b1fb91d6ca3395199e25a1a7739eba9a6a4ac2c417ae615940b3eb1b746dd0ecc7b2f7acdff887110115629f70877dafcd7a6625fa1b9e256bc8fe1d66005dbcf12fde0a5fcda5d4f23d58ece91d60eb91274df8d9d17d4a39e63533acf1b317db979b04ca3ab9a0bcba652d0010ca3fcd33ed8f8a62faf42f78b37912d3adb410f20bf16b31359cacc25fb783083a3f065f0a2dd6fe58b8f594e11a87bf0f4c5f5493f334c18b03ebdefebce50228937ec13a8c221b617450486291071f3c14f64f66c927dd4bd623c214ac35433b8a6875cdf00916476eac0f196858aa1484bc1cd45b726d33a965619829b8deaa9d9fa0c3c210f23967ce26a4bdd939cff8aa662f70fb0af97ee44bcb9e2755000a195741d8919e4dcb1a5caae21009f686fa1489c72f16f9fee76b5410ece7f406947f4a19f394a5121da79f3216777b0fee5423328156ecf0b4548dbd5b3f7b526d6b9cfd57576f67dd521c314c2d37474ed0cf732c3b073a101c735a4c4e6b33c9aaa12c91d147ad1075a20287d36c388657614a9c648d8e49cce8cfa282b2a2e8e9da6e4444e4b6aed1bd0ada5009a335cd0500bdae9a01b97f7e8cfe8372398e750de92ee4a524393a19826d19de5e762fb53a88b9b4657e9c6d7d01a4124e3e39532f614aec5cb88d982b78b2ff568017c92f6a1ce5298b5f323b5ee61695038ef0c3a7a339cfac31cf7875a4563046a40e7b35cef1d37d811b342fcbb5373122415befc23cb656a619f7c262c443403b23ba20e341a079918dec6f4f801b92781179ad7ac1951f39ddb0b1f1fb95b28c0f4593a04486f0e0e86bb3b014674879aad10f41e0bad34d40bc817b6fd43c1dde8547882d82e5111e208107e9c9736d16ca77ac7453d7b6c7976a7dd6a4c6c0252185bc9948660a07b66151b09b980d8572ae829ab2f6d900cc63066c4ecb3a0317e8a9acaa8e22a216721f3d69c67843df2fbedd88bc424f761cdf420de4ff2c55b6925b1826c1c4134090d2aae82a7f64a8d428efe1b21097a6fdbc9b8a31c4d46c7b32d478bf5b9181bef8af4d3486958d7c198c46a5ad771090bb64e7fc2bd7677ae7618b861c83c13177075063517eff40cfd52ae56650e9e7035f783bfe8920c754e98470b327909ac2a407e07864710544b8adbc075502c75b5f0fdbca0cde5d94b013141c96b55ae1b60ab63f9e792641690af41b05a78233935fd7f82852ebb2602a10459a709256c41d108c2aeb71925089cc79b121eabd5edc54f3f7c8929685b88ab29700c7fb2f247cd7962c8ce6dc9f79f9358d6a7989d24ccc17d0dbaa0b7fbe73479164181ae7d6b6a02678cce46f74ea2bd387ecb73041817b429a0220e1c3635fe492f5f3a8e2b65c086fe24c375563d7220856dd8f970716d548492964a156554dc88810c3c4f81dcc3ae80243e19679a3be9c9b1b8c707b416e9166c54a568bb9d84728c1a283d9231a12b13688ce2362901342652d66bf44cec223f561d2735d977c6adcf57e9066220d0770fc77fdf6ff367a2f36ae20062887beb88d1b453f267aef9bc763ab716bacb9214c38b95f4f2f3f6c236aa71aef83c1ae4b26133678884476c1d7c6d3e7b99f13e028ac6cebddfae4793f9ae975f3d66b725b500e7c7d2f664eaa0c358deb91cb2d6173394b306749d2bfb2684b985769bdb682e922b75555d38dad1899057a64ef6ea361e4712244d02d0dfec8c3d40770122770c2538d6a14a8462ef18eb705c16e5ba30aa5366447c94869060e4df155f7d01ffda04c1ced0ad5fbe5fdd85856e1e49320319687d31a6e4c7145479f45f43a9b8e9ffe4cbacfad4a21e5445e119df2996cce8b11d0f224efb4f18b544d456e2fb1d96fcd99fc319dbd86720621ac25b490f3611f7e5655bb3940a503c07dbf41f4b87593595a66008808744668371a54ce1b9dfdaa16f90415e57470bc23898d13d8351ba34369e96347da13d012b4eab32ada90668654c5ed2b433716b1b4170f640cf4b40659efcf4150237bbc25f72b248be85cd482b55ce2f5f73e8f02efd2465805b37d12487465ec1085bc6602b71862771af13e13baece4916b1ddef9ce016c92db9fb9e82aee5e1c4e22c45090ad1c19801ce1c541ff3902baea7a12dbcac6ec2d128ac7acb203463921ca6ce1d182d60d553ddecc4a3175eec2e924e9191e0d69aa49ca0b653495b8c62b802e443e669220f2a4047a56ed5cb7431a3387a435070795e6e63d242a74555e97371989c6d0040748e89ac316618d5d6eb7bff8d91e953afbe00464df4e4f6380c273b7ac5934cacb6c3be4da6649c8a5ea12bdf9afa1ec1e5053db7668c10ae2df75c4b3b14525369bf33741525a7630158aca3d3c7da5c1d71d3f63c0c2948a43236968d623c6c163eb757f0c78d6ae682ff4e4b673be07193e8d6c106c92851b393f0523491d5152e06de675fa22ae7bded329836a8ca0b955a59cb575395952c6ea0cb1644f2cada196b96b44ee12115ff9668e32886103d8f8109fac4a2287738ee1d2d4c1c19dab94eaa2757ea32016df60d7286099eb010ba570b5791ce4c54d860b15d56c53a5ddb543b0b602b3a87ca5213aa9647e51b1cb1736697506081240f4f7163a646f2be30e62c617d7572d820a113f96320834a2f43842160511923bd1ef4f723a2ab9b242fffe97cf0199c9f2ebca266a63beea0af279f2d18651b2ea9789d03025857c8aefc5f8bc6ee92ab7c6ffed2606f9c7ef25cb6c96140256a08cc58218869c52f3e5074fe5ace87a86057cc29fc845ff275f1b2dbc5991cbebe4c556b29ce3da3415958f0c9c68a5c664a1da60365ce56b9a4df24ec5d69c6f5a2e685885f6973c0ccd4caf7e000346bdea502b1418c8819e05bb7bee31bbd235819b49c892f7dadade576cb8ca68bda916a598c32ec03cceba2d01a7960f38680facccdaaf05e254dd8c3631a7222d1561c998c54b16f17a425f3247232dca035d545202e1b180340219ce31c66987bc86f983240e7fd2c926e8af77e6ea9f4139ff1edc0c323b67ceadead8f64a8004164d942f6aa65a28544d7205d41aafe62c5bfc6fd9fc322e2a8b620532d00d1add7a0d25a9dbaff90e19de14ac2ca97e83a2d77e63888ba0f7eaf9b18a7f2e5f148d16887580e55e894ae79024385f439acd071494e6469b77d07e763553652a470f3b4bd8bb7968052f3a969dacced51572bd125870849ce3e55359b2e17eabc3153b5f62868ea0ca1f40738488dbe0020c103f53678b9eb1c10000000000000000000000000000000000000000000000000000070a111518202731");
            provider
                .verify_signature(SignatureScheme::MLDSA87, &msg, &pk, &sig)
                .expect("Wycheproof valid ML-DSA-87 vector tcId 1 must verify");
        }
        // tcId 2: empty provided context (ValidSignature)
        {
            let pk = unhex("17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff125469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d012d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa48ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c310d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbbe3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f6953865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56248e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b800d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e805");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("ba4275ff54c22d2d09ea1937a0667362acd44925c6d6965fad350b111d1cbcce68ddbd0e576d1a8810eb4e71623781f32f747d44c8e693749df191682f588906949d97617a4b0ec54ad966818dee88b95f0f28ca24bfc5bfe0c316140b0662c43093ae48b899cc71e5739e9d67095ed987a79b6a0e7aac960c3c4125f0e92bc9435d10bfffae34bb3af05e977ebe0bafcbeb2381c5afe3379667b4c201aebf162dbd0a4bd1baa88fb2f88fa970499a848737d3cf94cc8ce278880a169cad91f304e4e8f1091d4cf39d9a3ab9f88dcc6f3bc4df311a5be0cba290365b3e879527e2a77f0cb6eccc9d85a5e592fb00f3a2e925a26d295a6b82746d7f534c83c35bc4826ee4910216b9a2867032698996fb0e1669b539ccd2ec74d181f4844e8f4d28f9c174316c12dadb54cb1dde7338238a20731c2565bb959f8e3086273ed03abc7ac515728750633083c0b397b29d385d13f5afd2529b32f00dce66c9dc8ea93d99c8b61c5e0ab2fc70de2a8dabdcaf290d53e8fca7561bda8c516ad475e4ec6c7cd2603aa3c8a71d9fa5dc7efc33cf318bebc1f1594e6ea25c69b8f9ce34a65b8ab0ae8dd3538bd267d86c584b8f354d7e4776ed4dd59a73f9e70a1df572f033b69b3eafa5a901e02515472e37258608875ca469de07db71cd6b8dc7edeb3d866ed2d219e44fcb133a066e89d8e3013569ca6f1fee7bf4ae56a6d32a5f3e5a530819c31aadabc8a88503edbea9cdfa3171762e1e8bcebaf9bb6af7e540102d5fc810bbcf1e02ae564e04d9dc55dab0a9392d6c95a317730d9793954da2cb16544d15403d0db01e85881e2d4f1b9b98458e1af0985f98b014f08f200558f2fed7a70c352a27423bedeebb3775c0a1ede9d461d2aea303c09c8b1f73fc37a5b3a01fb24a131574f7eac90c78baa38cebe81e2335dafda20299f76d6a0ba77d2954d11381674f4069f45e133886d64222d92583d5908e3ab6eb6a72cfb41f7dc3e71c1383888f61624bdcaf12fb716de98232ee329af1dd045f30d377234db7bfd11ddab0b3108329e16ce568c8bada39a98df5a5f72a72f063fa4253313a806013f61ce5adbe54cf42180ebf6e496bd4b42aeacf069aaa8e1c231fd037b394d78a69d1742b45bc5784ab8593a198077423c4c357d734f9899cfe9b3b62b6b9c3f4d781b8484a3fd0eea7e8d6945f4ba2b046fee079b7f032bebbc402918daa2aa1c9433dc3bcfbd7f49a5d7a293833c21c1bade3e8a7ec3c83d485529de51b5993cdffe23b770e25acab0ab9fb3059f14952d9464ebfa36a6274d8da317a7b07c2afe38ba28ca942cf7bfaee4020e59911c047b2aa24d1787baae1bc3546364b782358676d75c7698769f1d4a0d5dccade7fcf80e308437f7fc24fdfbf72625abf1b0f534da62cf860da1efd986950e3e19a085999f4d008fce38459c673befcdf2287c1766e106beb4f3175e97812da141330dcb2beb3265e38c8423c19dd50a655c9e8dc969f6367f3383b644d53a26875d53cea26de429266b506e70e7e6832886ed06d81738b0b482bd23bda396eb674ddfdb64803d6c4fae2f040170b5a28923279838b7b876220d02dc7478666f7c3287b1ba4a2f8228e8c491a55ba459805c601b986caea27ee9436f63383351c74d673643b15f6007fc6dc49e337a65a8a96ecd7eef4ad730bf3dc1972fc396703ee26af1156dc4beb46c47d99bb69ebdaf81c2d738d0f70e57a2c7162f5a55242255675f22082aa43f5b3dd862b535b2a15bb815b4e9faf16a302552cd6098d40930dfad7a7c609d6aeade814242a8bf0721c1c26d0d3daa7a638880a6411c6538d80c259d31b639aadaea49563a8d7f5ddb64291d6b086c80d72bfe7d26802cbd20fd6ba5495011e42da1c82483cbe8e37838e73c48f79f65b205476bee600399feda6aaaa939eee12cb34be4e6bdbd18032c85b54a2713551de677a16ca0142ff97b77bc963e8f3c57d91df9b49474b01ca514641842893abc3181caee3f49b635d17daf41bcc4aeb1116ec4b3e78ff1480cf3a5d9c6a154384b88516834d19196976e2ba97cee91f7a0d73f7f8146e58dc0fc8f510511d39d82a7ba531a4abcce6b624035d753a37c5980343cfc7724cf83efb0c33fc4abb5b002241bf57a46b67cb5a4cbd637b2f19bc93b368d97e13c6a62c8443c8222e0a90c3ed1972cc739b824fdf729ed8eca02ad96bd78bf6d2b3d2853e24fa93199ff41635176b31aab2207013d0a9317fa49668dfeb672b8129e6175a2998642ab8e74f0823e3b5480ae80180ca395f5348744a3c7b344891f008aab65914760b5fe852615ad6425216b1c5e777db1a46517cd01a77b277cfa2c6f250c2d68c495fef28feee6e0716817d6b30716f5ca48001805042133eca17a41c2219784ce0f12858ccfd371c77b90966ea04c3996851edf31aef962946628007de5531b06fddf3449f6c552eaf6e16b3e9160e265900b8c8e414732505e02660e123d45a3d6f1b15e56fd759d38e821e27e84967e95c4b0d2a48e008897e655d1b65b76299f1e3074209abe44b37f8786b02df23aa4dcebe512e6312f1a3d6d781d749635247aca897626f5ee688f517df6cfe947ddead820f07fed4bcbe7f1bee3f19117b5666dc123d528f2bf03db346d6afb53804b0681aea98a9479fc6de5ae974d2c0d2055f07ba8a1d2d8b6a7e08a6805bd8634cc190c4988b502f475c36d78c7b3dda0057c818835bbf21c5a7c13bb6fd91cd3cfd76abe4c2ff908a08a3000b9021500ff94b297cec0fb3e51b1cae7026ab4347bfd5b6a641a3d347f45a2a2aacd22e521e00da0c3986c67672c5d7d7e61e7edafc15d42aa42cb37fa8621f79e9096b092efe853ab318b3e4bbd90f20165a1be1d3aa5b3de43751b65abbd952599869778393c4351ab8f534fd49e16547df01c40bfaf56de60b4fb0019bc34177cc8e2236d219fb3c0b84dedae6b88e134280eabd1823420cd1afe6d929774967fd7d885fbad33d89ed9dc5e0eb978eab5d96c50bed5887aa8277880c7b06bf2780cee82ce639a1e3344c88a25102edcc17a4cb48989c4ad6a998726ede31deb0b98107f40858bad7864983f6ecdf0c9761a42751b19d5360daa7fddbbd2e2292638b95c763ca1e747eedef0dd387e9d9ec9e5afee207d8c45703c5befc2de3878d313655ce85ad984250cdf054360f33d41dc193060d42cf9528b1fb91d6ca3395199e25a1a7739eba9a6a4ac2c417ae615940b3eb1b746dd0ecc7b2f7acdff887110115629f70877dafcd7a6625fa1b9e256bc8fe1d66005dbcf12fde0a5fcda5d4f23d58ece91d60eb91274df8d9d17d4a39e63533acf1b317db979b04ca3ab9a0bcba652d0010ca3fcd33ed8f8a62faf42f78b37912d3adb410f20bf16b31359cacc25fb783083a3f065f0a2dd6fe58b8f594e11a87bf0f4c5f5493f334c18b03ebdefebce50228937ec13a8c221b617450486291071f3c14f64f66c927dd4bd623c214ac35433b8a6875cdf00916476eac0f196858aa1484bc1cd45b726d33a965619829b8deaa9d9fa0c3c210f23967ce26a4bdd939cff8aa662f70fb0af97ee44bcb9e2755000a195741d8919e4dcb1a5caae21009f686fa1489c72f16f9fee76b5410ece7f406947f4a19f394a5121da79f3216777b0fee5423328156ecf0b4548dbd5b3f7b526d6b9cfd57576f67dd521c314c2d37474ed0cf732c3b073a101c735a4c4e6b33c9aaa12c91d147ad1075a20287d36c388657614a9c648d8e49cce8cfa282b2a2e8e9da6e4444e4b6aed1bd0ada5009a335cd0500bdae9a01b97f7e8cfe8372398e750de92ee4a524393a19826d19de5e762fb53a88b9b4657e9c6d7d01a4124e3e39532f614aec5cb88d982b78b2ff568017c92f6a1ce5298b5f323b5ee61695038ef0c3a7a339cfac31cf7875a4563046a40e7b35cef1d37d811b342fcbb5373122415befc23cb656a619f7c262c443403b23ba20e341a079918dec6f4f801b92781179ad7ac1951f39ddb0b1f1fb95b28c0f4593a04486f0e0e86bb3b014674879aad10f41e0bad34d40bc817b6fd43c1dde8547882d82e5111e208107e9c9736d16ca77ac7453d7b6c7976a7dd6a4c6c0252185bc9948660a07b66151b09b980d8572ae829ab2f6d900cc63066c4ecb3a0317e8a9acaa8e22a216721f3d69c67843df2fbedd88bc424f761cdf420de4ff2c55b6925b1826c1c4134090d2aae82a7f64a8d428efe1b21097a6fdbc9b8a31c4d46c7b32d478bf5b9181bef8af4d3486958d7c198c46a5ad771090bb64e7fc2bd7677ae7618b861c83c13177075063517eff40cfd52ae56650e9e7035f783bfe8920c754e98470b327909ac2a407e07864710544b8adbc075502c75b5f0fdbca0cde5d94b013141c96b55ae1b60ab63f9e792641690af41b05a78233935fd7f82852ebb2602a10459a709256c41d108c2aeb71925089cc79b121eabd5edc54f3f7c8929685b88ab29700c7fb2f247cd7962c8ce6dc9f79f9358d6a7989d24ccc17d0dbaa0b7fbe73479164181ae7d6b6a02678cce46f74ea2bd387ecb73041817b429a0220e1c3635fe492f5f3a8e2b65c086fe24c375563d7220856dd8f970716d548492964a156554dc88810c3c4f81dcc3ae80243e19679a3be9c9b1b8c707b416e9166c54a568bb9d84728c1a283d9231a12b13688ce2362901342652d66bf44cec223f561d2735d977c6adcf57e9066220d0770fc77fdf6ff367a2f36ae20062887beb88d1b453f267aef9bc763ab716bacb9214c38b95f4f2f3f6c236aa71aef83c1ae4b26133678884476c1d7c6d3e7b99f13e028ac6cebddfae4793f9ae975f3d66b725b500e7c7d2f664eaa0c358deb91cb2d6173394b306749d2bfb2684b985769bdb682e922b75555d38dad1899057a64ef6ea361e4712244d02d0dfec8c3d40770122770c2538d6a14a8462ef18eb705c16e5ba30aa5366447c94869060e4df155f7d01ffda04c1ced0ad5fbe5fdd85856e1e49320319687d31a6e4c7145479f45f43a9b8e9ffe4cbacfad4a21e5445e119df2996cce8b11d0f224efb4f18b544d456e2fb1d96fcd99fc319dbd86720621ac25b490f3611f7e5655bb3940a503c07dbf41f4b87593595a66008808744668371a54ce1b9dfdaa16f90415e57470bc23898d13d8351ba34369e96347da13d012b4eab32ada90668654c5ed2b433716b1b4170f640cf4b40659efcf4150237bbc25f72b248be85cd482b55ce2f5f73e8f02efd2465805b37d12487465ec1085bc6602b71862771af13e13baece4916b1ddef9ce016c92db9fb9e82aee5e1c4e22c45090ad1c19801ce1c541ff3902baea7a12dbcac6ec2d128ac7acb203463921ca6ce1d182d60d553ddecc4a3175eec2e924e9191e0d69aa49ca0b653495b8c62b802e443e669220f2a4047a56ed5cb7431a3387a435070795e6e63d242a74555e97371989c6d0040748e89ac316618d5d6eb7bff8d91e953afbe00464df4e4f6380c273b7ac5934cacb6c3be4da6649c8a5ea12bdf9afa1ec1e5053db7668c10ae2df75c4b3b14525369bf33741525a7630158aca3d3c7da5c1d71d3f63c0c2948a43236968d623c6c163eb757f0c78d6ae682ff4e4b673be07193e8d6c106c92851b393f0523491d5152e06de675fa22ae7bded329836a8ca0b955a59cb575395952c6ea0cb1644f2cada196b96b44ee12115ff9668e32886103d8f8109fac4a2287738ee1d2d4c1c19dab94eaa2757ea32016df60d7286099eb010ba570b5791ce4c54d860b15d56c53a5ddb543b0b602b3a87ca5213aa9647e51b1cb1736697506081240f4f7163a646f2be30e62c617d7572d820a113f96320834a2f43842160511923bd1ef4f723a2ab9b242fffe97cf0199c9f2ebca266a63beea0af279f2d18651b2ea9789d03025857c8aefc5f8bc6ee92ab7c6ffed2606f9c7ef25cb6c96140256a08cc58218869c52f3e5074fe5ace87a86057cc29fc845ff275f1b2dbc5991cbebe4c556b29ce3da3415958f0c9c68a5c664a1da60365ce56b9a4df24ec5d69c6f5a2e685885f6973c0ccd4caf7e000346bdea502b1418c8819e05bb7bee31bbd235819b49c892f7dadade576cb8ca68bda916a598c32ec03cceba2d01a7960f38680facccdaaf05e254dd8c3631a7222d1561c998c54b16f17a425f3247232dca035d545202e1b180340219ce31c66987bc86f983240e7fd2c926e8af77e6ea9f4139ff1edc0c323b67ceadead8f64a8004164d942f6aa65a28544d7205d41aafe62c5bfc6fd9fc322e2a8b620532d00d1add7a0d25a9dbaff90e19de14ac2ca97e83a2d77e63888ba0f7eaf9b18a7f2e5f148d16887580e55e894ae79024385f439acd071494e6469b77d07e763553652a470f3b4bd8bb7968052f3a969dacced51572bd125870849ce3e55359b2e17eabc3153b5f62868ea0ca1f40738488dbe0020c103f53678b9eb1c10000000000000000000000000000000000000000000000000000070a111518202731");
            provider
                .verify_signature(SignatureScheme::MLDSA87, &msg, &pk, &sig)
                .expect("Wycheproof valid ML-DSA-87 vector tcId 2 must verify");
        }
    }

    #[test]
    fn wycheproof_mldsa87_sigver_invalid_rejected() {
        let provider = RustCrypto::default();
        // tcId 8: signature with a bit flip in c_tilde (ModifiedSignature)
        {
            let pk = unhex("17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff125469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d012d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa48ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c310d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbbe3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f6953865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56248e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b800d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e805");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("bb4275ff54c22d2d09ea1937a0667362acd44925c6d6965fad350b111d1cbcce68ddbd0e576d1a8810eb4e71623781f32f747d44c8e693749df191682f588906949d97617a4b0ec54ad966818dee88b95f0f28ca24bfc5bfe0c316140b0662c43093ae48b899cc71e5739e9d67095ed987a79b6a0e7aac960c3c4125f0e92bc9435d10bfffae34bb3af05e977ebe0bafcbeb2381c5afe3379667b4c201aebf162dbd0a4bd1baa88fb2f88fa970499a848737d3cf94cc8ce278880a169cad91f304e4e8f1091d4cf39d9a3ab9f88dcc6f3bc4df311a5be0cba290365b3e879527e2a77f0cb6eccc9d85a5e592fb00f3a2e925a26d295a6b82746d7f534c83c35bc4826ee4910216b9a2867032698996fb0e1669b539ccd2ec74d181f4844e8f4d28f9c174316c12dadb54cb1dde7338238a20731c2565bb959f8e3086273ed03abc7ac515728750633083c0b397b29d385d13f5afd2529b32f00dce66c9dc8ea93d99c8b61c5e0ab2fc70de2a8dabdcaf290d53e8fca7561bda8c516ad475e4ec6c7cd2603aa3c8a71d9fa5dc7efc33cf318bebc1f1594e6ea25c69b8f9ce34a65b8ab0ae8dd3538bd267d86c584b8f354d7e4776ed4dd59a73f9e70a1df572f033b69b3eafa5a901e02515472e37258608875ca469de07db71cd6b8dc7edeb3d866ed2d219e44fcb133a066e89d8e3013569ca6f1fee7bf4ae56a6d32a5f3e5a530819c31aadabc8a88503edbea9cdfa3171762e1e8bcebaf9bb6af7e540102d5fc810bbcf1e02ae564e04d9dc55dab0a9392d6c95a317730d9793954da2cb16544d15403d0db01e85881e2d4f1b9b98458e1af0985f98b014f08f200558f2fed7a70c352a27423bedeebb3775c0a1ede9d461d2aea303c09c8b1f73fc37a5b3a01fb24a131574f7eac90c78baa38cebe81e2335dafda20299f76d6a0ba77d2954d11381674f4069f45e133886d64222d92583d5908e3ab6eb6a72cfb41f7dc3e71c1383888f61624bdcaf12fb716de98232ee329af1dd045f30d377234db7bfd11ddab0b3108329e16ce568c8bada39a98df5a5f72a72f063fa4253313a806013f61ce5adbe54cf42180ebf6e496bd4b42aeacf069aaa8e1c231fd037b394d78a69d1742b45bc5784ab8593a198077423c4c357d734f9899cfe9b3b62b6b9c3f4d781b8484a3fd0eea7e8d6945f4ba2b046fee079b7f032bebbc402918daa2aa1c9433dc3bcfbd7f49a5d7a293833c21c1bade3e8a7ec3c83d485529de51b5993cdffe23b770e25acab0ab9fb3059f14952d9464ebfa36a6274d8da317a7b07c2afe38ba28ca942cf7bfaee4020e59911c047b2aa24d1787baae1bc3546364b782358676d75c7698769f1d4a0d5dccade7fcf80e308437f7fc24fdfbf72625abf1b0f534da62cf860da1efd986950e3e19a085999f4d008fce38459c673befcdf2287c1766e106beb4f3175e97812da141330dcb2beb3265e38c8423c19dd50a655c9e8dc969f6367f3383b644d53a26875d53cea26de429266b506e70e7e6832886ed06d81738b0b482bd23bda396eb674ddfdb64803d6c4fae2f040170b5a28923279838b7b876220d02dc7478666f7c3287b1ba4a2f8228e8c491a55ba459805c601b986caea27ee9436f63383351c74d673643b15f6007fc6dc49e337a65a8a96ecd7eef4ad730bf3dc1972fc396703ee26af1156dc4beb46c47d99bb69ebdaf81c2d738d0f70e57a2c7162f5a55242255675f22082aa43f5b3dd862b535b2a15bb815b4e9faf16a302552cd6098d40930dfad7a7c609d6aeade814242a8bf0721c1c26d0d3daa7a638880a6411c6538d80c259d31b639aadaea49563a8d7f5ddb64291d6b086c80d72bfe7d26802cbd20fd6ba5495011e42da1c82483cbe8e37838e73c48f79f65b205476bee600399feda6aaaa939eee12cb34be4e6bdbd18032c85b54a2713551de677a16ca0142ff97b77bc963e8f3c57d91df9b49474b01ca514641842893abc3181caee3f49b635d17daf41bcc4aeb1116ec4b3e78ff1480cf3a5d9c6a154384b88516834d19196976e2ba97cee91f7a0d73f7f8146e58dc0fc8f510511d39d82a7ba531a4abcce6b624035d753a37c5980343cfc7724cf83efb0c33fc4abb5b002241bf57a46b67cb5a4cbd637b2f19bc93b368d97e13c6a62c8443c8222e0a90c3ed1972cc739b824fdf729ed8eca02ad96bd78bf6d2b3d2853e24fa93199ff41635176b31aab2207013d0a9317fa49668dfeb672b8129e6175a2998642ab8e74f0823e3b5480ae80180ca395f5348744a3c7b344891f008aab65914760b5fe852615ad6425216b1c5e777db1a46517cd01a77b277cfa2c6f250c2d68c495fef28feee6e0716817d6b30716f5ca48001805042133eca17a41c2219784ce0f12858ccfd371c77b90966ea04c3996851edf31aef962946628007de5531b06fddf3449f6c552eaf6e16b3e9160e265900b8c8e414732505e02660e123d45a3d6f1b15e56fd759d38e821e27e84967e95c4b0d2a48e008897e655d1b65b76299f1e3074209abe44b37f8786b02df23aa4dcebe512e6312f1a3d6d781d749635247aca897626f5ee688f517df6cfe947ddead820f07fed4bcbe7f1bee3f19117b5666dc123d528f2bf03db346d6afb53804b0681aea98a9479fc6de5ae974d2c0d2055f07ba8a1d2d8b6a7e08a6805bd8634cc190c4988b502f475c36d78c7b3dda0057c818835bbf21c5a7c13bb6fd91cd3cfd76abe4c2ff908a08a3000b9021500ff94b297cec0fb3e51b1cae7026ab4347bfd5b6a641a3d347f45a2a2aacd22e521e00da0c3986c67672c5d7d7e61e7edafc15d42aa42cb37fa8621f79e9096b092efe853ab318b3e4bbd90f20165a1be1d3aa5b3de43751b65abbd952599869778393c4351ab8f534fd49e16547df01c40bfaf56de60b4fb0019bc34177cc8e2236d219fb3c0b84dedae6b88e134280eabd1823420cd1afe6d929774967fd7d885fbad33d89ed9dc5e0eb978eab5d96c50bed5887aa8277880c7b06bf2780cee82ce639a1e3344c88a25102edcc17a4cb48989c4ad6a998726ede31deb0b98107f40858bad7864983f6ecdf0c9761a42751b19d5360daa7fddbbd2e2292638b95c763ca1e747eedef0dd387e9d9ec9e5afee207d8c45703c5befc2de3878d313655ce85ad984250cdf054360f33d41dc193060d42cf9528b1fb91d6ca3395199e25a1a7739eba9a6a4ac2c417ae615940b3eb1b746dd0ecc7b2f7acdff887110115629f70877dafcd7a6625fa1b9e256bc8fe1d66005dbcf12fde0a5fcda5d4f23d58ece91d60eb91274df8d9d17d4a39e63533acf1b317db979b04ca3ab9a0bcba652d0010ca3fcd33ed8f8a62faf42f78b37912d3adb410f20bf16b31359cacc25fb783083a3f065f0a2dd6fe58b8f594e11a87bf0f4c5f5493f334c18b03ebdefebce50228937ec13a8c221b617450486291071f3c14f64f66c927dd4bd623c214ac35433b8a6875cdf00916476eac0f196858aa1484bc1cd45b726d33a965619829b8deaa9d9fa0c3c210f23967ce26a4bdd939cff8aa662f70fb0af97ee44bcb9e2755000a195741d8919e4dcb1a5caae21009f686fa1489c72f16f9fee76b5410ece7f406947f4a19f394a5121da79f3216777b0fee5423328156ecf0b4548dbd5b3f7b526d6b9cfd57576f67dd521c314c2d37474ed0cf732c3b073a101c735a4c4e6b33c9aaa12c91d147ad1075a20287d36c388657614a9c648d8e49cce8cfa282b2a2e8e9da6e4444e4b6aed1bd0ada5009a335cd0500bdae9a01b97f7e8cfe8372398e750de92ee4a524393a19826d19de5e762fb53a88b9b4657e9c6d7d01a4124e3e39532f614aec5cb88d982b78b2ff568017c92f6a1ce5298b5f323b5ee61695038ef0c3a7a339cfac31cf7875a4563046a40e7b35cef1d37d811b342fcbb5373122415befc23cb656a619f7c262c443403b23ba20e341a079918dec6f4f801b92781179ad7ac1951f39ddb0b1f1fb95b28c0f4593a04486f0e0e86bb3b014674879aad10f41e0bad34d40bc817b6fd43c1dde8547882d82e5111e208107e9c9736d16ca77ac7453d7b6c7976a7dd6a4c6c0252185bc9948660a07b66151b09b980d8572ae829ab2f6d900cc63066c4ecb3a0317e8a9acaa8e22a216721f3d69c67843df2fbedd88bc424f761cdf420de4ff2c55b6925b1826c1c4134090d2aae82a7f64a8d428efe1b21097a6fdbc9b8a31c4d46c7b32d478bf5b9181bef8af4d3486958d7c198c46a5ad771090bb64e7fc2bd7677ae7618b861c83c13177075063517eff40cfd52ae56650e9e7035f783bfe8920c754e98470b327909ac2a407e07864710544b8adbc075502c75b5f0fdbca0cde5d94b013141c96b55ae1b60ab63f9e792641690af41b05a78233935fd7f82852ebb2602a10459a709256c41d108c2aeb71925089cc79b121eabd5edc54f3f7c8929685b88ab29700c7fb2f247cd7962c8ce6dc9f79f9358d6a7989d24ccc17d0dbaa0b7fbe73479164181ae7d6b6a02678cce46f74ea2bd387ecb73041817b429a0220e1c3635fe492f5f3a8e2b65c086fe24c375563d7220856dd8f970716d548492964a156554dc88810c3c4f81dcc3ae80243e19679a3be9c9b1b8c707b416e9166c54a568bb9d84728c1a283d9231a12b13688ce2362901342652d66bf44cec223f561d2735d977c6adcf57e9066220d0770fc77fdf6ff367a2f36ae20062887beb88d1b453f267aef9bc763ab716bacb9214c38b95f4f2f3f6c236aa71aef83c1ae4b26133678884476c1d7c6d3e7b99f13e028ac6cebddfae4793f9ae975f3d66b725b500e7c7d2f664eaa0c358deb91cb2d6173394b306749d2bfb2684b985769bdb682e922b75555d38dad1899057a64ef6ea361e4712244d02d0dfec8c3d40770122770c2538d6a14a8462ef18eb705c16e5ba30aa5366447c94869060e4df155f7d01ffda04c1ced0ad5fbe5fdd85856e1e49320319687d31a6e4c7145479f45f43a9b8e9ffe4cbacfad4a21e5445e119df2996cce8b11d0f224efb4f18b544d456e2fb1d96fcd99fc319dbd86720621ac25b490f3611f7e5655bb3940a503c07dbf41f4b87593595a66008808744668371a54ce1b9dfdaa16f90415e57470bc23898d13d8351ba34369e96347da13d012b4eab32ada90668654c5ed2b433716b1b4170f640cf4b40659efcf4150237bbc25f72b248be85cd482b55ce2f5f73e8f02efd2465805b37d12487465ec1085bc6602b71862771af13e13baece4916b1ddef9ce016c92db9fb9e82aee5e1c4e22c45090ad1c19801ce1c541ff3902baea7a12dbcac6ec2d128ac7acb203463921ca6ce1d182d60d553ddecc4a3175eec2e924e9191e0d69aa49ca0b653495b8c62b802e443e669220f2a4047a56ed5cb7431a3387a435070795e6e63d242a74555e97371989c6d0040748e89ac316618d5d6eb7bff8d91e953afbe00464df4e4f6380c273b7ac5934cacb6c3be4da6649c8a5ea12bdf9afa1ec1e5053db7668c10ae2df75c4b3b14525369bf33741525a7630158aca3d3c7da5c1d71d3f63c0c2948a43236968d623c6c163eb757f0c78d6ae682ff4e4b673be07193e8d6c106c92851b393f0523491d5152e06de675fa22ae7bded329836a8ca0b955a59cb575395952c6ea0cb1644f2cada196b96b44ee12115ff9668e32886103d8f8109fac4a2287738ee1d2d4c1c19dab94eaa2757ea32016df60d7286099eb010ba570b5791ce4c54d860b15d56c53a5ddb543b0b602b3a87ca5213aa9647e51b1cb1736697506081240f4f7163a646f2be30e62c617d7572d820a113f96320834a2f43842160511923bd1ef4f723a2ab9b242fffe97cf0199c9f2ebca266a63beea0af279f2d18651b2ea9789d03025857c8aefc5f8bc6ee92ab7c6ffed2606f9c7ef25cb6c96140256a08cc58218869c52f3e5074fe5ace87a86057cc29fc845ff275f1b2dbc5991cbebe4c556b29ce3da3415958f0c9c68a5c664a1da60365ce56b9a4df24ec5d69c6f5a2e685885f6973c0ccd4caf7e000346bdea502b1418c8819e05bb7bee31bbd235819b49c892f7dadade576cb8ca68bda916a598c32ec03cceba2d01a7960f38680facccdaaf05e254dd8c3631a7222d1561c998c54b16f17a425f3247232dca035d545202e1b180340219ce31c66987bc86f983240e7fd2c926e8af77e6ea9f4139ff1edc0c323b67ceadead8f64a8004164d942f6aa65a28544d7205d41aafe62c5bfc6fd9fc322e2a8b620532d00d1add7a0d25a9dbaff90e19de14ac2ca97e83a2d77e63888ba0f7eaf9b18a7f2e5f148d16887580e55e894ae79024385f439acd071494e6469b77d07e763553652a470f3b4bd8bb7968052f3a969dacced51572bd125870849ce3e55359b2e17eabc3153b5f62868ea0ca1f40738488dbe0020c103f53678b9eb1c10000000000000000000000000000000000000000000000000000070a111518202731");
            assert!(
                provider
                    .verify_signature(SignatureScheme::MLDSA87, &msg, &pk, &sig)
                    .is_err(),
                "Wycheproof invalid ML-DSA-87 vector tcId 8 must be rejected"
            );
        }
        // tcId 9: signature with a bit flip in z[0] (ModifiedSignature)
        {
            let pk = unhex("17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff125469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d012d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa48ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c310d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbbe3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f6953865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56248e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b800d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e805");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("ba4275ff54c22d2d09ea1937a0667362acd44925c6d6965fad350b111d1cbcce68ddbd0e576d1a8810eb4e71623781f32f747d44c8e693749df191682f588906959d97617a4b0ec54ad966818dee88b95f0f28ca24bfc5bfe0c316140b0662c43093ae48b899cc71e5739e9d67095ed987a79b6a0e7aac960c3c4125f0e92bc9435d10bfffae34bb3af05e977ebe0bafcbeb2381c5afe3379667b4c201aebf162dbd0a4bd1baa88fb2f88fa970499a848737d3cf94cc8ce278880a169cad91f304e4e8f1091d4cf39d9a3ab9f88dcc6f3bc4df311a5be0cba290365b3e879527e2a77f0cb6eccc9d85a5e592fb00f3a2e925a26d295a6b82746d7f534c83c35bc4826ee4910216b9a2867032698996fb0e1669b539ccd2ec74d181f4844e8f4d28f9c174316c12dadb54cb1dde7338238a20731c2565bb959f8e3086273ed03abc7ac515728750633083c0b397b29d385d13f5afd2529b32f00dce66c9dc8ea93d99c8b61c5e0ab2fc70de2a8dabdcaf290d53e8fca7561bda8c516ad475e4ec6c7cd2603aa3c8a71d9fa5dc7efc33cf318bebc1f1594e6ea25c69b8f9ce34a65b8ab0ae8dd3538bd267d86c584b8f354d7e4776ed4dd59a73f9e70a1df572f033b69b3eafa5a901e02515472e37258608875ca469de07db71cd6b8dc7edeb3d866ed2d219e44fcb133a066e89d8e3013569ca6f1fee7bf4ae56a6d32a5f3e5a530819c31aadabc8a88503edbea9cdfa3171762e1e8bcebaf9bb6af7e540102d5fc810bbcf1e02ae564e04d9dc55dab0a9392d6c95a317730d9793954da2cb16544d15403d0db01e85881e2d4f1b9b98458e1af0985f98b014f08f200558f2fed7a70c352a27423bedeebb3775c0a1ede9d461d2aea303c09c8b1f73fc37a5b3a01fb24a131574f7eac90c78baa38cebe81e2335dafda20299f76d6a0ba77d2954d11381674f4069f45e133886d64222d92583d5908e3ab6eb6a72cfb41f7dc3e71c1383888f61624bdcaf12fb716de98232ee329af1dd045f30d377234db7bfd11ddab0b3108329e16ce568c8bada39a98df5a5f72a72f063fa4253313a806013f61ce5adbe54cf42180ebf6e496bd4b42aeacf069aaa8e1c231fd037b394d78a69d1742b45bc5784ab8593a198077423c4c357d734f9899cfe9b3b62b6b9c3f4d781b8484a3fd0eea7e8d6945f4ba2b046fee079b7f032bebbc402918daa2aa1c9433dc3bcfbd7f49a5d7a293833c21c1bade3e8a7ec3c83d485529de51b5993cdffe23b770e25acab0ab9fb3059f14952d9464ebfa36a6274d8da317a7b07c2afe38ba28ca942cf7bfaee4020e59911c047b2aa24d1787baae1bc3546364b782358676d75c7698769f1d4a0d5dccade7fcf80e308437f7fc24fdfbf72625abf1b0f534da62cf860da1efd986950e3e19a085999f4d008fce38459c673befcdf2287c1766e106beb4f3175e97812da141330dcb2beb3265e38c8423c19dd50a655c9e8dc969f6367f3383b644d53a26875d53cea26de429266b506e70e7e6832886ed06d81738b0b482bd23bda396eb674ddfdb64803d6c4fae2f040170b5a28923279838b7b876220d02dc7478666f7c3287b1ba4a2f8228e8c491a55ba459805c601b986caea27ee9436f63383351c74d673643b15f6007fc6dc49e337a65a8a96ecd7eef4ad730bf3dc1972fc396703ee26af1156dc4beb46c47d99bb69ebdaf81c2d738d0f70e57a2c7162f5a55242255675f22082aa43f5b3dd862b535b2a15bb815b4e9faf16a302552cd6098d40930dfad7a7c609d6aeade814242a8bf0721c1c26d0d3daa7a638880a6411c6538d80c259d31b639aadaea49563a8d7f5ddb64291d6b086c80d72bfe7d26802cbd20fd6ba5495011e42da1c82483cbe8e37838e73c48f79f65b205476bee600399feda6aaaa939eee12cb34be4e6bdbd18032c85b54a2713551de677a16ca0142ff97b77bc963e8f3c57d91df9b49474b01ca514641842893abc3181caee3f49b635d17daf41bcc4aeb1116ec4b3e78ff1480cf3a5d9c6a154384b88516834d19196976e2ba97cee91f7a0d73f7f8146e58dc0fc8f510511d39d82a7ba531a4abcce6b624035d753a37c5980343cfc7724cf83efb0c33fc4abb5b002241bf57a46b67cb5a4cbd637b2f19bc93b368d97e13c6a62c8443c8222e0a90c3ed1972cc739b824fdf729ed8eca02ad96bd78bf6d2b3d2853e24fa93199ff41635176b31aab2207013d0a9317fa49668dfeb672b8129e6175a2998642ab8e74f0823e3b5480ae80180ca395f5348744a3c7b344891f008aab65914760b5fe852615ad6425216b1c5e777db1a46517cd01a77b277cfa2c6f250c2d68c495fef28feee6e0716817d6b30716f5ca48001805042133eca17a41c2219784ce0f12858ccfd371c77b90966ea04c3996851edf31aef962946628007de5531b06fddf3449f6c552eaf6e16b3e9160e265900b8c8e414732505e02660e123d45a3d6f1b15e56fd759d38e821e27e84967e95c4b0d2a48e008897e655d1b65b76299f1e3074209abe44b37f8786b02df23aa4dcebe512e6312f1a3d6d781d749635247aca897626f5ee688f517df6cfe947ddead820f07fed4bcbe7f1bee3f19117b5666dc123d528f2bf03db346d6afb53804b0681aea98a9479fc6de5ae974d2c0d2055f07ba8a1d2d8b6a7e08a6805bd8634cc190c4988b502f475c36d78c7b3dda0057c818835bbf21c5a7c13bb6fd91cd3cfd76abe4c2ff908a08a3000b9021500ff94b297cec0fb3e51b1cae7026ab4347bfd5b6a641a3d347f45a2a2aacd22e521e00da0c3986c67672c5d7d7e61e7edafc15d42aa42cb37fa8621f79e9096b092efe853ab318b3e4bbd90f20165a1be1d3aa5b3de43751b65abbd952599869778393c4351ab8f534fd49e16547df01c40bfaf56de60b4fb0019bc34177cc8e2236d219fb3c0b84dedae6b88e134280eabd1823420cd1afe6d929774967fd7d885fbad33d89ed9dc5e0eb978eab5d96c50bed5887aa8277880c7b06bf2780cee82ce639a1e3344c88a25102edcc17a4cb48989c4ad6a998726ede31deb0b98107f40858bad7864983f6ecdf0c9761a42751b19d5360daa7fddbbd2e2292638b95c763ca1e747eedef0dd387e9d9ec9e5afee207d8c45703c5befc2de3878d313655ce85ad984250cdf054360f33d41dc193060d42cf9528b1fb91d6ca3395199e25a1a7739eba9a6a4ac2c417ae615940b3eb1b746dd0ecc7b2f7acdff887110115629f70877dafcd7a6625fa1b9e256bc8fe1d66005dbcf12fde0a5fcda5d4f23d58ece91d60eb91274df8d9d17d4a39e63533acf1b317db979b04ca3ab9a0bcba652d0010ca3fcd33ed8f8a62faf42f78b37912d3adb410f20bf16b31359cacc25fb783083a3f065f0a2dd6fe58b8f594e11a87bf0f4c5f5493f334c18b03ebdefebce50228937ec13a8c221b617450486291071f3c14f64f66c927dd4bd623c214ac35433b8a6875cdf00916476eac0f196858aa1484bc1cd45b726d33a965619829b8deaa9d9fa0c3c210f23967ce26a4bdd939cff8aa662f70fb0af97ee44bcb9e2755000a195741d8919e4dcb1a5caae21009f686fa1489c72f16f9fee76b5410ece7f406947f4a19f394a5121da79f3216777b0fee5423328156ecf0b4548dbd5b3f7b526d6b9cfd57576f67dd521c314c2d37474ed0cf732c3b073a101c735a4c4e6b33c9aaa12c91d147ad1075a20287d36c388657614a9c648d8e49cce8cfa282b2a2e8e9da6e4444e4b6aed1bd0ada5009a335cd0500bdae9a01b97f7e8cfe8372398e750de92ee4a524393a19826d19de5e762fb53a88b9b4657e9c6d7d01a4124e3e39532f614aec5cb88d982b78b2ff568017c92f6a1ce5298b5f323b5ee61695038ef0c3a7a339cfac31cf7875a4563046a40e7b35cef1d37d811b342fcbb5373122415befc23cb656a619f7c262c443403b23ba20e341a079918dec6f4f801b92781179ad7ac1951f39ddb0b1f1fb95b28c0f4593a04486f0e0e86bb3b014674879aad10f41e0bad34d40bc817b6fd43c1dde8547882d82e5111e208107e9c9736d16ca77ac7453d7b6c7976a7dd6a4c6c0252185bc9948660a07b66151b09b980d8572ae829ab2f6d900cc63066c4ecb3a0317e8a9acaa8e22a216721f3d69c67843df2fbedd88bc424f761cdf420de4ff2c55b6925b1826c1c4134090d2aae82a7f64a8d428efe1b21097a6fdbc9b8a31c4d46c7b32d478bf5b9181bef8af4d3486958d7c198c46a5ad771090bb64e7fc2bd7677ae7618b861c83c13177075063517eff40cfd52ae56650e9e7035f783bfe8920c754e98470b327909ac2a407e07864710544b8adbc075502c75b5f0fdbca0cde5d94b013141c96b55ae1b60ab63f9e792641690af41b05a78233935fd7f82852ebb2602a10459a709256c41d108c2aeb71925089cc79b121eabd5edc54f3f7c8929685b88ab29700c7fb2f247cd7962c8ce6dc9f79f9358d6a7989d24ccc17d0dbaa0b7fbe73479164181ae7d6b6a02678cce46f74ea2bd387ecb73041817b429a0220e1c3635fe492f5f3a8e2b65c086fe24c375563d7220856dd8f970716d548492964a156554dc88810c3c4f81dcc3ae80243e19679a3be9c9b1b8c707b416e9166c54a568bb9d84728c1a283d9231a12b13688ce2362901342652d66bf44cec223f561d2735d977c6adcf57e9066220d0770fc77fdf6ff367a2f36ae20062887beb88d1b453f267aef9bc763ab716bacb9214c38b95f4f2f3f6c236aa71aef83c1ae4b26133678884476c1d7c6d3e7b99f13e028ac6cebddfae4793f9ae975f3d66b725b500e7c7d2f664eaa0c358deb91cb2d6173394b306749d2bfb2684b985769bdb682e922b75555d38dad1899057a64ef6ea361e4712244d02d0dfec8c3d40770122770c2538d6a14a8462ef18eb705c16e5ba30aa5366447c94869060e4df155f7d01ffda04c1ced0ad5fbe5fdd85856e1e49320319687d31a6e4c7145479f45f43a9b8e9ffe4cbacfad4a21e5445e119df2996cce8b11d0f224efb4f18b544d456e2fb1d96fcd99fc319dbd86720621ac25b490f3611f7e5655bb3940a503c07dbf41f4b87593595a66008808744668371a54ce1b9dfdaa16f90415e57470bc23898d13d8351ba34369e96347da13d012b4eab32ada90668654c5ed2b433716b1b4170f640cf4b40659efcf4150237bbc25f72b248be85cd482b55ce2f5f73e8f02efd2465805b37d12487465ec1085bc6602b71862771af13e13baece4916b1ddef9ce016c92db9fb9e82aee5e1c4e22c45090ad1c19801ce1c541ff3902baea7a12dbcac6ec2d128ac7acb203463921ca6ce1d182d60d553ddecc4a3175eec2e924e9191e0d69aa49ca0b653495b8c62b802e443e669220f2a4047a56ed5cb7431a3387a435070795e6e63d242a74555e97371989c6d0040748e89ac316618d5d6eb7bff8d91e953afbe00464df4e4f6380c273b7ac5934cacb6c3be4da6649c8a5ea12bdf9afa1ec1e5053db7668c10ae2df75c4b3b14525369bf33741525a7630158aca3d3c7da5c1d71d3f63c0c2948a43236968d623c6c163eb757f0c78d6ae682ff4e4b673be07193e8d6c106c92851b393f0523491d5152e06de675fa22ae7bded329836a8ca0b955a59cb575395952c6ea0cb1644f2cada196b96b44ee12115ff9668e32886103d8f8109fac4a2287738ee1d2d4c1c19dab94eaa2757ea32016df60d7286099eb010ba570b5791ce4c54d860b15d56c53a5ddb543b0b602b3a87ca5213aa9647e51b1cb1736697506081240f4f7163a646f2be30e62c617d7572d820a113f96320834a2f43842160511923bd1ef4f723a2ab9b242fffe97cf0199c9f2ebca266a63beea0af279f2d18651b2ea9789d03025857c8aefc5f8bc6ee92ab7c6ffed2606f9c7ef25cb6c96140256a08cc58218869c52f3e5074fe5ace87a86057cc29fc845ff275f1b2dbc5991cbebe4c556b29ce3da3415958f0c9c68a5c664a1da60365ce56b9a4df24ec5d69c6f5a2e685885f6973c0ccd4caf7e000346bdea502b1418c8819e05bb7bee31bbd235819b49c892f7dadade576cb8ca68bda916a598c32ec03cceba2d01a7960f38680facccdaaf05e254dd8c3631a7222d1561c998c54b16f17a425f3247232dca035d545202e1b180340219ce31c66987bc86f983240e7fd2c926e8af77e6ea9f4139ff1edc0c323b67ceadead8f64a8004164d942f6aa65a28544d7205d41aafe62c5bfc6fd9fc322e2a8b620532d00d1add7a0d25a9dbaff90e19de14ac2ca97e83a2d77e63888ba0f7eaf9b18a7f2e5f148d16887580e55e894ae79024385f439acd071494e6469b77d07e763553652a470f3b4bd8bb7968052f3a969dacced51572bd125870849ce3e55359b2e17eabc3153b5f62868ea0ca1f40738488dbe0020c103f53678b9eb1c10000000000000000000000000000000000000000000000000000070a111518202731");
            assert!(
                provider
                    .verify_signature(SignatureScheme::MLDSA87, &msg, &pk, &sig)
                    .is_err(),
                "Wycheproof invalid ML-DSA-87 vector tcId 9 must be rejected"
            );
        }
        // tcId 6: short signature (IncorrectSignatureLength)
        {
            let pk = unhex("17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff125469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d012d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa48ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c310d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbbe3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f6953865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56248e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b800d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e805");
            let msg = unhex("48656c6c6f20776f726c64");
            let sig = unhex("ba4275ff54c22d2d09ea1937a0667362acd44925c6d6965fad350b111d1cbcce68ddbd0e576d1a8810eb4e71623781f32f747d44c8e693749df191682f588906949d97617a4b0ec54ad966818dee88b95f0f28ca24bfc5bfe0c316140b0662c43093ae48b899cc71e5739e9d67095ed987a79b6a0e7aac960c3c4125f0e92bc9435d10bfffae34bb3af05e977ebe0bafcbeb2381c5afe3379667b4c201aebf162dbd0a4bd1baa88fb2f88fa970499a848737d3cf94cc8ce278880a169cad91f304e4e8f1091d4cf39d9a3ab9f88dcc6f3bc4df311a5be0cba290365b3e879527e2a77f0cb6eccc9d85a5e592fb00f3a2e925a26d295a6b82746d7f534c83c35bc4826ee4910216b9a2867032698996fb0e1669b539ccd2ec74d181f4844e8f4d28f9c174316c12dadb54cb1dde7338238a20731c2565bb959f8e3086273ed03abc7ac515728750633083c0b397b29d385d13f5afd2529b32f00dce66c9dc8ea93d99c8b61c5e0ab2fc70de2a8dabdcaf290d53e8fca7561bda8c516ad475e4ec6c7cd2603aa3c8a71d9fa5dc7efc33cf318bebc1f1594e6ea25c69b8f9ce34a65b8ab0ae8dd3538bd267d86c584b8f354d7e4776ed4dd59a73f9e70a1df572f033b69b3eafa5a901e02515472e37258608875ca469de07db71cd6b8dc7edeb3d866ed2d219e44fcb133a066e89d8e3013569ca6f1fee7bf4ae56a6d32a5f3e5a530819c31aadabc8a88503edbea9cdfa3171762e1e8bcebaf9bb6af7e540102d5fc810bbcf1e02ae564e04d9dc55dab0a9392d6c95a317730d9793954da2cb16544d15403d0db01e85881e2d4f1b9b98458e1af0985f98b014f08f200558f2fed7a70c352a27423bedeebb3775c0a1ede9d461d2aea303c09c8b1f73fc37a5b3a01fb24a131574f7eac90c78baa38cebe81e2335dafda20299f76d6a0ba77d2954d11381674f4069f45e133886d64222d92583d5908e3ab6eb6a72cfb41f7dc3e71c1383888f61624bdcaf12fb716de98232ee329af1dd045f30d377234db7bfd11ddab0b3108329e16ce568c8bada39a98df5a5f72a72f063fa4253313a806013f61ce5adbe54cf42180ebf6e496bd4b42aeacf069aaa8e1c231fd037b394d78a69d1742b45bc5784ab8593a198077423c4c357d734f9899cfe9b3b62b6b9c3f4d781b8484a3fd0eea7e8d6945f4ba2b046fee079b7f032bebbc402918daa2aa1c9433dc3bcfbd7f49a5d7a293833c21c1bade3e8a7ec3c83d485529de51b5993cdffe23b770e25acab0ab9fb3059f14952d9464ebfa36a6274d8da317a7b07c2afe38ba28ca942cf7bfaee4020e59911c047b2aa24d1787baae1bc3546364b782358676d75c7698769f1d4a0d5dccade7fcf80e308437f7fc24fdfbf72625abf1b0f534da62cf860da1efd986950e3e19a085999f4d008fce38459c673befcdf2287c1766e106beb4f3175e97812da141330dcb2beb3265e38c8423c19dd50a655c9e8dc969f6367f3383b644d53a26875d53cea26de429266b506e70e7e6832886ed06d81738b0b482bd23bda396eb674ddfdb64803d6c4fae2f040170b5a28923279838b7b876220d02dc7478666f7c3287b1ba4a2f8228e8c491a55ba459805c601b986caea27ee9436f63383351c74d673643b15f6007fc6dc49e337a65a8a96ecd7eef4ad730bf3dc1972fc396703ee26af1156dc4beb46c47d99bb69ebdaf81c2d738d0f70e57a2c7162f5a55242255675f22082aa43f5b3dd862b535b2a15bb815b4e9faf16a302552cd6098d40930dfad7a7c609d6aeade814242a8bf0721c1c26d0d3daa7a638880a6411c6538d80c259d31b639aadaea49563a8d7f5ddb64291d6b086c80d72bfe7d26802cbd20fd6ba5495011e42da1c82483cbe8e37838e73c48f79f65b205476bee600399feda6aaaa939eee12cb34be4e6bdbd18032c85b54a2713551de677a16ca0142ff97b77bc963e8f3c57d91df9b49474b01ca514641842893abc3181caee3f49b635d17daf41bcc4aeb1116ec4b3e78ff1480cf3a5d9c6a154384b88516834d19196976e2ba97cee91f7a0d73f7f8146e58dc0fc8f510511d39d82a7ba531a4abcce6b624035d753a37c5980343cfc7724cf83efb0c33fc4abb5b002241bf57a46b67cb5a4cbd637b2f19bc93b368d97e13c6a62c8443c8222e0a90c3ed1972cc739b824fdf729ed8eca02ad96bd78bf6d2b3d2853e24fa93199ff41635176b31aab2207013d0a9317fa49668dfeb672b8129e6175a2998642ab8e74f0823e3b5480ae80180ca395f5348744a3c7b344891f008aab65914760b5fe852615ad6425216b1c5e777db1a46517cd01a77b277cfa2c6f250c2d68c495fef28feee6e0716817d6b30716f5ca48001805042133eca17a41c2219784ce0f12858ccfd371c77b90966ea04c3996851edf31aef962946628007de5531b06fddf3449f6c552eaf6e16b3e9160e265900b8c8e414732505e02660e123d45a3d6f1b15e56fd759d38e821e27e84967e95c4b0d2a48e008897e655d1b65b76299f1e3074209abe44b37f8786b02df23aa4dcebe512e6312f1a3d6d781d749635247aca897626f5ee688f517df6cfe947ddead820f07fed4bcbe7f1bee3f19117b5666dc123d528f2bf03db346d6afb53804b0681aea98a9479fc6de5ae974d2c0d2055f07ba8a1d2d8b6a7e08a6805bd8634cc190c4988b502f475c36d78c7b3dda0057c818835bbf21c5a7c13bb6fd91cd3cfd76abe4c2ff908a08a3000b9021500ff94b297cec0fb3e51b1cae7026ab4347bfd5b6a641a3d347f45a2a2aacd22e521e00da0c3986c67672c5d7d7e61e7edafc15d42aa42cb37fa8621f79e9096b092efe853ab318b3e4bbd90f20165a1be1d3aa5b3de43751b65abbd952599869778393c4351ab8f534fd49e16547df01c40bfaf56de60b4fb0019bc34177cc8e2236d219fb3c0b84dedae6b88e134280eabd1823420cd1afe6d929774967fd7d885fbad33d89ed9dc5e0eb978eab5d96c50bed5887aa8277880c7b06bf2780cee82ce639a1e3344c88a25102edcc17a4cb48989c4ad6a998726ede31deb0b98107f40858bad7864983f6ecdf0c9761a42751b19d5360daa7fddbbd2e2292638b95c763ca1e747eedef0dd387e9d9ec9e5afee207d8c45703c5befc2de3878d313655ce85ad984250cdf054360f33d41dc193060d42cf9528b1fb91d6ca3395199e25a1a7739eba9a6a4ac2c417ae615940b3eb1b746dd0ecc7b2f7acdff887110115629f70877dafcd7a6625fa1b9e256bc8fe1d66005dbcf12fde0a5fcda5d4f23d58ece91d60eb91274df8d9d17d4a39e63533acf1b317db979b04ca3ab9a0bcba652d0010ca3fcd33ed8f8a62faf42f78b37912d3adb410f20bf16b31359cacc25fb783083a3f065f0a2dd6fe58b8f594e11a87bf0f4c5f5493f334c18b03ebdefebce50228937ec13a8c221b617450486291071f3c14f64f66c927dd4bd623c214ac35433b8a6875cdf00916476eac0f196858aa1484bc1cd45b726d33a965619829b8deaa9d9fa0c3c210f23967ce26a4bdd939cff8aa662f70fb0af97ee44bcb9e2755000a195741d8919e4dcb1a5caae21009f686fa1489c72f16f9fee76b5410ece7f406947f4a19f394a5121da79f3216777b0fee5423328156ecf0b4548dbd5b3f7b526d6b9cfd57576f67dd521c314c2d37474ed0cf732c3b073a101c735a4c4e6b33c9aaa12c91d147ad1075a20287d36c388657614a9c648d8e49cce8cfa282b2a2e8e9da6e4444e4b6aed1bd0ada5009a335cd0500bdae9a01b97f7e8cfe8372398e750de92ee4a524393a19826d19de5e762fb53a88b9b4657e9c6d7d01a4124e3e39532f614aec5cb88d982b78b2ff568017c92f6a1ce5298b5f323b5ee61695038ef0c3a7a339cfac31cf7875a4563046a40e7b35cef1d37d811b342fcbb5373122415befc23cb656a619f7c262c443403b23ba20e341a079918dec6f4f801b92781179ad7ac1951f39ddb0b1f1fb95b28c0f4593a04486f0e0e86bb3b014674879aad10f41e0bad34d40bc817b6fd43c1dde8547882d82e5111e208107e9c9736d16ca77ac7453d7b6c7976a7dd6a4c6c0252185bc9948660a07b66151b09b980d8572ae829ab2f6d900cc63066c4ecb3a0317e8a9acaa8e22a216721f3d69c67843df2fbedd88bc424f761cdf420de4ff2c55b6925b1826c1c4134090d2aae82a7f64a8d428efe1b21097a6fdbc9b8a31c4d46c7b32d478bf5b9181bef8af4d3486958d7c198c46a5ad771090bb64e7fc2bd7677ae7618b861c83c13177075063517eff40cfd52ae56650e9e7035f783bfe8920c754e98470b327909ac2a407e07864710544b8adbc075502c75b5f0fdbca0cde5d94b013141c96b55ae1b60ab63f9e792641690af41b05a78233935fd7f82852ebb2602a10459a709256c41d108c2aeb71925089cc79b121eabd5edc54f3f7c8929685b88ab29700c7fb2f247cd7962c8ce6dc9f79f9358d6a7989d24ccc17d0dbaa0b7fbe73479164181ae7d6b6a02678cce46f74ea2bd387ecb73041817b429a0220e1c3635fe492f5f3a8e2b65c086fe24c375563d7220856dd8f970716d548492964a156554dc88810c3c4f81dcc3ae80243e19679a3be9c9b1b8c707b416e9166c54a568bb9d84728c1a283d9231a12b13688ce2362901342652d66bf44cec223f561d2735d977c6adcf57e9066220d0770fc77fdf6ff367a2f36ae20062887beb88d1b453f267aef9bc763ab716bacb9214c38b95f4f2f3f6c236aa71aef83c1ae4b26133678884476c1d7c6d3e7b99f13e028ac6cebddfae4793f9ae975f3d66b725b500e7c7d2f664eaa0c358deb91cb2d6173394b306749d2bfb2684b985769bdb682e922b75555d38dad1899057a64ef6ea361e4712244d02d0dfec8c3d40770122770c2538d6a14a8462ef18eb705c16e5ba30aa5366447c94869060e4df155f7d01ffda04c1ced0ad5fbe5fdd85856e1e49320319687d31a6e4c7145479f45f43a9b8e9ffe4cbacfad4a21e5445e119df2996cce8b11d0f224efb4f18b544d456e2fb1d96fcd99fc319dbd86720621ac25b490f3611f7e5655bb3940a503c07dbf41f4b87593595a66008808744668371a54ce1b9dfdaa16f90415e57470bc23898d13d8351ba34369e96347da13d012b4eab32ada90668654c5ed2b433716b1b4170f640cf4b40659efcf4150237bbc25f72b248be85cd482b55ce2f5f73e8f02efd2465805b37d12487465ec1085bc6602b71862771af13e13baece4916b1ddef9ce016c92db9fb9e82aee5e1c4e22c45090ad1c19801ce1c541ff3902baea7a12dbcac6ec2d128ac7acb203463921ca6ce1d182d60d553ddecc4a3175eec2e924e9191e0d69aa49ca0b653495b8c62b802e443e669220f2a4047a56ed5cb7431a3387a435070795e6e63d242a74555e97371989c6d0040748e89ac316618d5d6eb7bff8d91e953afbe00464df4e4f6380c273b7ac5934cacb6c3be4da6649c8a5ea12bdf9afa1ec1e5053db7668c10ae2df75c4b3b14525369bf33741525a7630158aca3d3c7da5c1d71d3f63c0c2948a43236968d623c6c163eb757f0c78d6ae682ff4e4b673be07193e8d6c106c92851b393f0523491d5152e06de675fa22ae7bded329836a8ca0b955a59cb575395952c6ea0cb1644f2cada196b96b44ee12115ff9668e32886103d8f8109fac4a2287738ee1d2d4c1c19dab94eaa2757ea32016df60d7286099eb010ba570b5791ce4c54d860b15d56c53a5ddb543b0b602b3a87ca5213aa9647e51b1cb1736697506081240f4f7163a646f2be30e62c617d7572d820a113f96320834a2f43842160511923bd1ef4f723a2ab9b242fffe97cf0199c9f2ebca266a63beea0af279f2d18651b2ea9789d03025857c8aefc5f8bc6ee92ab7c6ffed2606f9c7ef25cb6c96140256a08cc58218869c52f3e5074fe5ace87a86057cc29fc845ff275f1b2dbc5991cbebe4c556b29ce3da3415958f0c9c68a5c664a1da60365ce56b9a4df24ec5d69c6f5a2e685885f6973c0ccd4caf7e000346bdea502b1418c8819e05bb7bee31bbd235819b49c892f7dadade576cb8ca68bda916a598c32ec03cceba2d01a7960f38680facccdaaf05e254dd8c3631a7222d1561c998c54b16f17a425f3247232dca035d545202e1b180340219ce31c66987bc86f983240e7fd2c926e8af77e6ea9f4139ff1edc0c323b67ceadead8f64a8004164d942f6aa65a28544d7205d41aafe62c5bfc6fd9fc322e2a8b620532d00d1add7a0d25a9dbaff90e19de14ac2ca97e83a2d77e63888ba0f7eaf9b18a7f2e5f148d16887580e55e894ae79024385f439acd071494e6469b77d07e763553652a470f3b4bd8bb7968052f3a969dacced51572bd125870849ce3e55359b2e17eabc3153b5f62868ea0ca1f40738488dbe0020c103f53678b9eb1c10000000000000000000000000000000000000000000000000000070a1115182027");
            assert!(
                provider
                    .verify_signature(SignatureScheme::MLDSA87, &msg, &pk, &sig)
                    .is_err(),
                "Wycheproof invalid ML-DSA-87 vector tcId 6 must be rejected"
            );
        }
    }

    // ---------- ML-DSA-65 deterministic sigGen + seed->pk KATs
    //            (mldsa_65_sign_seed_test.json) ----------
    #[test]
    fn wycheproof_mldsa65_siggen_deterministic_matches() {
        let provider = RustCrypto::default();
        // group 0, tcId 1: baseline (deterministic, empty ctx)
        {
            let seed = unhex("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
            let msg = unhex("48656c6c6f20776f726c64");
            let expected_sig = unhex(
                "69da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c2862344713a1e9c086a44f9a870a3ccc14de62d6c12b278c354d7197c4d6d7f83d1422b29b250f5ee3fec118311d905e5db2b4b8b23b8d542202d6652f6dc3f9d7ed51f2463082d3f145cfd0fa7ac548a47e91c1ccb1a55b215e90ab355bfc6d67154287b1dfae0fb530264dbb841a7684b396e5ca0459d795216416a9d232bc89b32e0f9461f53107c78e66c8e876554e8ddd501867b55dcfc1fb33f102e03373cdd192640f1027a08ce277b468f6ed0fe80a9d6cd2d6b2f7a3738c8325d95b0ccc6e7b9fb000c923b92298e0867d4a9f6dd5513e8001033c633bb1641ee66349487224dd43386c7fcc29916332066a868100d46e2c5b8354c28f087a024cba27694afc4c1665e0d72b37686919ad55052cc63a144febe4e2a0c9ae416e064e289f9f69cbb883665d1130826b7b74e30c94a2b98b67b471663e3d66326db3b43bebf958e8665b68eda90e8c5d9494b0c7c9ec48800910dd6d906b1fcd47a0aac462ac87b126d21b5ba150df61f752257ddf5a063b4a5b150371d625535e3b2874b9fe548960ff67931cd6c12496e8213e2ace6fff48e6bdc60310e49389f62579db26b92ad73e9d3f23942cab51784f48b3660b6450caecbb0df2aa4c8e56577f5ea450d2f7f51aacc0b304a62250bf2cae7b99dcd955b6596625d06da1c67f730b706fdba630f00fd891830d251484640b7258ab364d6fd9986878fffa69b7c44b92e43143affae8b098e1d27716850f37553bf266cdfb561abbcdbfeb80752b364434e64b80429b54cc88693ce03dc0fa147f0741b215f0728499bdc25140aafc976ac99e910ba8a8a50d21b7bddaa28626b3b90a93fd44077068357c81d36e735eda4362930adead4951a0baa104f384fc70e842a9f329e1868b07b455e9cc3fecd54805c9052e70f88c3b92fe0fc6a4d7dda18cf5694e5398860e439a1e19d5a66f2fbc0aacdd1a498711bb16054796c015a715395ef6174e37b04eda589b673c4d5dda737817fb52f392caf7a72d7a3e84b2180cb5b75bc8af065bdc05c3e4040435a1b160081352ac43e09cbf2ead6e09c2b0be0e37894888fe2812f68806f957c13fce6ff167bcee21d4f412ec95a4847f3db7bf441223a4d4ca9ed69adb4de8a4b5b01c775f2721226e6c59ff26fc38e1bb78a384b30e7b55f082e264d8f25e31518619ddd6b6a9faf8aa6cdb5eab75ed59a33825d5ef8b93bde5d120ada773fcc0852b918f4f03e2d2a543b15363adb823eb1f6c533b98d940411e1f5c1cf521f9f63d5454697608326625fffe01bf87f44187dad631df2898effd2c291d98222e564abe3b042b75e90c9c54667842fa8ebb68a1244bf8e0c3ae3ee5f97d5ddeefd986c4bd3f99d877c2cc2381a89abdc61713d38cee58bf69805a485c288d21b15843147066b4a74c69dc25de878e21d35fdfe6746feb4c166606bf3219e42cf63581e7e6bd6570f40f8fae590cedf5106fe57037ccb2324b74fca6500f6ed3d0736cdcc67d04f8fa9e80054a5bd7c8459fc1abb1c4c78677d7f6b325af94a0e5c9c7db0a748e12c5265e8724947d9b5c4bab1a8b6faec827cc41ec115ef3c2d7348cddabddfbc8436f3b41765e13f3762b3b45ed23156f085831e726a55d4b83848b3d1d3352aab9edcc0ac2388f2383f6301ad813b917ee3f23734e057832ae4cf65e668c9ddd0bdd0f9d8b6693254649668aa91a1fa5eb7c59859bb6ddd36c25f4a2223f5d688b480d0388fa307ea69298f9bf7737f6b3dbfda87b331affd75cd8d88f0460e98ebc2890b217bd6d11000a3a088cd837f4f8859a43f76afaaab05a0c3007a149d4d6b9155cadc2c9b55003efdec5012b6272b87183694c505f0446ede55f35b8ab201f9eda974ff840eccb0f004fa3acf753acd0613f66e2a6ac82e322199d37b4af83cbb3d98371c31be79bb42331e819644cbad2ce27a04e4c517998692cd8331552892e199a01a6922bda4d38ac4c01f708809e529c3216eaab399ef25b350ea213ba47126f278140e17391ca7139bd13c56f415e6b74aed8dbfbf38c95dc6db366fd72aa863a27fa1ebf198716400b978a3709e35039731930406588ebdffd35fa230a9b75fce41d7acd214ca4f0029896c137495eade0cf4d10fe621c73f01061acb077de72177ff5dbc6f0c5bec681aa34668ca4fcdd727525068b0b0e9072971b84ef6ce11d5c3c6024da40966703dcc2b33ae04f677677635a55db508f34f1403cdbe37960c8577dac3d848b29f3b5c5c6c56fb74f34c8f4634c04b8cce9b218f1760ca00e6de87efd14087c633469c892bf3e319443336733bb60cfb44941bfa25229aa24384d812db90fe74e0f93fda005eea87400736cabc036f71421b6657b1674d4a8f76cbbf3a8b1c0af82f72973927752257c532db439d96762ad64f102551a9d03f9ce3d8cc850c393c128bf8054bb55bb92ea31ec0706f083a9cf90424c617f8ad2a21225d1913c30e8f47a6b7131304d536a85596ebfd987b64b6bf3c51638d6c839214b53c3c10aa52bd9c6eb77fcf80b5e3b724dec1381d0e02207a6adc73ff53d9d1ffcee1c4a28fa5445ce518eee937074ff7a402f5bbcb362ff090415f9dbd93b62ee56dc8c50e4d2e34c6c621650c0dffe311484e95d68de77170c909c815828946aeeec7ede56bcf433e22fc63a33f764ced1f9242f3d26dc7558686e471f30fbe9304d3d56af8b23e72a4088970b24b2f7e968c1d0392eeeb0b0f0ac8c176547a5383d948ed15484b79e21314a1f28ed624f61e5aaecf2269e5b027e1910ffddede52fad4e8da224e8a10b079548fa7cd44172f4991adfd7623d13e5a19c812824bcf990c07c9721ded9093be6ce7bc7da3ac8c932133a64396b822be92b088844991596df893625a4ef24543bf75a10d7d17ff70350ef62ce3a7758aebbf9b3977b08becb9ea28376082f607965f2cded28bbdb39dab7e00833b0488370d221742b66e27d9ee2d9dd07f401bc22a62c8a9d8d3a290c63804991496aafa47a32578f583cfb53d0c2199055973440d7535e0da6cb2957f4e04002ecea68f9c3ff76cade27ed15fd7835989d0abb197fe32f68636139a42710644bb25860ff33f539200e3ccb8a7738422ca0fa0c744b4c19d15c5d4a3cb082e20a78e20b5a4965b043595cbcacad500b5adbb6cd597e6a4b9c5ea6a1f2e653b5474da277f1818048094ac9e0e1e0b20068d1c1ce5a114a4db7195057a6ce4d221c336fdc29190fee8ff855cae8b7f7c02eec21f972c827066d9c6dcc4a4179bc44ea9b88abe5124bf78b071e09e9af43f739a6e1030091fc091e73edc447f25c68bf84b8df7aa8f091ab42662b93e02c27003afc7b0ca69efcfa60bd53d4d78ceb7c4d2c8fd5ed7e8b35024de849e06400ad145fdb28348d22b317ccec704c401f88db1af2a5348223f5cefd914e404c9d73805d0de77211881486f1bf4aadacadd3ae2588f0db7b5e6957fed50a374f541cfe5e4e923c82ec47e5b3d2c70ad6760c79cd5080b490bdc75f9ef5e1d17f0978b1e8770775f902b9463e6980e1683b2454751ba2dad4a2e6460924bd60ff49b03230cb11fcd04a0388e60874c35d3f6cfc4dd487665e1b16578751eaea89e126bf58044596e3188c7a9631017be1f2dcd7d612331832ff8755460dc496aa99a61ea053c78e72607a18213ff9ef4bb880903b91e9a43e0b1f0ed1511b2eca2f4253fcfbd7d0faebf3680fbf0a45df231544882c9c46505c726d56905d02fd046c1652d8fd06d15286a1a8f8b69fbd825ca421fd80f5e9ba1a23f924937ad049adeec60c78fea1adf9b1ef7e8ac4d1ded18f1a801b0bda8fe9a88098825ff3eef5c1fc68cbea143310b39543293f3f5fbcf4773b02054c0bc79f00554947c7604b36389c0c45f597a88f3713456b4cfd83b30cb6520b624aa09c812066a8cd542dc67e19e4c92b562b4e0f6799fe57d9d4f4f3e0b6fabff4b1fc190bf1e78775ebcbe3655d370ca6c08f48decf6153a4989eeab6921f8475f85197f51d651e563994257df57977e5f219b4879751de57ab0374b407a21adb4ba520bb35e7b7508675bf49f4e432190451423cbd529fc79b22baae9cb1d8660c3a49c456ac03bc06c0ef3b02f7d8acd40919315206fb38e715139c9bd6f89a58634fe683df03f5bda719764f6c38131bc5ba1c53244472ef73834ade04b86ca08dd753141ac0a9a230e246735060a044018bc9b75d50134b20e6219c13f8325b5a0201e9453f6f012fe72e829ee1c637fe30037a9212a31c6e713726a6cd4cf2dd66ffdba77f1e2800e717940f231d04aa2e4e88dea084754947d848c0271856bfe659922408449858a81fa6583f062d96898d18ec53664f0067eb9b9c40ad2579ba9802abd8d1bf287e49d94ae397e784db14b5f7010ee4fc42e6e3c8ba80370afc188fcecaf466ea830d7b16362e5c9329980b981decc7174f3ff70a35d8a180ee12ed0cbffd4e8d14eb503387e4959f702d4293109e922eb561371f9ab21475821f8555d92f0aa1c3d841a6f1eabd4e663993636c754ce2b3c3f6a6b6d0b161e777b8296d7dce7fd162970496494d4f60716244a5a7fb7cee40e1d565e6566697e8f9300000000000000000000000005101318212b",
            );
            let sig = provider
                .sign(SignatureScheme::MLDSA65, &msg, &seed)
                .expect("deterministic sign must succeed");
            assert_eq!(
                sig, expected_sig,
                "ML-DSA-65 deterministic signature must match Wycheproof group 0 tcId 1"
            );
            // Cross-check: the produced signature verifies under the vector pk
            let pk = unhex(
                "f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7eac20c5754255206a178f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe283d106eaef92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7ea9be178be35405683b44367af85d2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413b843b83f3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa855f827049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab29e892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edbafa2747db9bc42f92af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f9568bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d48cc26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb929bee9ff5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7dcbebeb5a239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e0501944409f32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c86744ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b62013965ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb06f9116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bdd0c31e9f1080e8ed8eb99fde66bafb29e3357389fe3785b60c78e229ef073e1b65e34d848bd4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b636afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a842701603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb271416b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a49075767ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf252577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd3375e608e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67acf29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b3024df986391badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa6247342905995233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca3268265c9ce042d50915430a6c455f32277da42f9962fb9163b623231ebc080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd683027bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f8881638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d25733143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480dcbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba3768c55bb1f07aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430268c1492a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776a37a1f56fbf7d08e591f978da49c3870625879f70e2418aec5cba32fa8c346fa9038baebc35ad0068a4d03537aee14c2e71570a87490377fa8dd66f995aa044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867bae249431dcf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455ff47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87173a18dc",
            );
            provider
                .verify_signature(SignatureScheme::MLDSA65, &msg, &pk, &sig)
                .expect("produced signature must verify under the vector public key");
        }
        // group 26, tcId 94: DISTINCT seed and message (deterministic, empty ctx)
        {
            let seed = unhex("9d881c3a88a1edf505eccd12c92f8d0be6fc3aa2d6e095e7873b45802955c4bb");
            let msg = unhex(
                "1a84210d357a88c86a11e31524ec0d2e76b9cf2b042516ae6242a02068253eb475a71d64c3d1080767b6f77676f6d6626604890c8f07acc85177d9475eb52220",
            );
            let expected_sig = unhex(
                "dacf8d6759606c392d89b6a1f38c70cf258621a19f209ef5d2ddbd99fae4ab77316518a1d13f217036e1f95c28b67d34ae66c91c8ec6f9458ca9b2fb0f5bb8f9f5e2377912daa7729e0df8885b34496ceda37f86d3d92f44080db7db4ace021402d64075e3c097fc6c6a88290ce23a2b28828f27096991c6c3b70761868d898ad5003b4bfc6fb33f4c9331fc885326eae53afcc15916f0b7acde1ed8748572d9bbbe7632259d21bcfd8d32feae24e54acc5d1523d357e7a92c31d7c56b706c225a131f7613786fac424c4681a2209130edcb90fe3ca3c7b41f211d98746a3ec8ccd2688769a9df50d50a8e1054abea652a52d722ae2f1ec3165820186d354631435d62fbb14732fa14cc51a3cd994f970fca249317eaa3f31fbeb5a3ac80cc203ba6d332724ed925f9c22415bd1e1e418c188c58e87520ffa3f4d4ab75784ebb7c9493285b073a3cc9f1553e33edf87255ab5aeabe65fa8150c09d2dfb04257cb9eee2a30044d39dee4f8077fb266b07d0ff82390e2b47a3e73ec54e158a4828fbf7a486fb7760cdc56896d74c3cf25171792e2e5710a7fcd1d46171818574097d80d0c2e9ffb78853741eb0ca65488edb593acb80ebfdd2c93843ae76f2bb51b2cbe68531b562d45e4808f1405b16835ea59c6b914944ff3ba92bf306339e6e3c667e27a2597be3b6b428eb933587ac0e0b7ebc3528721f2659d01f63e4865d70f3a8a4b8cdb3f88daa41d2cc0b1566228392e30bf9eaa033a14e92ae8195a4583fa91552f9dab7108dc6ab77e9beadc93a6a8d926c69ff31492504c8936fc8e7607a76b5c107efa339a6f23604de3c4a4e96bd642680018847d2a446cde1307fa300113855faeb10eba0650409c8de9c73ba0cbdd3a5845eb93bd494bda653be93693eaa323106c81b4a48b51785bf72ecf5298ad8eb998b7484578ce18594a0bc7a14f0f48b253743a1340971ca5c9f0838d99c0c0ecbe4ad4b2a8967f8296c690e5dcafaa66b0eb5941771f0c9cd021da5d5c6a7bc5f6e674368ceac54812a25225235ad7bd5068c00fbcac40a491ec8eb77c1632396bd35fa13aebf1d1e698db3e307de4ed012a9c3363046ef9276178f10e7ba994bdfadb81180dfe7fd8064f72aac602a548f4fafaf60f9672080535cb681a62a742dc5742a9526131701dd31ac5a05dadebaf637138de4a893469ea982247ec8da6389cd33c9f7f97135e6a55f6b3bbb0ce0a40be329c0ae8ece0309730e1e9ce959b68b7867328bf193cc721b6fa2f1049cfa9802cadf353c38aca8db90aeaaf970fbedbda6251458098a36af410919cbd3255d0ee620147124791955af515ba4c0939edd88311396bfca0ad7bcc400a1102d9279f914dbd2ba74faa8e54014c2563c7f5007608693512ef97061700ea48775cc6c72b76823b73d76af969b4ae512284a8f7934ffec92eb6bafc9bdc17707d0fa5557100cad292a79d6099e7d18d4d6dd721a8f241170d252360f3879384a024f732aaa6ab50c72328521761a8a7d510ef1f919fa6b9b22718c13ccba7deed834f68560e1e4596e3260d9fab7565425d1736af2a0c7a06710899c275f7f2e5a29707a7baf21d0f406b92df1b832edc5c9ac2f540af90839397d1dafb45f4d75c3e8523a47722ca92dcb7406fe69d3f31ab2d301ed6cc1ca4faf119ba2272a595658df798bc987e9588148c6b67d6054879c61bb4bbb61ac0a5a667e708bfd92764aa9a5c3f4f29348c4f3912b60040eb06b605ef0f1544156dc2557c3b60b5e15b52a364fe71d70a8a7ecd674baa479837c9e1a5d32c8cb41ca04ec0b1854e167bfa87ac30f272aaf2a41191fe8a2e8fafc884146c31c44e5ee47ecfebfb8292eae470a42698a9a94979ef5b6371c10c299a8e99e0e6eb5beba1f77a635021e8ce60253e29add096e9b7a364f388d4ca4b4ff90760d117de1e97f2a4a80e0d83c23d2a5e53977bf3d710d45bb39661a4d59b7d00aee87ee1fcf6fc250b1a54cee4069d7363814cd6a9a9040ad76f1a6d43c7510bacbab22285f0ce0eef4fd61520a59fe61c540f9918e3629636c6e45a542e33690e7909f58bbf91bee2cbb3afd3dbe3d45f0c218aa461023e963ba7fc2e1f405dd4a7ca8aba9bd6fdf485911d4ba75b622d4d7356f2770c73d9006392a16d08bd7fb5e852eb0d8c7dbe5243a6ec45ed4222514eea5308bd627613313460b2645a6b4fa8da3f227d2c504aa96a455fa40f1fc66339e4b3975ae7f52877b8af97d5f8a7ef7fec47ff4f69a86782102949e502ddcd6a553f1ef06e8b54681cc914f37ee27cb91adff1dd100a89622aa63232a7a756fe92d26de11974b173fde511a22ed386f3e7ad0d660067e3fa429fa1891da7338e3e3b5c05b4ee894ea456e5b50aa38b66fdb901b3b82bb0d38e3cad9f12e274c2c5a42df44c807e495b5ec91341c9a0c501ace67e44b8761439595b88af4c9923333e3fe982aae8ef26b137ce4444066ea0ce4db1665a88b3708ec1efca6d09b9e0ad2e3cf5db2af8e057d8d84bc9fb1e66a2e4b6d6491179db5351502e91b85c189c25a323a80785ecc5026f5110179f3afb64000738feb5ad12600e2a3cdfdaa155b982a764107c2deb671e7c3e992b3d8feaf1261865b6e74457b9b6f1a1384f6315f5b6cde47b87332c79492a5c365df966cfdb780fb47ba6e43b37e86c99745de3f3af6b09e9acbfdf25cba6e3fedfa7484e2b1ae66570b966c77e48a6797c7e044b2832d3c2e01192e4c74e13573eb85638c3ab8bc256a8dafd2fbefd312930b39fa66be3bfd6c0bbbb25a78a1cf8c7d6055eb334e8ef9194d42d4f8d8baad0a6e62d4e16accea09918e62c91e9e48aadef7a25acb8320e8f5d1fe9d182fd6f89717cec20508ef61709d9579594c06243d2469ff46dabc717a749358f5c891fb66ed788ff828a81da53a1376c2ccbab9562974d6147558e62e796e9d41948acff1b1e036e5899a95a111d1be45e4b3b062321dbae0de57810e019b523dd5de3b3add8fe32ece1e894d81f0f620637a4cbb66e0be2beed03b601e65d12c7c5c6c165b90c80510f2de33903569243fc18f1e4a60f10365464076e98397da0bb822fa5599fd1824d266b07b705693ad09958e1f2fe81255d41fde098505d1d5102c8c6b5328ce06c5520ffa0909231be3bfb18972260da6bb7d9edcf8f50b8ce0bc973b72ddf59dc5b6372c765b5867dbed3b6ee5e56d6f0d7effa9574a848582ac0050a34f87fe2a4052548169420b0cd71898018c5aa2f4e861d138fd0f6375d34b1ddcdfb2eb94975c2ab4125c492bfcd08dfbe7b3cb0f3c2e0436a803c9d7112d2a93ffda26b0547eaf307dce468a3d7ca47a2cfabaa1c941d3b8840378dde957196262ff5b3b48620eee19b0326e6a07d84e2576a7e398a16fb69932677d46424a82d1291b87eb4b9edf6975bd4fd3dec983e6d6ea038112f35d99f1b1d93ebef3a8dcb6f84b9e263ff07cb3f4ca006c6ce543a1fd3af88ee39f88c544fd246976d5cbdc9d12f3137ee7c3a86ab2e0b31dab3bc9773d0fc3be4b8b28bd7ce6b2061ff98f1662bfc75573d4f15a9580a34eaa60173cc95ed40c567a778e7f67082fd92119fd868c238df6921f362c7c83bd2f6c637cb793741bc29534261e07873ab6e239719b20cd63f0bf48b50e49865080bdd60eabd5691ba4b3633c8fcb42dbd71af4df9e25fcd400cbec576930154d7a69282f2b3426d1e701425e02e275e8528ab471fac33de6acebf393e037cd6692662cfe4bd63cf157e5cff5d0db0e1f82653bab6942537da47cb786eb2345a84a73fc38c6e52cab80fb23b20c53282137549c72510f4450d3e1d5b22783b6e94d645c170fe013e4266bd0d825e3696a953f4a4ea058bc28478b68e44190461b84a07b464603ee210d34edff155706df7109b2660d6ecca50caf3f248fd1c84486afbfeb2fb9eea7cfe4e8ec4709d8959e3cda924161f5c3ec00e4a30d4ab3f6820538706ad1282cb3c6bb38b3067fd64ce7fbef0d5266bed8a66fe8d9424fade8e86cf9e942d9666eecfef591bf0a98d87b2312a604a8b3611365c0e282b9b2380706ca646c2393601d4d385e8e90164afdb3cd849ca5fa732dcb87313df8fceba7562f5b959ac682298647e2c28401afc80b2dfb34ba5d9dd185d51e63cb3ca8fa79ef12a6b5dbc51d6aa754580cbe61e5967f4a3b59322d0644835cade9fe7cd75b34a1a3ad9abfd530f022fc947fd4a4ca8831e7f2892ddae691a62722749fc6724ff6a9fe7af0a86b6c9fe92a9b239eb82b2965a75dbd10e4560294ddd1ab9b822d8df6d365634ac48661379fdb4b34200aca456c06c49c744d836a8dadc6613a8dde6cf98e33a2ee99c7e452b2446f2f0f41a91ad39642c649126af029a90c9c505d1dd1427e6f36480f581494c0101ee0b2ddba57914dd5dca64c68006cb35d3213bea8c3fbd41940f56f63a107bfa28bfcfef8a13370076dc572a039d6d7766cfa1f04d623bf66789200118a756744a67cd014e6d0316ddbc5b1a799c3af187a2646ad6d0cb6b5adc1cf6099f59f88af0e3715f92b1a5ffbc9f8d4f097d291f494a2d33b8b0c22a0acb3b5dff2273847535b6e8f989eadb6f50e172035546b73a66465acb8c1d3f70782939dcbcce90c5152858b95a6b1cedcfa000008141c232a35",
            );
            let sig = provider
                .sign(SignatureScheme::MLDSA65, &msg, &seed)
                .expect("deterministic sign must succeed");
            assert_eq!(
                sig, expected_sig,
                "ML-DSA-65 deterministic signature must match Wycheproof group 26 tcId 94"
            );
            // Cross-check: the produced signature verifies under the vector pk
            let pk = unhex(
                "9f551e7f9c08b283fd5ba2ac4f26c2f50605960824adece499cc6cbd55371594ab319e56e5e455ec4d495b5a7ae8c34a08444ac22de4613390207145a545d0832b326ca79e76cdfb58159e740d6757b1065b5dd51cbb95401c713103efff046bdda2f0320072bc87b62c1f907f92a0b204dda9af7f01284cb2572d5693d0c754029057702357e8e7333298fc9b8e6e7baa5db54ee05d97a3ea437eb3a48ccfdcc051a799453d3ca0bac5ffe189b37dc3dce22381ffa9c793c667ad94cfeb91781525f7f506082f0cee0b6a0659e01f2e5a1206f5f48e7557a933230fc26f02f8680f620281fe037cafd7425bcce72bea49ab036d0a02ae4779cefd1876079ea6bf7e8d73f944eb8cc559b719f67353422a557bb45649089e9a6560701dbdc68529defe44aedf25fd5b746c96e6813780e09ef37563b4c92f71e6ebdfaf7eff9ee0bfcaca11edc604d849132c63f1b31774d9503fb9290e48a7f0dc78180e9fb7de367967a42308e762e8a4e5cfff3555362e3ae4456a80f2cae7407914c46238bbd04e6cb585423f35f7d754b82b8bd56f16612723acdbea9b3b99cd79e612099909a4e18825009e601663d7429bcc369a8da37536a1a8fca2fe29264c9321446b1cbabdefff6d1f2b6c66819a3a1d0bd724d4b893b522f9d2f4a5057838ae58f6508f471df3fb0d0414d1d6d82ef2bdf571864cdd6124185b54f5cd9989018ed11952bc45ed0eec722f5ae7df361c579fb28bf2781b3ec5481f2704761044ee5c688fcad731fc5c40032ebd1d591357bc33c6a1a3e555799b7e49bb2396c31cfe66eb5b5fe503c9a4ac4dc450bbd3c19148e093922adb413798bca27a09920b1ce64b1e8e7881747d6b71d5e70e7bc2745d89f1fa59aaf786667ec29cf4d58dc0b7b7a2d5cd51c37da95e46ba06a34d60d668c6f96388175c20e1c40f3fc1a9a73e39ef2fafc46929e3d48de00e88c29343fb28cf5d8550f7eb42f587dea565ef430c577609f45fde810ad95941a46ab705c7a5fe49d59b57131466e2b9cc0935d4b0e0d10d7e504845210067b2ada746e26f70e53c8804aa21de03b66ffe4351dc2e5c6c778f8e9d1a5b35c5e44882174bf0eac90ed28fcdd501bd7f0ff5ae92281e2cf4e903f70aeb8418a137388a11a25d8cf6e43f5b87076bb407e08f30c4fa27aefc02d1215cbc0b936e7ef96b807a258420f16afa75ed576162a7f65be1b038c8e96d3fef1e990bb7c89f765c041f029200a7383d003ba7bc396eabf510a8bad6286b0e0048f93b5cde599346d6615281710f0e61acc67f1593a7c116b5ef85d1a761c2851d61c6aeb39e8d23a3c8d5f2c71b7eefd2df25af4e811559e536b1f1d5da58d8d90d6dc925b5e81d3bca2dabf2e2e955d7f4c7d0577a86150a5a8bd73f660f80b4e05c33edaf1b3b6d1cd98cb596a3fbcfcc971cae06194161f8976b825e1cbf6f433de500f5fe66482631a172676ed45b6f66de708b2bc3a230e955c8fff8d0dda921856e6c8266cc52f09e1eb53aff4cf3ae02c34b7625bdb0215461da16d3238641a14c5915956585b68ea637c0a2711d67447be54c4fb62c46f729a5f2d35119914da7b505b96e616ef8c001e5410a896477f2c8632d9d277f473039dfb66e4f003f15c6af62df3f47e8429077237aaa99530363605907523cb56759fe08e6430f3b087cc7073cfa65ea69514131b30569ba2cbf89259efe0713780e1654df23df106979d033d7218bc82ad0740afab16fa3cb1dca4f00466c4209e0308908339b7b7b0f695c0d3491fcfe228202cdfa97e8281dbc130bfd47a17ea2864d6f1251357d768a5805b639a12fd7daaf00a01a94d82334995cafcc154b56b2d28107d3f347a24593cbaea76b3ff9eafc0e64f2937f24227386c72d759b418bfb3b262ae50bd400e32c6949626c13586eac43e52b3b88dcd441e8ee4ec32891179a5adb808b4d64ccbe66a462fb134410d9e4d5a5ae9e4250fc78adfac4d05a609b452b615c57b59228e9f53567c15ea81c993638b85cff3da0fcb0bc3d2cb43617b46db53945a92a6ba2244430ab2c8236dcd6365d0adcee0f2b2899dc670dea6e42b9457fd2961e6042eb1e5f8ea9dcd38ad6bd4e1f42751de2c611c9801ffe99524d7b35f7b7c3eed694f574a069cd1f2bd087f78c69c5967091e83dd2ccf14ccde21400104ad96a5d652c4b790cc4785ec8c537746d505c341fe0f4e3e18668b1ea70f0aee459a1087e35a316d2b0a3d4b0748c057973fbe665961507d5af889e6bf0bb3fe6d16ae7c9aed9b0161c40ebdbc1bf83db8a4f96cad7220687089d652fd98e956cccbf762aea5c8e5b170f757bfaf9fbaa92c77e636354a4fff6c0c0f570d8e3a47916f06f905eb7ab6fab753be14ca80b725f5f1122367120d35b5e0706761acc5e7c977db26bf8398937b66dea745728d70e9beb288890fd2d16217426c5b844ad9f97f96536d800591749f9c7b384b9e295e0d17f5faad7fd6a6a8314461d128d09c3a5ca72a32565b640250451ab22ebd769c9229ca0195c1afd418f98c571b86f76aefa9b03ab43813b66aef0d2b7ee9ae3ae45c186b0ce9e2becb8cfca0e8c33faa7eff7fca14149d36db558e40e24d28a74c9562e53c77a380f4bd9f92ffa7dee1418ce75426c0334ce80ecf205f0dfcdf8db267db63d28247e7e399fa6c6eb2ac81794a989f5dfcb77fdc99e68987d04503c641d66b09706b6085be41744d694396b032ccb5a8d8608234f95a81a",
            );
            provider
                .verify_signature(SignatureScheme::MLDSA65, &msg, &pk, &sig)
                .expect("produced signature must verify under the vector public key");
        }
    }

    #[test]
    fn wycheproof_mldsa65_keygen_seed_to_pk_matches() {
        // Belt and braces: check the FIPS-204 seed(xi) -> public-key mapping the
        // provider leans on, via the same SigningKey::from_seed call its
        // keygen/sign path uses
        // group 0
        {
            let seed = unhex("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
            let expected_pk = unhex(
                "f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7eac20c5754255206a178f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe283d106eaef92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7ea9be178be35405683b44367af85d2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413b843b83f3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa855f827049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab29e892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edbafa2747db9bc42f92af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f9568bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d48cc26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb929bee9ff5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7dcbebeb5a239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e0501944409f32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c86744ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b62013965ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb06f9116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bdd0c31e9f1080e8ed8eb99fde66bafb29e3357389fe3785b60c78e229ef073e1b65e34d848bd4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b636afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a842701603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb271416b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a49075767ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf252577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd3375e608e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67acf29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b3024df986391badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa6247342905995233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca3268265c9ce042d50915430a6c455f32277da42f9962fb9163b623231ebc080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd683027bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f8881638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d25733143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480dcbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba3768c55bb1f07aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430268c1492a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776a37a1f56fbf7d08e591f978da49c3870625879f70e2418aec5cba32fa8c346fa9038baebc35ad0068a4d03537aee14c2e71570a87490377fa8dd66f995aa044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867bae249431dcf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455ff47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87173a18dc",
            );
            let seed = B32::try_from(seed.as_slice()).expect("32-byte seed");
            let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
            let pk = signing_key.expanded_key().verifying_key().encode().to_vec();
            assert_eq!(pk, expected_pk, "ML-DSA-65 seed->pk must match Wycheproof group 0");
        }
        // group 26 (distinct seed)
        {
            let seed = unhex("9d881c3a88a1edf505eccd12c92f8d0be6fc3aa2d6e095e7873b45802955c4bb");
            let expected_pk = unhex(
                "9f551e7f9c08b283fd5ba2ac4f26c2f50605960824adece499cc6cbd55371594ab319e56e5e455ec4d495b5a7ae8c34a08444ac22de4613390207145a545d0832b326ca79e76cdfb58159e740d6757b1065b5dd51cbb95401c713103efff046bdda2f0320072bc87b62c1f907f92a0b204dda9af7f01284cb2572d5693d0c754029057702357e8e7333298fc9b8e6e7baa5db54ee05d97a3ea437eb3a48ccfdcc051a799453d3ca0bac5ffe189b37dc3dce22381ffa9c793c667ad94cfeb91781525f7f506082f0cee0b6a0659e01f2e5a1206f5f48e7557a933230fc26f02f8680f620281fe037cafd7425bcce72bea49ab036d0a02ae4779cefd1876079ea6bf7e8d73f944eb8cc559b719f67353422a557bb45649089e9a6560701dbdc68529defe44aedf25fd5b746c96e6813780e09ef37563b4c92f71e6ebdfaf7eff9ee0bfcaca11edc604d849132c63f1b31774d9503fb9290e48a7f0dc78180e9fb7de367967a42308e762e8a4e5cfff3555362e3ae4456a80f2cae7407914c46238bbd04e6cb585423f35f7d754b82b8bd56f16612723acdbea9b3b99cd79e612099909a4e18825009e601663d7429bcc369a8da37536a1a8fca2fe29264c9321446b1cbabdefff6d1f2b6c66819a3a1d0bd724d4b893b522f9d2f4a5057838ae58f6508f471df3fb0d0414d1d6d82ef2bdf571864cdd6124185b54f5cd9989018ed11952bc45ed0eec722f5ae7df361c579fb28bf2781b3ec5481f2704761044ee5c688fcad731fc5c40032ebd1d591357bc33c6a1a3e555799b7e49bb2396c31cfe66eb5b5fe503c9a4ac4dc450bbd3c19148e093922adb413798bca27a09920b1ce64b1e8e7881747d6b71d5e70e7bc2745d89f1fa59aaf786667ec29cf4d58dc0b7b7a2d5cd51c37da95e46ba06a34d60d668c6f96388175c20e1c40f3fc1a9a73e39ef2fafc46929e3d48de00e88c29343fb28cf5d8550f7eb42f587dea565ef430c577609f45fde810ad95941a46ab705c7a5fe49d59b57131466e2b9cc0935d4b0e0d10d7e504845210067b2ada746e26f70e53c8804aa21de03b66ffe4351dc2e5c6c778f8e9d1a5b35c5e44882174bf0eac90ed28fcdd501bd7f0ff5ae92281e2cf4e903f70aeb8418a137388a11a25d8cf6e43f5b87076bb407e08f30c4fa27aefc02d1215cbc0b936e7ef96b807a258420f16afa75ed576162a7f65be1b038c8e96d3fef1e990bb7c89f765c041f029200a7383d003ba7bc396eabf510a8bad6286b0e0048f93b5cde599346d6615281710f0e61acc67f1593a7c116b5ef85d1a761c2851d61c6aeb39e8d23a3c8d5f2c71b7eefd2df25af4e811559e536b1f1d5da58d8d90d6dc925b5e81d3bca2dabf2e2e955d7f4c7d0577a86150a5a8bd73f660f80b4e05c33edaf1b3b6d1cd98cb596a3fbcfcc971cae06194161f8976b825e1cbf6f433de500f5fe66482631a172676ed45b6f66de708b2bc3a230e955c8fff8d0dda921856e6c8266cc52f09e1eb53aff4cf3ae02c34b7625bdb0215461da16d3238641a14c5915956585b68ea637c0a2711d67447be54c4fb62c46f729a5f2d35119914da7b505b96e616ef8c001e5410a896477f2c8632d9d277f473039dfb66e4f003f15c6af62df3f47e8429077237aaa99530363605907523cb56759fe08e6430f3b087cc7073cfa65ea69514131b30569ba2cbf89259efe0713780e1654df23df106979d033d7218bc82ad0740afab16fa3cb1dca4f00466c4209e0308908339b7b7b0f695c0d3491fcfe228202cdfa97e8281dbc130bfd47a17ea2864d6f1251357d768a5805b639a12fd7daaf00a01a94d82334995cafcc154b56b2d28107d3f347a24593cbaea76b3ff9eafc0e64f2937f24227386c72d759b418bfb3b262ae50bd400e32c6949626c13586eac43e52b3b88dcd441e8ee4ec32891179a5adb808b4d64ccbe66a462fb134410d9e4d5a5ae9e4250fc78adfac4d05a609b452b615c57b59228e9f53567c15ea81c993638b85cff3da0fcb0bc3d2cb43617b46db53945a92a6ba2244430ab2c8236dcd6365d0adcee0f2b2899dc670dea6e42b9457fd2961e6042eb1e5f8ea9dcd38ad6bd4e1f42751de2c611c9801ffe99524d7b35f7b7c3eed694f574a069cd1f2bd087f78c69c5967091e83dd2ccf14ccde21400104ad96a5d652c4b790cc4785ec8c537746d505c341fe0f4e3e18668b1ea70f0aee459a1087e35a316d2b0a3d4b0748c057973fbe665961507d5af889e6bf0bb3fe6d16ae7c9aed9b0161c40ebdbc1bf83db8a4f96cad7220687089d652fd98e956cccbf762aea5c8e5b170f757bfaf9fbaa92c77e636354a4fff6c0c0f570d8e3a47916f06f905eb7ab6fab753be14ca80b725f5f1122367120d35b5e0706761acc5e7c977db26bf8398937b66dea745728d70e9beb288890fd2d16217426c5b844ad9f97f96536d800591749f9c7b384b9e295e0d17f5faad7fd6a6a8314461d128d09c3a5ca72a32565b640250451ab22ebd769c9229ca0195c1afd418f98c571b86f76aefa9b03ab43813b66aef0d2b7ee9ae3ae45c186b0ce9e2becb8cfca0e8c33faa7eff7fca14149d36db558e40e24d28a74c9562e53c77a380f4bd9f92ffa7dee1418ce75426c0334ce80ecf205f0dfcdf8db267db63d28247e7e399fa6c6eb2ac81794a989f5dfcb77fdc99e68987d04503c641d66b09706b6085be41744d694396b032ccb5a8d8608234f95a81a",
            );
            let seed = B32::try_from(seed.as_slice()).expect("32-byte seed");
            let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
            let pk = signing_key.expanded_key().verifying_key().encode().to_vec();
            assert_eq!(pk, expected_pk, "ML-DSA-65 seed->pk must match Wycheproof group 26");
        }
    }

    // ---------- ML-DSA-87 deterministic sigGen + seed->pk KATs
    //            (mldsa_87_sign_seed_test.json) ----------
    #[test]
    fn wycheproof_mldsa87_siggen_deterministic_matches() {
        let provider = RustCrypto::default();
        // group 0, tcId 1: baseline (deterministic, empty ctx)
        {
            let seed = unhex("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
            let msg = unhex("48656c6c6f20776f726c64");
            let expected_sig = unhex(
                "ba4275ff54c22d2d09ea1937a0667362acd44925c6d6965fad350b111d1cbcce68ddbd0e576d1a8810eb4e71623781f32f747d44c8e693749df191682f588906949d97617a4b0ec54ad966818dee88b95f0f28ca24bfc5bfe0c316140b0662c43093ae48b899cc71e5739e9d67095ed987a79b6a0e7aac960c3c4125f0e92bc9435d10bfffae34bb3af05e977ebe0bafcbeb2381c5afe3379667b4c201aebf162dbd0a4bd1baa88fb2f88fa970499a848737d3cf94cc8ce278880a169cad91f304e4e8f1091d4cf39d9a3ab9f88dcc6f3bc4df311a5be0cba290365b3e879527e2a77f0cb6eccc9d85a5e592fb00f3a2e925a26d295a6b82746d7f534c83c35bc4826ee4910216b9a2867032698996fb0e1669b539ccd2ec74d181f4844e8f4d28f9c174316c12dadb54cb1dde7338238a20731c2565bb959f8e3086273ed03abc7ac515728750633083c0b397b29d385d13f5afd2529b32f00dce66c9dc8ea93d99c8b61c5e0ab2fc70de2a8dabdcaf290d53e8fca7561bda8c516ad475e4ec6c7cd2603aa3c8a71d9fa5dc7efc33cf318bebc1f1594e6ea25c69b8f9ce34a65b8ab0ae8dd3538bd267d86c584b8f354d7e4776ed4dd59a73f9e70a1df572f033b69b3eafa5a901e02515472e37258608875ca469de07db71cd6b8dc7edeb3d866ed2d219e44fcb133a066e89d8e3013569ca6f1fee7bf4ae56a6d32a5f3e5a530819c31aadabc8a88503edbea9cdfa3171762e1e8bcebaf9bb6af7e540102d5fc810bbcf1e02ae564e04d9dc55dab0a9392d6c95a317730d9793954da2cb16544d15403d0db01e85881e2d4f1b9b98458e1af0985f98b014f08f200558f2fed7a70c352a27423bedeebb3775c0a1ede9d461d2aea303c09c8b1f73fc37a5b3a01fb24a131574f7eac90c78baa38cebe81e2335dafda20299f76d6a0ba77d2954d11381674f4069f45e133886d64222d92583d5908e3ab6eb6a72cfb41f7dc3e71c1383888f61624bdcaf12fb716de98232ee329af1dd045f30d377234db7bfd11ddab0b3108329e16ce568c8bada39a98df5a5f72a72f063fa4253313a806013f61ce5adbe54cf42180ebf6e496bd4b42aeacf069aaa8e1c231fd037b394d78a69d1742b45bc5784ab8593a198077423c4c357d734f9899cfe9b3b62b6b9c3f4d781b8484a3fd0eea7e8d6945f4ba2b046fee079b7f032bebbc402918daa2aa1c9433dc3bcfbd7f49a5d7a293833c21c1bade3e8a7ec3c83d485529de51b5993cdffe23b770e25acab0ab9fb3059f14952d9464ebfa36a6274d8da317a7b07c2afe38ba28ca942cf7bfaee4020e59911c047b2aa24d1787baae1bc3546364b782358676d75c7698769f1d4a0d5dccade7fcf80e308437f7fc24fdfbf72625abf1b0f534da62cf860da1efd986950e3e19a085999f4d008fce38459c673befcdf2287c1766e106beb4f3175e97812da141330dcb2beb3265e38c8423c19dd50a655c9e8dc969f6367f3383b644d53a26875d53cea26de429266b506e70e7e6832886ed06d81738b0b482bd23bda396eb674ddfdb64803d6c4fae2f040170b5a28923279838b7b876220d02dc7478666f7c3287b1ba4a2f8228e8c491a55ba459805c601b986caea27ee9436f63383351c74d673643b15f6007fc6dc49e337a65a8a96ecd7eef4ad730bf3dc1972fc396703ee26af1156dc4beb46c47d99bb69ebdaf81c2d738d0f70e57a2c7162f5a55242255675f22082aa43f5b3dd862b535b2a15bb815b4e9faf16a302552cd6098d40930dfad7a7c609d6aeade814242a8bf0721c1c26d0d3daa7a638880a6411c6538d80c259d31b639aadaea49563a8d7f5ddb64291d6b086c80d72bfe7d26802cbd20fd6ba5495011e42da1c82483cbe8e37838e73c48f79f65b205476bee600399feda6aaaa939eee12cb34be4e6bdbd18032c85b54a2713551de677a16ca0142ff97b77bc963e8f3c57d91df9b49474b01ca514641842893abc3181caee3f49b635d17daf41bcc4aeb1116ec4b3e78ff1480cf3a5d9c6a154384b88516834d19196976e2ba97cee91f7a0d73f7f8146e58dc0fc8f510511d39d82a7ba531a4abcce6b624035d753a37c5980343cfc7724cf83efb0c33fc4abb5b002241bf57a46b67cb5a4cbd637b2f19bc93b368d97e13c6a62c8443c8222e0a90c3ed1972cc739b824fdf729ed8eca02ad96bd78bf6d2b3d2853e24fa93199ff41635176b31aab2207013d0a9317fa49668dfeb672b8129e6175a2998642ab8e74f0823e3b5480ae80180ca395f5348744a3c7b344891f008aab65914760b5fe852615ad6425216b1c5e777db1a46517cd01a77b277cfa2c6f250c2d68c495fef28feee6e0716817d6b30716f5ca48001805042133eca17a41c2219784ce0f12858ccfd371c77b90966ea04c3996851edf31aef962946628007de5531b06fddf3449f6c552eaf6e16b3e9160e265900b8c8e414732505e02660e123d45a3d6f1b15e56fd759d38e821e27e84967e95c4b0d2a48e008897e655d1b65b76299f1e3074209abe44b37f8786b02df23aa4dcebe512e6312f1a3d6d781d749635247aca897626f5ee688f517df6cfe947ddead820f07fed4bcbe7f1bee3f19117b5666dc123d528f2bf03db346d6afb53804b0681aea98a9479fc6de5ae974d2c0d2055f07ba8a1d2d8b6a7e08a6805bd8634cc190c4988b502f475c36d78c7b3dda0057c818835bbf21c5a7c13bb6fd91cd3cfd76abe4c2ff908a08a3000b9021500ff94b297cec0fb3e51b1cae7026ab4347bfd5b6a641a3d347f45a2a2aacd22e521e00da0c3986c67672c5d7d7e61e7edafc15d42aa42cb37fa8621f79e9096b092efe853ab318b3e4bbd90f20165a1be1d3aa5b3de43751b65abbd952599869778393c4351ab8f534fd49e16547df01c40bfaf56de60b4fb0019bc34177cc8e2236d219fb3c0b84dedae6b88e134280eabd1823420cd1afe6d929774967fd7d885fbad33d89ed9dc5e0eb978eab5d96c50bed5887aa8277880c7b06bf2780cee82ce639a1e3344c88a25102edcc17a4cb48989c4ad6a998726ede31deb0b98107f40858bad7864983f6ecdf0c9761a42751b19d5360daa7fddbbd2e2292638b95c763ca1e747eedef0dd387e9d9ec9e5afee207d8c45703c5befc2de3878d313655ce85ad984250cdf054360f33d41dc193060d42cf9528b1fb91d6ca3395199e25a1a7739eba9a6a4ac2c417ae615940b3eb1b746dd0ecc7b2f7acdff887110115629f70877dafcd7a6625fa1b9e256bc8fe1d66005dbcf12fde0a5fcda5d4f23d58ece91d60eb91274df8d9d17d4a39e63533acf1b317db979b04ca3ab9a0bcba652d0010ca3fcd33ed8f8a62faf42f78b37912d3adb410f20bf16b31359cacc25fb783083a3f065f0a2dd6fe58b8f594e11a87bf0f4c5f5493f334c18b03ebdefebce50228937ec13a8c221b617450486291071f3c14f64f66c927dd4bd623c214ac35433b8a6875cdf00916476eac0f196858aa1484bc1cd45b726d33a965619829b8deaa9d9fa0c3c210f23967ce26a4bdd939cff8aa662f70fb0af97ee44bcb9e2755000a195741d8919e4dcb1a5caae21009f686fa1489c72f16f9fee76b5410ece7f406947f4a19f394a5121da79f3216777b0fee5423328156ecf0b4548dbd5b3f7b526d6b9cfd57576f67dd521c314c2d37474ed0cf732c3b073a101c735a4c4e6b33c9aaa12c91d147ad1075a20287d36c388657614a9c648d8e49cce8cfa282b2a2e8e9da6e4444e4b6aed1bd0ada5009a335cd0500bdae9a01b97f7e8cfe8372398e750de92ee4a524393a19826d19de5e762fb53a88b9b4657e9c6d7d01a4124e3e39532f614aec5cb88d982b78b2ff568017c92f6a1ce5298b5f323b5ee61695038ef0c3a7a339cfac31cf7875a4563046a40e7b35cef1d37d811b342fcbb5373122415befc23cb656a619f7c262c443403b23ba20e341a079918dec6f4f801b92781179ad7ac1951f39ddb0b1f1fb95b28c0f4593a04486f0e0e86bb3b014674879aad10f41e0bad34d40bc817b6fd43c1dde8547882d82e5111e208107e9c9736d16ca77ac7453d7b6c7976a7dd6a4c6c0252185bc9948660a07b66151b09b980d8572ae829ab2f6d900cc63066c4ecb3a0317e8a9acaa8e22a216721f3d69c67843df2fbedd88bc424f761cdf420de4ff2c55b6925b1826c1c4134090d2aae82a7f64a8d428efe1b21097a6fdbc9b8a31c4d46c7b32d478bf5b9181bef8af4d3486958d7c198c46a5ad771090bb64e7fc2bd7677ae7618b861c83c13177075063517eff40cfd52ae56650e9e7035f783bfe8920c754e98470b327909ac2a407e07864710544b8adbc075502c75b5f0fdbca0cde5d94b013141c96b55ae1b60ab63f9e792641690af41b05a78233935fd7f82852ebb2602a10459a709256c41d108c2aeb71925089cc79b121eabd5edc54f3f7c8929685b88ab29700c7fb2f247cd7962c8ce6dc9f79f9358d6a7989d24ccc17d0dbaa0b7fbe73479164181ae7d6b6a02678cce46f74ea2bd387ecb73041817b429a0220e1c3635fe492f5f3a8e2b65c086fe24c375563d7220856dd8f970716d548492964a156554dc88810c3c4f81dcc3ae80243e19679a3be9c9b1b8c707b416e9166c54a568bb9d84728c1a283d9231a12b13688ce2362901342652d66bf44cec223f561d2735d977c6adcf57e9066220d0770fc77fdf6ff367a2f36ae20062887beb88d1b453f267aef9bc763ab716bacb9214c38b95f4f2f3f6c236aa71aef83c1ae4b26133678884476c1d7c6d3e7b99f13e028ac6cebddfae4793f9ae975f3d66b725b500e7c7d2f664eaa0c358deb91cb2d6173394b306749d2bfb2684b985769bdb682e922b75555d38dad1899057a64ef6ea361e4712244d02d0dfec8c3d40770122770c2538d6a14a8462ef18eb705c16e5ba30aa5366447c94869060e4df155f7d01ffda04c1ced0ad5fbe5fdd85856e1e49320319687d31a6e4c7145479f45f43a9b8e9ffe4cbacfad4a21e5445e119df2996cce8b11d0f224efb4f18b544d456e2fb1d96fcd99fc319dbd86720621ac25b490f3611f7e5655bb3940a503c07dbf41f4b87593595a66008808744668371a54ce1b9dfdaa16f90415e57470bc23898d13d8351ba34369e96347da13d012b4eab32ada90668654c5ed2b433716b1b4170f640cf4b40659efcf4150237bbc25f72b248be85cd482b55ce2f5f73e8f02efd2465805b37d12487465ec1085bc6602b71862771af13e13baece4916b1ddef9ce016c92db9fb9e82aee5e1c4e22c45090ad1c19801ce1c541ff3902baea7a12dbcac6ec2d128ac7acb203463921ca6ce1d182d60d553ddecc4a3175eec2e924e9191e0d69aa49ca0b653495b8c62b802e443e669220f2a4047a56ed5cb7431a3387a435070795e6e63d242a74555e97371989c6d0040748e89ac316618d5d6eb7bff8d91e953afbe00464df4e4f6380c273b7ac5934cacb6c3be4da6649c8a5ea12bdf9afa1ec1e5053db7668c10ae2df75c4b3b14525369bf33741525a7630158aca3d3c7da5c1d71d3f63c0c2948a43236968d623c6c163eb757f0c78d6ae682ff4e4b673be07193e8d6c106c92851b393f0523491d5152e06de675fa22ae7bded329836a8ca0b955a59cb575395952c6ea0cb1644f2cada196b96b44ee12115ff9668e32886103d8f8109fac4a2287738ee1d2d4c1c19dab94eaa2757ea32016df60d7286099eb010ba570b5791ce4c54d860b15d56c53a5ddb543b0b602b3a87ca5213aa9647e51b1cb1736697506081240f4f7163a646f2be30e62c617d7572d820a113f96320834a2f43842160511923bd1ef4f723a2ab9b242fffe97cf0199c9f2ebca266a63beea0af279f2d18651b2ea9789d03025857c8aefc5f8bc6ee92ab7c6ffed2606f9c7ef25cb6c96140256a08cc58218869c52f3e5074fe5ace87a86057cc29fc845ff275f1b2dbc5991cbebe4c556b29ce3da3415958f0c9c68a5c664a1da60365ce56b9a4df24ec5d69c6f5a2e685885f6973c0ccd4caf7e000346bdea502b1418c8819e05bb7bee31bbd235819b49c892f7dadade576cb8ca68bda916a598c32ec03cceba2d01a7960f38680facccdaaf05e254dd8c3631a7222d1561c998c54b16f17a425f3247232dca035d545202e1b180340219ce31c66987bc86f983240e7fd2c926e8af77e6ea9f4139ff1edc0c323b67ceadead8f64a8004164d942f6aa65a28544d7205d41aafe62c5bfc6fd9fc322e2a8b620532d00d1add7a0d25a9dbaff90e19de14ac2ca97e83a2d77e63888ba0f7eaf9b18a7f2e5f148d16887580e55e894ae79024385f439acd071494e6469b77d07e763553652a470f3b4bd8bb7968052f3a969dacced51572bd125870849ce3e55359b2e17eabc3153b5f62868ea0ca1f40738488dbe0020c103f53678b9eb1c10000000000000000000000000000000000000000000000000000070a111518202731",
            );
            let sig = provider
                .sign(SignatureScheme::MLDSA87, &msg, &seed)
                .expect("deterministic sign must succeed");
            assert_eq!(
                sig, expected_sig,
                "ML-DSA-87 deterministic signature must match Wycheproof group 0 tcId 1"
            );
            // Cross-check: the produced signature verifies under the vector pk
            let pk = unhex(
                "17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff125469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d012d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa48ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c310d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbbe3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f6953865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56248e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b800d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e805",
            );
            provider
                .verify_signature(SignatureScheme::MLDSA87, &msg, &pk, &sig)
                .expect("produced signature must verify under the vector public key");
        }
        // group 26, tcId 85: DISTINCT seed and message (deterministic, empty ctx)
        {
            let seed = unhex("8c4cf531c6d42b744cec189408dfaccbd7b5c89a71c91e72777ceb718050e457");
            let msg = unhex(
                "481192b3aa7eb314dc46d6bf26b266c5d8c4699f675067c03b8dc5b568596f9cd4f249fba4d0bfc53cee3b03256c5194b3d4db2abd26ef58b39162811b299c12",
            );
            let expected_sig = unhex(
                "ba08f30ca148ad671268519ba421668dea0a714f4cab1b4284b79c78a918d9e8088feef74bcf0ecdf636cfd5a15e59c68c6c4dfefafabc523a35bad9e1f22673bd6493e78376c4f84ba9918cd2f508e658cdfb90c184727772475fcb7f748556ba7386c1321cafc5602c91990903cbe6a4ae0bdc15704c91a99e5e635c24c9263956e46c2c65f80b4f568f1e74da31ad8f1ba7b1b39b480908dde12520a4c712d4b0a0cb90f59fc18bbc9dcf78fca1044b0b7e8294800e7077ce631c43413f5d611a44aad0b718d89183a4a7a1861354afa8db1ad7a954ca67b5b6b4221a248e6501a8d2159d98597094b496ebf295419a8902b76a202a64f11c1e3dd8db6deff21a24a4d0b998d3e5bd7aa3c31997547797b5579371249181cf5f38b9d57e8b0fea5649ac25c46c5e4e0831c8df0b19b9bcec3b89f898e36cf60f5b7e031068782cfa395c645ba1fc8d1487620457c05b6f6e3ceae623de9b1d896938fb10abb9daeea88d96c0a540ce161ef5f4746f0e38e51de66c19a57148da3ee910571689d35b4a5ba9b113ad77af1f8b713fff7cc431b2a7182f4b99e214bf1e698f56e22c8434d67627067f2e9dbe9095da5afbaa8a513d97b875e9ba2a037eb0e3dce33b2ad877a5f37669f1d2d5b3bafa97555fd1c310559ab6ce32807f48b715853f22580051125cccd07726574bbb67210d9280e0ec2f58448b987016139138ee9e4ff26f9549e8ccc56d20204d1b08f4a58bf3f6892c17a6a8a8fbab6fa0e3cdc5fbac91428cf228d113db635969ab165aaf0afa436d537f1488c8a171455430a7915544070378f3f623c0214b39c49a5ae8ad286bd2d7c9edf430fff8c47afe491c28bb89fa9d64cc37766af38b9460e0b229f85ac63ecc6f13857caac435569ab6967641e211be07ba0c2132c3b3f39649a2c44948fe17efdf1ef3de5fa049fca5b5f34c995fcb33c65452a08516752c5f876158c9230a36663b7865ccd48ee1279a7437794c5c35f9a57f7935a87dcf64a344b9ee1e075cdacd93fc337768fcd6eaf4cd0a3ae3b3eff9b51a4b502ecb884860c35c1bb7cc7a492ef09e96477d8285cb378526fde11357ad51dc028d3c4eddf3dfbeab0d99f813370b1baf089b385b3a91719ae6c17dd4d8f26657992958b59d8f867fe917ff3cfd0afd155c2f776c2b8672cb004d3198fe28c55436978cc931aefffca615f99d498347b4e58c552f356d7c47b9eb0a64ea22aee36bae0ef8c4641856a7789220e00393421f1a48a111dd839967c5f20a9efaab68541da7e8445f4623eaddb2f583768413d6e4b2599292f4b556d729c7050079175920c66adc4593e7fc2937a77ebc21e7e1ff1854f9d30c78e1c940363668463c9a4da6bcc3c7c98c7ec6072ad04d453d65ef567ff1cd6d970c1166f427fce3f3930da15a9586cc0ff497bc7c6278e501e0c70ce7a984a617aa36062a0f2f7e3de8708d36739a7f4795c55dc5fa9c6452cb5274dab01f82014398a6e7f2895192f837828e9158402caccfde92635a64f99ca4476d1343d3a689bb7b32452d0e522567da1d9e4238fc92844d1353ef4681ddf6799fba45494b934a541c72a0fda1131c5ea54ed5dfd16a401d5e57f8e33ae835f467a237f2e0d1fe085e5c41178724aef3e2c8b4fc3befdb5e27930f01f935cf674f65decab6f112a0d75309ec839ab68ff603df92a9c485555a74669ec046c7507bda564af53837d58281f32d51a6a334f924ed358072ae3d8bf866b26c3f4e2cdb8976958f1abefc6c37ecf98032ac949785e4a51932461f98894c85f1fced01984d4ad4d14e820b320d48346498ea6cf91125bc48c3f496fc5e715dfaf79f75891de73b97391890caa546012a13545c2a14ed1b650ab0d99501d0b378d6c406f37f51e039ed2cf3fac3fa1d7c820f45b715cf9953599d54316af8b8732dd1ab1b69c986dc7acab96aaf1e8f83a8f0ae44850d1f6c3a9050ef7c3c1cc4b8661c14f7f25f5c7028a75593dba0959c1bb7b6445e988889b85aeebafcc6872adbb7cfb24b962c91543433fb57bef57bbe6ba03b4d09189b752cde2887d37bf5be0d335a3b9241355065c9a9faab224b8c3ab19e3141d22fca9ed0960c0308ec94a5b1652be1e44811d68c606df46489a6694ba0beaef5deba4512c828e07ab5d4757a24594fbf0aa4539a59ca06516dcb93636e24e241a5a919c3599a0cb64e6560a049f07f5096ede9fc335b52517e77d7bbafdd124bbcc6aeca923a9fc10c8f01be4c78237c8b82b7458044349d13dbc43f1b39b0eea9ac5e3dc35992cc6e6c97ccba15a653927635017016dede56c3b3488b4dfaa7cb43b5769a5603d641be73891f6f023fccaf49e35eb3f4bc61f99e9eec10980d5a6dcfbfe3e5f51b17467a32c71840208e06622d1b90544f7fe45009dc5722e97c3c7757c28bc96a2b31a17f14df227dedc90dbb93ba7285335880c0f5755d7e5ffb41bc5f6213b9161efe9e5353cea0fc7ff618c20fb97fbf09c33708b01f16805ef6cbfe227c0799b31269a405c929c7d0570533850cd4fefc54a8c97b9267a6a7bf5ffce965314f858f89bea1db6d9652095612c6b2282607392139ce55f98223c23f3a66c4ee104bf11e1d59fa28203426497cc3852f80be2cbc9481742a21491da7fff0215698688f522da0f284732fe2908c56d1bf67c3194714716225dc11bc24a0b242723778e6e0f68c66e51b7a7946c076cda93cb2178cc9b1c42a1fdbf7eb8a5d29d1d198439e22f3961e83eb4408c4a0d2d336f894ab3c4b68f37c1a161a667767ee64c2db53ae1feb44773b5f7448e905fa3a031b5436b0287970e62fb4f528601e63f603094f0f7f01e5026a7696b95839f9c405ac932f30abc52baded3cb06c66947e790190f010b5cd6b07c2e78aacf75bb511f81a52c75d2cc1ce8f0cc16a958025f995281865d3150ebf6fa686d9eadcb88902086bd196b16fb1286bc4e3a853d3d067007ca10ad19a8912c9a73f0303ad0f342cd8df70ed38f4b1f7b1725e2da6b78d9c7f9673c84746202f442c2ba230e481917ece4c8bcc5ffdff2f94bde5af09cdb6bc6583c3cd79c468da4636975235904f1d8d661fea5defdf8ca86bb0dc1a1e7943e9297111bde5d671f4a7f8644073465b2ab59aa19a644c5ea58dfd4991bae3a719ac2be9eaf11c8591eafbc75c467ea80a92bf612dc2207ef70db865414839b9b0d4c184ee21ba9c74f36d0a3387ab2e151badac98ae7cd8ae0350faaefe8c6d51677670a62f1e6a4ff0be51bba6201f567234d0136e0f1acb34e1fb3cf1431b7340a01f5d40519f97561f265403b82efdc752ea855d4571a35c8623cb08c5d821fd1049acaad59737bbadd584c265ebdd927c50644f0832568139a4fc3f04bbdee9cdb6bb296b7564325fcad03a193d018c0bd576e6975d737bb3cddfbc29daa522fb1df6f1507150d3f80abf3728ca3babecf5ee2d1e21353956553c9e5a589485a7ba0da40b4c73b256685a5d6c18cec52514c9b3c994576295d51cf693124528a17e965368f56acabe049497cfb5cf70e17e152d6a670c8607d1e295c3d822df6a88c1ad835730d059aff49f8d897d0beeb71caad24c7aa4fb99e00ad74dc4e98818271db2e943162529049881fdafdd3ff16132205196e4d2abc40033b47b3cc22d61114d72166dfb24677ceaf079a35093e39b7f89f0a68cb0af1ce091ce3fe543904195c71f8f0ab21e843e86f081878b0452a646b0e4f45b977b7b32b617964812b631f15cd48b9360c400ea12e1936f53822a481dc191797c3043e51e107e7fbc1860032ae5bb927f245412217789c922fb57aa69dd6906b0e55b741f029962562129d2260f6a3a059692b9ffe93b2470d413a4b26c76e355e5c818666091ba985d671397ce49aa527b2065650a4f7b0a2662a7b5ab2d5d37adb897cff54fef03edce73685d9f6c3d3fd5c1ca5fefe4f8fbc7bb49301ae13cd17f7c26a2876e80a6472c0fa668f6de651f02a7090834be2cc7ed4cb0a1636335e011fde12db4cf9e1878a863bfb7e82282c59c0b3a1c2f7380f1bb9a84512c1c2edab8a3434f958c0612dc755301c45095317e7533693e82ad511a4da4e7bb7c9e3cbc1af77d0fdd93b5916128283b8fddfae6f4cc21820ce2e4c739698ed6c0459426271bca02390012efad0ff2db19396e4efd14563cd3fb432d14b162d2c809e3b4f3244eebe5d64248a5f8d8cc0bd6235946af15b2362d52be4a5fc6b23dc55357352aa106c893a83ec6cba4d9e453a9e86de17397b96fb3f81db4aed877a7efe1eb833dc335f0c6d866b5297f74dba1f216c9070f5c3e186482fdae80cacff97e7f3658d54d2d5a2727cc7e450df8d65fee834283480b64c6034d1e2490ba2a927d437717c8cc9f31804e197f8fcfd7274810ea3dd60f707ab9ed53671c56b178fc0ccc1ff88945574a72d2a00753733d0e455a31948f5f11e436e219c48494b9c0e65d667e4c05c6cd9c6c8f3268fb668622f5fa9a4626b5d5c17deb7b823e628c760b081de07534304bc24bcb49a3650e90d357e5f5831ba2bb4a23632564d7f1859bbe2edaadc860373c7833b5767cc6e597866d70dc4f7939e6277857986979af0ac0640c1a09a09806415c2927bd2ebee8085fdfedd93197db0a1f4e1b6732ef84a214a78333dc40557627019f9890a9fafb7386386ba857c9aa06bf8497fac8de676ba62ca1906c6dcdb5733c1668b40055f6d835b0f98e2efb54c18e51902d28835d81d6000041f297df2f8da8c21de3bd1d2a6f4afdd3cd0bac2893873ed97b17e2660a6ecba83e3d9b3cbe78e12aa5425fdce00e061059ac4ad3639592311c7db15e4801231661b3fce69a5d39f92fb5c66debb26e939d8b1974a9c45796bc1cbb885ad6f7c0e2b6f2b3f0565b2c9edf966dcc4106ce1e1b3a3967e17e81fcff0ac0f1768249768838105c90834b3e8db93577f54c7e3e1254f03356bc9b0e107d4ab62d023579e80c15c1dec72a7de127d499506bde6d02651288e680135eadb1efe77719c963cf14414076c8a9c30888db446c10745cf6868c619519761f3ecbdf6e089f43b9662b882748be5d9e83729a43068ef39ebad5d8701be44e390a375b2f8ca8bd3cfeb2595b5f5a0567c8ec715db577c7b31cb7ac90f6d3b76165be298f27659a9a1c0082ee10b960ff9f5abe0972637960508418c9c50d43ce2980728312731344ec25e51570e27f6b545b585706dcae1f9c384cbf1c42b2639cfbaec0dfd3ccccb99be9667770476c8b5bc1877a63a313fc2d16d3e200e99411f228da0b58092d592db52599ca63c996a3172a0e222c5f8d53c4d13d4e20dc4418d2d85c9a780a53a8737d98c0bafbfe27d48287d44dc0e3d1d0fff0d304fd11f457c2cccfa9e6c5094dcc366926358ce8e2e2dd5a5fafda380733fbf8fbf9624a75adc395d36e5be3102f31afcd57b9843da4663f10eba2e2fac7d3918348bb3a6ce4121c3644c507079b9d513e74c5358a109c0d81f3100f29af015d6f7f509af8bf1c57fc255c0215430b6021f3b1439a41a0c11b7a8897fd2756f7481fb69aa2b1c5ab30a11491ef14e30173f38dfad7ae2f135d66fb1c4b2e94db9f105b2a5e8598739dcd7ca079b6ef8ef8dd11320dec6a04ea81d763bd01773e5230883a9e04df428b4023a95a972155ce722145400166631dab378dd57556c27ca09ea585c20b5180ae0cb3dea4b5a3a300e1c909eeabbb36785b3f453df6e87ea3d72478dfbc9fe44c4d22b876b06ac13566feaff1b4445ee0ffcf80f8a85f5991a44fc058b12dc96acd62cb41899d3b3e485f2346218a49c016074dd926be86fb06bd41c5d887f694b1efedabfb93485ae722bc2b24b486339bd60946858189a93013fa0855fce5fbc8b2a8314c9e1cff8010775ff10714f788b9eb48fe1848f3affd7d0c9f3011cbedfc31f56e72fa9a3aa51d89898bc62cafa6efbdb4c2a09774d04d72b7e824ba5e534b91c1e4142250b2c384f4a6b3a499da82558e38b40c21e59130c78055f169ded782f308d31669e7d4ebfc9b8fd6fcf99f95b390a612215350d53e2b461452201c33eddd58819237e59977fa29284907c8e2418f773bb48c343e80cbcf734dfc78609ed086c34da7409c037246c3c374df5a478dbcc15b103e7e093ddb0cc43b12bf66e2b74c1a8158633972defa5dcc2c69110a5fb9bcda80038ea2026cc115ccbf0114d036addbb777d69994f5a5acce9a239b1ea4977e41c165c794fa071d9a87baeeef9992aa412903e3011742ed11684402ca814b33816430957f8117e6590b4ef34a720c451e1d44e29e452988b4da9b9f3e929a0b212ad4a0d8d8bd066d713cccd8dc19d78f210125a5156243fadfb93323d3a2abb17e4e5e46bd766e18885f85034357d63af2cc9dbc2c67a8cddae83961686dcfeb071f5861686d78a6adb616708949596276c1c3c8cee2fc42518dc8f1031736558c8e98d1333c4c638197c50000000000000000000000000000000000000000060c161923283037",
            );
            let sig = provider
                .sign(SignatureScheme::MLDSA87, &msg, &seed)
                .expect("deterministic sign must succeed");
            assert_eq!(
                sig, expected_sig,
                "ML-DSA-87 deterministic signature must match Wycheproof group 26 tcId 85"
            );
            // Cross-check: the produced signature verifies under the vector pk
            let pk = unhex(
                "d49ddc3da4a587a55461f3f4e011c91c780af18aa8b2ffb29a2ce0865caa86e0d94254183e4c961ab4c718cf7dcae2746c813ecbf87bc49050d5e8d3bc8ba83eb09665d7bba9ab9c825e6e8df8c36de9bfbd30c9ca4785ae6f5d094dd7dd0551e09e943b1dfa3057dc5848e545f3348a73668ae0623d0dfb135225f5d394159dac6a748a64915ba3e2d05cd2ee52c00c6c813494fb87f66b0f7e99a7afb374a7b664d736393f7d0ec376b33ac9946fc0aa922af1388c62a19abe8d32ec05b98db0db378d61fa79551df2c319153b26efe5f329a1136068d32257cd99e62254df02e4d5d266ce5a90137e7cad4c4cb69365da4bb6130e1b36aa2cbd60579835a9e9adc58e334700e9f21be75ad0553b0e77097e1f110bf0e40727e772e9509c9c84b05ce01379fa3f8096e204de355fa44e8a127aba5320363df063b614abce6b24fdc9d252d9c040dfddd5c2a0f5744617dcf58168bd1a0133d02fdc3a434a0807989f755d70151d587f263028e1176d140f014a883bf5701d97d5da18a8b3a40e043fe850f48765755a5d2f94637ad006cefbeb4165c9553854d3c4ac2446062a87b10f06d81ea735c4a3dc608083e7f074f6d6a71d50ffba82c0ca726bda4acb3be8a3aa3286c094752b2f44ad5b8dabc20355b17e670739338367ecbf52ad55373ea141eda091bf281b0432bff1b00a11999877ee14131513ad1fb66bcd3bb8759a559b0c6cf77c2106b7f0434196c1734453d8183e094ec25fa0d518db9ff4a0f84da7727e85bbb7cc7b51b0f15e03cde85b833f95e20ba1c76f7498cd95f4d4b840ff7554833a2c643810cb6dadf991cbcfbef6f79415eaaf37657cd2ff9979f89527750960a46f060f6c13dd3279a740a5dd2c22c1eec33159b13da17769b5d6aed786aba4df9f36b4b2e688d6459b8b87bd27e955d5ace93380001d002174e20a5bd237ab6f485e14763a84f93403748d6cd8d40fc7c80cb51812a55a764b5d1e75893a0160f11e5b98717a1579ff3d375ec956a543e7d02b63fb2f1a553715027f9a84f007452ba09ab4604d48d5ee64f9e74b1cb905d1d1474fca2632ad7b2e7e5405961229bcd3454e05836d3038d03c46cdb621b65c2a407a2e97d7bfa6552aa62854c466bef6eac119cbcc5207cd903f092377f7c603cc8b18ac636d2a0182ad201182f3fe2d533f18b5bcf70ca7ca63fa778a3cc1c4b0154b08ddb3d233c8c2aa1ae49b1b1878076c08283fc6b7468f8ec6ffb12d63127ce5d8a5f86476f71bbc41adeee86fd413ea5972fa04b46e523aff60a0d8df411a4ec8802d2913d3d05520b5334f02d2eaca9499df3cfde52b450485fe87425311622fcf0535296aa537809b4a443c6de1d3886ae76f45fc9933e418621936376fe937bb86a207ecbc330d0a183013cf36312fd2f67ea8a49571c8401f34f195de3ee1b7ef261e2078f89a24bc7f64304263778996f89b6051b3027a6419d31398cdb61e68829b23443ea857f54dd8ea93844e5618b79402fa6e8ea075d2b4bb506f3f58e228b687d6c5e076a6c65bed6b48d425d35f64abe35aae69e806ffef670b49e4e831ee1a35860c818a1f7f062066818bfbdc99787b438435a74f27b5c944bf0559ce4ce5aa1837325b4162890aec0aae67cf0beff63a3b131df88b205f2c5575ecf49d2d0d0db78871f7c6f8651abadbdc53d280927214ce68b8f4784b92ee15fcd4e0894982f87fcef6ce86faa5d93afbefa8d93b6eb5e229316f5fa7345849079c4d7446b6d50c3c264bee379c92a237953571ee46ddefd0f2d4efe0db28f45d12e0854a3c5b2fd89c9acf6f01e71b2e415d5dddddb66db37dbc3350c5af1bee33c44246cae200e9c9ec9e9b67ba393cc5a17dac9ebe6792205b3685deddd3ec4e82034a446eee9cd0139e986f77d8feb7540115cdd331f5d7742d4d4f18d28f80b64680a7a88cf2644f408a64962c1ed23ce950c486d919937aba953535e34d83da150987b81a546f61dd5501e1391cb2ac8c15827ca66954642f5c0c79af85712dffc0f240bb053131008d0c401188f2919f7a8e998272d84508835c2b7346d6549a3d424867192b19ae0c1608a4ec7e15ad4fa9bd4f09f0c29fb5b7ff96f9f9c65d5707e8f27c95a08a158b3484b5287af504b8cb5e774ddd148da6e24544fdd09c4110fce5dd2cda6bfef9ff65e76640690c0999af02d08555cc0d59aab6379b58fab5c5cdd51cf99f314c8a78ca1e22dc3364ce566d57e9bde0dd23229c705ae74608c5a685345f9c96bbbeb42fbb47dc38adb792080d93f47fe664a5b39edddb998eca824f77f7ff92d348e0807114616b771b58bdb6b6e5b0a816e74cc25e40bc9f777698f700d1df3c2e164fe791ecebfba19f666defaf36d8b6407e2f513b75561d33ee4bcf98b39f4ffffd2ab94e4be03960d57caa287e7e27d809856dfa578aee84be48f962788a4d2a802f6fc9a7b556bb58c2b9d0fe8d68862b7bf00157ffaf88ad53f963fef45a97b78f920f9063cffe08bc8c5a9cac8b0a941725ae87a71d3f28fe453e48ef194abec6d564e1f2f5d23a03e050317edfd515c6b6b21e446a0f67f23469b9d251eb86ab7e6068e4c24b8ba2c678b261a1e5b633473ffade5b6b958951bbd38a001dadfc7a47c8a069a6a33fa9dbd8e40d2cba262ca682625a1e9fa8249de5c7cf6d2f68e1c004adde005b57352b9a9be590318a5beae5f67302c133afe7616c048c08b2fba21851391a612c8c7d11b82e38b7e0de5e6fc5f43172cbd6ecbce9362e2b63eaa1abf811e731ade4cb23e46454504f158b58a4a135ea733ec33e318180536a2cfed7d88fe7502d996932fa4eb4f98918be5a957a0f34c5d928ff933a1322e6db5cfe5105afa3cd1701d1847623ff91c46bc7a877e0da45efd713e3027c747e66bb9f483556a80841f7a7e360a6ce73df7399c6bd7bb4de31e635af3e93d269b5b9be9ff40dd882c14ff6f3231ce7ffacb279e3626ab78508da4a3f22622bcdb759f582ef087fb5a06cba61458ff4a26683726534346899f599c9526ac27fde25a37bcea3de6d629884e42ae11ca90b7e45d3784085619dcecdfd7b66925fb93704eaec3732becd3e5e37cde3819269dfa1b98c4443aecde5d54eb92f1ebcf2d18893de6a8a43a16bdc5bd2dde8ca0a95459fd88cfde0c3bd0ea0bd72a7779a79d915ad5013a741c7d1ec2f451402b78e5176d42f1cea9c6d351ca7ebd779e435bc02a6d058cbdfea9016533cc5da364f614a1bfa15520d3d73c5fe2aa24a6e9599fcbfb2fc22be45105ac538a0c1ba466d8ebe0b5ff66fbb4d22f5954d12c26f8dde86af3f082456a3cdfceba13c226645038b04128034f9f464bfb93dd734e4c88e86c973217f3001c8d2918dc4cad559acd7b4fb98fbc4488293c6588b0cdf3f075a9489c6be1a19638ba80c20ae9a1bd345a0d98cbb67a054869b7ba8166fa459451e34b5a71b3fdac68019dcc2eeebd996dc4fec02de34435a37c8df3b5382faf88a32971ef60e7d39e0db0b22a4d05613bce9389276ff2bc2a0987d8c588e7f6d8006ffc7b3b71bacc468611115b7ee8d66349f180388d104d086c0ca2ae11b4718c997ed1f99c6a9203ff64396308ba5cb2ec5db26c0f648073a283e35385080df80fa12928355de31",
            );
            provider
                .verify_signature(SignatureScheme::MLDSA87, &msg, &pk, &sig)
                .expect("produced signature must verify under the vector public key");
        }
    }

    #[test]
    fn wycheproof_mldsa87_keygen_seed_to_pk_matches() {
        // Belt and braces: check the FIPS-204 seed(xi) -> public-key mapping the
        // provider leans on, via the same SigningKey::from_seed call its
        // keygen/sign path uses
        // group 0
        {
            let seed = unhex("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
            let expected_pk = unhex(
                "17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff125469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d012d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa48ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c310d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbbe3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f6953865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56248e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b800d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e805",
            );
            let seed = B32::try_from(seed.as_slice()).expect("32-byte seed");
            let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);
            let pk = signing_key.expanded_key().verifying_key().encode().to_vec();
            assert_eq!(pk, expected_pk, "ML-DSA-87 seed->pk must match Wycheproof group 0");
        }
        // group 26 (distinct seed)
        {
            let seed = unhex("8c4cf531c6d42b744cec189408dfaccbd7b5c89a71c91e72777ceb718050e457");
            let expected_pk = unhex(
                "d49ddc3da4a587a55461f3f4e011c91c780af18aa8b2ffb29a2ce0865caa86e0d94254183e4c961ab4c718cf7dcae2746c813ecbf87bc49050d5e8d3bc8ba83eb09665d7bba9ab9c825e6e8df8c36de9bfbd30c9ca4785ae6f5d094dd7dd0551e09e943b1dfa3057dc5848e545f3348a73668ae0623d0dfb135225f5d394159dac6a748a64915ba3e2d05cd2ee52c00c6c813494fb87f66b0f7e99a7afb374a7b664d736393f7d0ec376b33ac9946fc0aa922af1388c62a19abe8d32ec05b98db0db378d61fa79551df2c319153b26efe5f329a1136068d32257cd99e62254df02e4d5d266ce5a90137e7cad4c4cb69365da4bb6130e1b36aa2cbd60579835a9e9adc58e334700e9f21be75ad0553b0e77097e1f110bf0e40727e772e9509c9c84b05ce01379fa3f8096e204de355fa44e8a127aba5320363df063b614abce6b24fdc9d252d9c040dfddd5c2a0f5744617dcf58168bd1a0133d02fdc3a434a0807989f755d70151d587f263028e1176d140f014a883bf5701d97d5da18a8b3a40e043fe850f48765755a5d2f94637ad006cefbeb4165c9553854d3c4ac2446062a87b10f06d81ea735c4a3dc608083e7f074f6d6a71d50ffba82c0ca726bda4acb3be8a3aa3286c094752b2f44ad5b8dabc20355b17e670739338367ecbf52ad55373ea141eda091bf281b0432bff1b00a11999877ee14131513ad1fb66bcd3bb8759a559b0c6cf77c2106b7f0434196c1734453d8183e094ec25fa0d518db9ff4a0f84da7727e85bbb7cc7b51b0f15e03cde85b833f95e20ba1c76f7498cd95f4d4b840ff7554833a2c643810cb6dadf991cbcfbef6f79415eaaf37657cd2ff9979f89527750960a46f060f6c13dd3279a740a5dd2c22c1eec33159b13da17769b5d6aed786aba4df9f36b4b2e688d6459b8b87bd27e955d5ace93380001d002174e20a5bd237ab6f485e14763a84f93403748d6cd8d40fc7c80cb51812a55a764b5d1e75893a0160f11e5b98717a1579ff3d375ec956a543e7d02b63fb2f1a553715027f9a84f007452ba09ab4604d48d5ee64f9e74b1cb905d1d1474fca2632ad7b2e7e5405961229bcd3454e05836d3038d03c46cdb621b65c2a407a2e97d7bfa6552aa62854c466bef6eac119cbcc5207cd903f092377f7c603cc8b18ac636d2a0182ad201182f3fe2d533f18b5bcf70ca7ca63fa778a3cc1c4b0154b08ddb3d233c8c2aa1ae49b1b1878076c08283fc6b7468f8ec6ffb12d63127ce5d8a5f86476f71bbc41adeee86fd413ea5972fa04b46e523aff60a0d8df411a4ec8802d2913d3d05520b5334f02d2eaca9499df3cfde52b450485fe87425311622fcf0535296aa537809b4a443c6de1d3886ae76f45fc9933e418621936376fe937bb86a207ecbc330d0a183013cf36312fd2f67ea8a49571c8401f34f195de3ee1b7ef261e2078f89a24bc7f64304263778996f89b6051b3027a6419d31398cdb61e68829b23443ea857f54dd8ea93844e5618b79402fa6e8ea075d2b4bb506f3f58e228b687d6c5e076a6c65bed6b48d425d35f64abe35aae69e806ffef670b49e4e831ee1a35860c818a1f7f062066818bfbdc99787b438435a74f27b5c944bf0559ce4ce5aa1837325b4162890aec0aae67cf0beff63a3b131df88b205f2c5575ecf49d2d0d0db78871f7c6f8651abadbdc53d280927214ce68b8f4784b92ee15fcd4e0894982f87fcef6ce86faa5d93afbefa8d93b6eb5e229316f5fa7345849079c4d7446b6d50c3c264bee379c92a237953571ee46ddefd0f2d4efe0db28f45d12e0854a3c5b2fd89c9acf6f01e71b2e415d5dddddb66db37dbc3350c5af1bee33c44246cae200e9c9ec9e9b67ba393cc5a17dac9ebe6792205b3685deddd3ec4e82034a446eee9cd0139e986f77d8feb7540115cdd331f5d7742d4d4f18d28f80b64680a7a88cf2644f408a64962c1ed23ce950c486d919937aba953535e34d83da150987b81a546f61dd5501e1391cb2ac8c15827ca66954642f5c0c79af85712dffc0f240bb053131008d0c401188f2919f7a8e998272d84508835c2b7346d6549a3d424867192b19ae0c1608a4ec7e15ad4fa9bd4f09f0c29fb5b7ff96f9f9c65d5707e8f27c95a08a158b3484b5287af504b8cb5e774ddd148da6e24544fdd09c4110fce5dd2cda6bfef9ff65e76640690c0999af02d08555cc0d59aab6379b58fab5c5cdd51cf99f314c8a78ca1e22dc3364ce566d57e9bde0dd23229c705ae74608c5a685345f9c96bbbeb42fbb47dc38adb792080d93f47fe664a5b39edddb998eca824f77f7ff92d348e0807114616b771b58bdb6b6e5b0a816e74cc25e40bc9f777698f700d1df3c2e164fe791ecebfba19f666defaf36d8b6407e2f513b75561d33ee4bcf98b39f4ffffd2ab94e4be03960d57caa287e7e27d809856dfa578aee84be48f962788a4d2a802f6fc9a7b556bb58c2b9d0fe8d68862b7bf00157ffaf88ad53f963fef45a97b78f920f9063cffe08bc8c5a9cac8b0a941725ae87a71d3f28fe453e48ef194abec6d564e1f2f5d23a03e050317edfd515c6b6b21e446a0f67f23469b9d251eb86ab7e6068e4c24b8ba2c678b261a1e5b633473ffade5b6b958951bbd38a001dadfc7a47c8a069a6a33fa9dbd8e40d2cba262ca682625a1e9fa8249de5c7cf6d2f68e1c004adde005b57352b9a9be590318a5beae5f67302c133afe7616c048c08b2fba21851391a612c8c7d11b82e38b7e0de5e6fc5f43172cbd6ecbce9362e2b63eaa1abf811e731ade4cb23e46454504f158b58a4a135ea733ec33e318180536a2cfed7d88fe7502d996932fa4eb4f98918be5a957a0f34c5d928ff933a1322e6db5cfe5105afa3cd1701d1847623ff91c46bc7a877e0da45efd713e3027c747e66bb9f483556a80841f7a7e360a6ce73df7399c6bd7bb4de31e635af3e93d269b5b9be9ff40dd882c14ff6f3231ce7ffacb279e3626ab78508da4a3f22622bcdb759f582ef087fb5a06cba61458ff4a26683726534346899f599c9526ac27fde25a37bcea3de6d629884e42ae11ca90b7e45d3784085619dcecdfd7b66925fb93704eaec3732becd3e5e37cde3819269dfa1b98c4443aecde5d54eb92f1ebcf2d18893de6a8a43a16bdc5bd2dde8ca0a95459fd88cfde0c3bd0ea0bd72a7779a79d915ad5013a741c7d1ec2f451402b78e5176d42f1cea9c6d351ca7ebd779e435bc02a6d058cbdfea9016533cc5da364f614a1bfa15520d3d73c5fe2aa24a6e9599fcbfb2fc22be45105ac538a0c1ba466d8ebe0b5ff66fbb4d22f5954d12c26f8dde86af3f082456a3cdfceba13c226645038b04128034f9f464bfb93dd734e4c88e86c973217f3001c8d2918dc4cad559acd7b4fb98fbc4488293c6588b0cdf3f075a9489c6be1a19638ba80c20ae9a1bd345a0d98cbb67a054869b7ba8166fa459451e34b5a71b3fdac68019dcc2eeebd996dc4fec02de34435a37c8df3b5382faf88a32971ef60e7d39e0db0b22a4d05613bce9389276ff2bc2a0987d8c588e7f6d8006ffc7b3b71bacc468611115b7ee8d66349f180388d104d086c0ca2ae11b4718c997ed1f99c6a9203ff64396308ba5cb2ec5db26c0f648073a283e35385080df80fa12928355de31",
            );
            let seed = B32::try_from(seed.as_slice()).expect("32-byte seed");
            let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);
            let pk = signing_key.expanded_key().verifying_key().encode().to_vec();
            assert_eq!(pk, expected_pk, "ML-DSA-87 seed->pk must match Wycheproof group 26");
        }
    }
}

// PQ HPKE provider tests
//
// Checks that the provider hooked the PQ KEMs and the SHAKE256 KDF into its HPKE
// arms correctly. For each of the 7 supported PQ HpkeConfigs:
//   (a) derive_hpke_keypair -> hpke_seal -> hpke_open round-trips, and
//   (b) setup_sender / setup_receiver agree on the exported secret.
//
// Ideally these would be KATs, but nobody publishes HPKE vectors for these KEMs
// with KdfShake256 (rust-hpke's kat_tests.rs only covers the boring RFC 9180
// suites), so round-trip correctness is the best we can do here. The real
// byte-for-byte KATs live down in the KEM crate.
#[cfg(test)]
mod pq_hpke_tests {
    use super::*;
    use openmls_traits::{
        crypto::OpenMlsCrypto,
        types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType},
    };

    // All 7 PQ HpkeConfigs that must be wired (stored as tuples since
    // HpkeConfig doesn't derive Copy/Clone; each field type is Copy)
    fn pq_configs() -> Vec<(HpkeKemType, HpkeKdfType, HpkeAeadType)> {
        vec![
            (
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ),
            (
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ),
            (
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem768,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem1024,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ),
        ]
    }

    /// Expected serialised key sizes for each PQ KEM, indexed by HpkeKemType.
    /// Values are (private_key_bytes, public_key_bytes) as defined by each KEM's
    /// Serializable impl in rust-hpke:
    ///   XWing  (MlKem768X25519):  sk=32,  pk=1216
    ///   MlKem768P256:             sk=32,  pk=1249
    ///   MlKem1024P384:            sk=32,  pk=1665
    ///   MlKem768:                 sk=64,  pk=1184
    ///   MlKem1024:                sk=64,  pk=1568
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

    /// For each PQ HpkeConfig: derive a keypair, seal a message, open it, and
    /// assert the recovered plaintext matches the original. Also checks the derived
    /// keypair comes out at the wire sizes each KEM is supposed to produce.
    #[test]
    fn pq_hpke_seal_open_round_trip() {
        let provider = RustCrypto::default();
        let plaintext = b"pq-hpke round-trip test";
        let info = b"test-info";
        let aad = b"test-aad";

        for (kem, kdf, aead) in pq_configs() {
            // 64 bytes of IKM, plenty for any of the PQ KEMs
            let ikm = vec![0x42u8; 64];
            let kp = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
                .unwrap_or_else(|e| {
                    panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            // The derived keypair should match the sizes the KEM spec promises
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

    /// A1(a): for each PQ HpkeConfig, flipping one byte in the AEAD ciphertext
    /// must cause hpke_open to return Err (fail-closed AEAD authentication check)
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

            // Flip the first byte of the AEAD ciphertext portion
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

    /// A1(b): for each PQ HpkeConfig, attempting to open with a DIFFERENT
    /// recipient private key must return Err (fail-closed KEM decap rejection)
    #[test]
    fn pq_hpke_open_rejects_wrong_private_key() {
        let provider = RustCrypto::default();
        let plaintext = b"pq-hpke wrong-key test";
        let info = b"test-info";
        let aad = b"test-aad";

        for (kem, kdf, aead) in pq_configs() {
            // Derive the intended recipient keypair
            let ikm_a = vec![0x42u8; 64];
            let kp_a = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm_a)
                .unwrap_or_else(|e| {
                    panic!("derive_hpke_keypair (A) failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            // Seal to the intended recipient's public key
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

            // Derive a DIFFERENT recipient keypair (different IKM -> different key)
            let ikm_b = vec![0x99u8; 64];
            let kp_b = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm_b)
                .unwrap_or_else(|e| {
                    panic!("derive_hpke_keypair (B) failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            // Opening with the wrong private key must fail
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

    /// A1(c): for each PQ HpkeConfig, corrupting the encapsulated KEM output
    /// (kem_output / enc) must cause hpke_open to return Err
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

            // Flip the first byte of the encapsulated KEM output
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

    /// For each PQ HpkeConfig: setup_sender_and_export and
    /// setup_receiver_and_export must agree on the exported secret
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

    /// Regression test for the hpke 0.14 migration RNG bug: HPKE sender
    /// operations must use the provider's seeded RNG, not the OS RNG. Two
    /// providers built from the SAME seed must produce byte-identical
    /// HpkeCiphertexts for the same seal inputs. With the getrandom regression
    /// the per-seal ephemeral encapsulation is random and these differ; with the
    /// seeded RNG threaded through they are deterministic and identical.
    ///
    /// Covers one classical suite (DhKem25519) and one PQ suite (MlKem768X25519).
    #[test]
    fn hpke_seal_is_deterministic_under_seeded_rng() {
        let seed = EntropySeed::from_raw([0x5Au8; EntropySeed::EXPECTED_LEN]);

        let info = b"determinism-info";
        let aad = b"determinism-aad";
        let plaintext = b"determinism plaintext payload";

        // Classical + PQ config; derive recipient deterministically from a fixed
        // ikm so both providers seal to the same recipient public key
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
                    HpkeKdfType::Shake256,
                    HpkeAeadType::AesGcm256,
                ),
                vec![0x22u8; 64],
            ),
        ];

        for (config, ikm) in cases {
            let HpkeConfig(kem, kdf, aead) = config;

            // Recipient keypair is derived from ikm (no RNG), identical for both
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

            // Sanity: the deterministic ciphertext must still open correctly
            let recovered = provider_a
                .hpke_open(HpkeConfig(kem, kdf, aead), &ct_a, &recip.private, info, aad)
                .unwrap_or_else(|e| panic!("hpke_open failed for {kem:?}: {e:?}"));
            assert_eq!(recovered, plaintext, "round-trip mismatch for {kem:?}");
        }
    }

    /// The 9 official SHAKE256 PQ suites now run end to end (draft-ietf-mls-pq-ciphersuites
    /// "One shot KDFs in MLS", PR #21). They must be reported as supported.
    #[test]
    fn pq_shake256_suites_supported() {
        use openmls_traits::crypto::OpenMlsCrypto;
        let provider = RustCrypto::default();
        let official = [
            Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        ];
        let listed = provider.supported_ciphersuites();
        for cs in official {
            assert!(provider.supports(cs).is_ok(), "{cs:?} must be supported");
            assert!(listed.contains(&cs), "{cs:?} must be listed in supported_ciphersuites()");
        }
    }
}

#[cfg(test)]
mod shake_kdf_tests {
    use super::*;

    #[test]
    fn shake256_kdf_derive_matches_fips202_empty_vector() {
        use openmls_traits::crypto::OpenMlsCrypto;
        let provider = RustCrypto::default();
        // FIPS-202 SHAKE256("") first 32 bytes (distinguishes SHAKE256 from SHAKE128)
        let expected =
            hex::decode("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f").unwrap();
        let out = provider.shake256_kdf_derive(b"", 32).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
        // XOF is variable length: a longer read is a prefix-extension, not a re-hash
        let out64 = provider.shake256_kdf_derive(b"", 64).unwrap();
        assert_eq!(&out64.as_slice()[..32], expected.as_slice());
    }
}
