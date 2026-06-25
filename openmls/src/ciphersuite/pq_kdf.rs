//! SHAKE256 one-shot KDF for the official PQ MLS key schedule.
//!
//! draft-ietf-mls-pq-ciphersuites, "One shot KDFs in MLS" (PR #21, branch
//! `oneshot-kdf` - PROVISIONAL, unmerged, under WGLC):
//!
//!   Extract(secret, salt)         = Derive(concat(salt, secret), Nh)
//!   Expand(secret, label, length) = Derive(concat(label, secret), length)
//!
//! `Derive = SHAKE256(M, d = 8*L)` (draft-ietf-hpke-pq-04 section 5); SHAKE256 `Nh = 64`.
//! This module is the single home of that construction across both providers.

use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};
use tls_codec::SecretVLBytes;
use zeroize::Zeroizing;

/// SHAKE256 KDF.Nh - the Extract output length (draft-ietf-hpke-pq-04 section 5, Table 1)
const SHAKE256_NH: usize = 64;

/// TODO(PR#21): WGLC review proposed prefixing BOTH concats with this domain
/// separator ("MLS 1.0 expand") so Extract and Expand cannot collide. It is NOT
/// adopted upstream and NOT applied here. If the WG merges it, set this to the
/// label bytes; both ops below prepend it automatically. Keep empty until then.
const SHAKE_KDF_DOMAIN_SEP: &[u8] = b"";

/// Extract(secret=ikm, salt) = Derive(SHAKE_KDF_DOMAIN_SEP || salt || ikm, Nh)
pub(crate) fn shake256_extract(
    crypto: &impl OpenMlsCrypto,
    salt: &[u8],
    ikm: &[u8],
) -> Result<SecretVLBytes, CryptoError> {
    let mut input =
        Zeroizing::new(Vec::with_capacity(SHAKE_KDF_DOMAIN_SEP.len() + salt.len() + ikm.len()));
    input.extend_from_slice(SHAKE_KDF_DOMAIN_SEP);
    input.extend_from_slice(salt);
    input.extend_from_slice(ikm);
    crypto.shake256_kdf_derive(&input, SHAKE256_NH)
}

/// Expand(secret=prk, label=info, length) = Derive(SHAKE_KDF_DOMAIN_SEP || info || prk, length)
pub(crate) fn shake256_expand(
    crypto: &impl OpenMlsCrypto,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> Result<SecretVLBytes, CryptoError> {
    let mut input =
        Zeroizing::new(Vec::with_capacity(SHAKE_KDF_DOMAIN_SEP.len() + info.len() + prk.len()));
    input.extend_from_slice(SHAKE_KDF_DOMAIN_SEP);
    input.extend_from_slice(info);
    input.extend_from_slice(prk);
    crypto.shake256_kdf_derive(&input, length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::OpenMlsCryptoProvider;

    #[test]
    fn extract_is_derive_of_salt_then_ikm_to_nh() {
        let backend = OpenMlsRustCrypto::default();
        let crypto = backend.crypto();
        let salt = b"salt-bytes";
        let ikm = b"ikm-bytes";
        // Extract(secret=ikm, salt) = Derive(salt || ikm, Nh=64)
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(salt);
        expected_input.extend_from_slice(ikm);
        let expected = crypto.shake256_kdf_derive(&expected_input, SHAKE256_NH).unwrap();
        let got = shake256_extract(crypto, salt, ikm).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice());
        assert_eq!(got.as_slice().len(), 64, "SHAKE256 Nh");
    }

    #[test]
    fn expand_is_derive_of_info_then_prk_to_length() {
        let backend = OpenMlsRustCrypto::default();
        let crypto = backend.crypto();
        let prk = b"prk-bytes";
        let info = b"info-bytes";
        // Expand(secret=prk, label=info, length) = Derive(info || prk, length)
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(info);
        expected_input.extend_from_slice(prk);
        let expected = crypto.shake256_kdf_derive(&expected_input, 48).unwrap();
        let got = shake256_expand(crypto, prk, info, 48).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice());
        assert_eq!(got.as_slice().len(), 48);
    }

    #[test]
    fn concat_order_matters_extract_ne_swapped() {
        // Guards against silently swapping salt/ikm: order is normative
        let backend = OpenMlsRustCrypto::default();
        let crypto = backend.crypto();
        let a = shake256_extract(crypto, b"AAAA", b"BBBB").unwrap();
        let b = shake256_extract(crypto, b"BBBB", b"AAAA").unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn no_domain_sep_prefix_applied_yet() {
        // PR#21 domain-sep label is NOT adopted: input must be exactly salt||ikm
        let backend = OpenMlsRustCrypto::default();
        let crypto = backend.crypto();
        let got = shake256_extract(crypto, b"S", b"I").unwrap();
        let bare = crypto.shake256_kdf_derive(b"SI", SHAKE256_NH).unwrap();
        assert_eq!(got.as_slice(), bare.as_slice());
    }
}
