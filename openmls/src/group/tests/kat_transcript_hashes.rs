//! # Known Answer Tests for the transcript hashes
//!
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
//! for more description on the test vectors.

use std::convert::TryFrom;

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider};
use serde::{self, Deserialize, Serialize};
use tls_codec::Deserialize as TlsDeserializeTrait;

#[cfg(test)]
use crate::test_utils::read;
use crate::{
    framing::{mls_auth_content::AuthenticatedContent, *},
    group::*,
    schedule::*,
    test_utils::*,
    versions::ProtocolVersion,
};

const TEST_VECTOR_PATH_READ: &str = "test_vectors/transcript-hashes.json";

/// ```json
/// {
///   "cipher_suite": /* uint16 */,
///
///   /* Chosen by the generator */
///   "confirmation_key": /* hex-encoded binary data */,
///   "authenticated_content": /* hex-encoded TLS serialized AuthenticatedContent */,
///   "interim_transcript_hash_before": /* hex-encoded binary data */,
///
///   /* Computed values */
///   "confirmed_transcript_hash_after": /* hex-encoded binary data */,
///   "interim_transcript_hash_after": /* hex-encoded binary data */,
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TranscriptTestVector {
    pub cipher_suite: u16,

    #[serde(with = "hex::serde")]
    pub confirmation_key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub authenticated_content: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub interim_transcript_hash_before: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub confirmed_transcript_hash_after: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub interim_transcript_hash_after: Vec<u8>,
}

// -------------------------------------------------------------------------------------------------

#[test]
fn read_test_vectors_transcript() {
    let tests: Vec<TranscriptTestVector> = read(TEST_VECTOR_PATH_READ);

    for test_vector in tests {
        run_test_vector(test_vector);
    }
}

pub fn run_test_vector(test_vector: TranscriptTestVector) {
    let backend = OpenMlsRustCrypto::default();

    let ciphersuite = Ciphersuite::try_from(test_vector.cipher_suite).unwrap();
    if backend.crypto().supports(ciphersuite).is_err() {
        log::debug!("Skipping unsupported ciphersuite `{ciphersuite:?}`.");
        return;
    }

    // Verification:
    //
    // Verify that `authenticated_content` contains a `Commit`, ...
    let authenticated_content = AuthenticatedContent::from(
        AuthenticatedContentIn::tls_deserialize_exact(test_vector.authenticated_content).unwrap(),
    );
    assert!(matches!(
        authenticated_content.content(),
        FramedContentBody::Commit(_)
    ));

    // ... and `authenticated_content.auth.confirmation_tag` is a valid MAC for `authenticated_content` with key `confirmation_key` and input `confirmed_transcript_hash_after`.
    let confirmation_key = ConfirmationKey::from_secret(Secret::from_slice(
        &test_vector.confirmation_key,
        ProtocolVersion::default(),
        ciphersuite,
    ));
    let got_confirmation_tag = confirmation_key
        .tag(&backend, &test_vector.confirmed_transcript_hash_after)
        .unwrap();
    assert_eq!(
        got_confirmation_tag,
        *authenticated_content.confirmation_tag().unwrap()
    );

    // Verify that *`confirmed_transcript_hash_after`* and `interim_transcript_hash_after` are the result of updating `interim_transcript_hash_before` with `authenticated_content`.
    let got_confirmed_transcript_hash_after = {
        let input = ConfirmedTranscriptHashInput::try_from(&authenticated_content).unwrap();

        input
            .calculate_confirmed_transcript_hash(
                backend.crypto(),
                ciphersuite,
                &test_vector.interim_transcript_hash_before,
            )
            .unwrap()
    };
    assert_eq!(
        test_vector.confirmed_transcript_hash_after,
        got_confirmed_transcript_hash_after
    );

    // Verify that `confirmed_transcript_hash_after` and *`interim_transcript_hash_after`* are the result of updating `interim_transcript_hash_before` with `authenticated_content`.
    let got_interim_transcript_hash_after = {
        let input = InterimTranscriptHashInput::from(&got_confirmation_tag);

        input
            .calculate_interim_transcript_hash(
                backend.crypto(),
                ciphersuite,
                &got_confirmed_transcript_hash_after,
            )
            .unwrap()
    };
    assert_eq!(
        test_vector.interim_transcript_hash_after,
        got_interim_transcript_hash_after
    );
}
