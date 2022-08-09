//! # Hash References
//!
//!
//! Some MLS messages refer to other MLS objects by hash.  For example, Welcome
//! messages refer to KeyPackages for the members being welcomed, and Commits refer
//! to Proposals they cover.  These identifiers are computed as follows:
//!
//! ```text
//! opaque HashReference[16];
//!
//! MakeHashRef(value) = KDF.expand(KDF.extract("", value), "MLS 1.0 ref", 16)
//!
//! HashReference KeyPackageRef;
//! HashReference ProposalRef;
//! ```
//!
//! For a KeyPackageRef, the `value` input is the encoded KeyPackage, and the
//! ciphersuite specified in the KeyPackage determines the KDF used.  For a
//! ProposalRef, the `value` input is the MLSPlaintext carrying the proposal, and
//! the KDF is determined by the group's ciphersuite.

use std::convert::TryInto;

use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::Ciphersuite;

const LABEL: &[u8; 11] = b"MLS 1.0 ref";
const VALUE_LEN: usize = 16;
type Value = [u8; VALUE_LEN];

/// A reference to an MLS object computed as an HKDF of the value.
#[derive(
    Clone, Copy, Hash, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize, PartialOrd, Ord,
)]
pub struct HashReference {
    value: Value,
}

/// A reference to a key package.
/// This value uniquely identifies a key package.
pub type KeyPackageRef = HashReference;

/// A reference to a proposal.
/// This value uniquely identifies a proposal.
pub type ProposalRef = HashReference;

impl HashReference {
    /// Compute a new [`HashReference`] value for a `value`.
    pub fn new(
        value: &[u8],
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCrypto,
    ) -> Result<Self, CryptoError> {
        let okm = backend.hkdf_expand(
            ciphersuite.hash_algorithm(),
            &backend.hkdf_extract(ciphersuite.hash_algorithm(), &[], value)?,
            LABEL,
            VALUE_LEN,
        )?;
        let value: Value = okm.try_into().map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self { value })
    }

    /// Get a reference to the hash reference's value.
    pub fn value(&self) -> &[u8; 16] {
        &self.value
    }

    /// Get a reference to the hash reference's value as slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut value = [0u8; VALUE_LEN];
        value.clone_from_slice(slice);
        Self { value }
    }
}

impl From<Value> for HashReference {
    fn from(value: Value) -> Self {
        Self { value }
    }
}

impl core::fmt::Display for HashReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HashReference: ")?;
        write!(f, "{}", hex::encode(&self.value))?;
        Ok(())
    }
}

impl core::fmt::Debug for HashReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl serde::Serialize for HashReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let str = hex::encode(&self.value);
        serializer.serialize_str(&str)
    }
}

impl<'de> serde::Deserialize<'de> for HashReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct HashVisitor;
        impl<'de> serde::de::Visitor<'de> for HashVisitor {
            type Value = HashReference;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a hex encoded string.")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut buf = [0u8; 16];
                hex::decode_to_slice(v, &mut buf).map_err(serde::de::Error::custom)?;
                Ok(HashReference { value: buf })
            }
        }
        deserializer.deserialize_str(HashVisitor)
    }
}

#[cfg(test)]
mod serialization_tests {
    use std::collections::HashMap;

    use super::*;

    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    #[derive(serde::Deserialize, serde::Serialize)]
    struct MapTest {
        map: HashMap<HashReference, String>,
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_serialization() {
        let hash = HashReference {
            value: b"Hello I'm Alice!".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&hash).unwrap(),
            serde_json::Value::String("48656c6c6f2049276d20416c69636521".to_owned())
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_deserialization() {
        let value = serde_json::Value::String("48656c6c6f2049276d20416c69636521".to_owned());
        let hash: HashReference = serde_json::from_value(value).unwrap();
        assert_eq!(&hash.value, b"Hello I'm Alice!");
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_map_serialization() {
        let mut test_map = MapTest {
            map: HashMap::new(),
        };
        let hash = HashReference {
            value: b"Hello I'm Alice!".to_owned(),
        };
        test_map.map.insert(hash, "value".to_owned());
        let expected = serde_json::json!({
            "map": {
                "48656c6c6f2049276d20416c69636521": "value"
            }
        });
        assert_eq!(serde_json::to_value(&test_map).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_map_deserialization() {
        let input = serde_json::json!({
            "map": {
                "48656c6c6f2049276d20416c69636521": "value"
            }
        });
        let hash = HashReference {
            value: b"Hello I'm Alice!".to_owned(),
        };
        let result: MapTest = serde_json::from_value(input).unwrap();
        assert_eq!(result.map[&hash], "value");
    }
}
