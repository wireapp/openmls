use super::*;

/// 7.1 Content Authentication
///
/// ```ignore
/// opaque MAC<V>;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Mac {
    pub(crate) mac_value: VLBytes,
}

impl PartialEq for Mac {
    // Constant time comparison.
    fn eq(&self, other: &Mac) -> bool {
        self.mac_value
            .as_slice()
            .ct_eq(other.mac_value.as_slice())
            .into()
    }
}

impl Mac {
    /// HMAC-Hash(salt, IKM). For all supported ciphersuites this is the same
    /// HMAC that is also used in HKDF.
    /// Compute the HMAC on `salt` with key `ikm`.
    pub(crate) fn new(
        backend: &impl OpenMlsCryptoProvider,
        salt: &Secret,
        ikm: &[u8],
    ) -> Result<Self, CryptoError> {
        Ok(Mac {
            mac_value: salt
                .hkdf_extract(
                    backend,
                    &Secret::from_slice(ikm, salt.mls_version, salt.ciphersuite),
                )?
                .value
                .as_slice()
                .into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn flip_last_byte(&mut self) {
        let mut last_bits = self.mac_value.pop().expect("An unexpected error occurred.");
        last_bits ^= 0xff;
        self.mac_value.push(last_bits);
    }
}

impl std::ops::Deref for Mac {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.mac_value.as_slice()
    }
}
