//! # X509 Credential
//!
//! An implementation of the x509 credential from the MLS spec.

use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};
use std::{convert::From, fmt::Debug};
use x509_cert::{
    der::{Decode, Encode},
    Certificate, PkiPath,
};

use openmls_traits::{
    crypto::OpenMlsCrypto,
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

mod serde_certificate {
    use serde::{
        de::Error as _,
        ser::{Error as _, SerializeSeq},
        Deserialize, Deserializer, Serializer,
    };
    use x509_cert::{
        der::{Decode, Encode},
        PkiPath,
    };

    pub(super) fn serialize<S: Serializer>(cert: &PkiPath, ser: S) -> Result<S::Ok, S::Error> {
        let mut cert_data = Vec::new();
        cert.encode_to_vec(&mut cert_data)
            .map_err(S::Error::custom)?;
        let mut seq = ser.serialize_seq(Some(cert_data.len()))?;
        cert_data
            .iter()
            .try_for_each(|b| seq.serialize_element(b))?;
        seq.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<PkiPath, D::Error>
    where
        D: Deserializer<'de>,
    {
        let cert_data = Vec::<u8>::deserialize(deserializer)?;
        PkiPath::from_der(&cert_data).map_err(D::Error::custom)
    }

    #[cfg(test)]
    mod tests {
        use openmls_traits::types::SignatureScheme;
        use rcgen::generate_simple_self_signed;
        use x509_cert::{der::Decode, Certificate, PkiPath};

        use crate::CertificateKeyPair;

        #[test]
        fn should_serialize_ceritifcate() {
            let cert_generator = |quantity: usize| -> PkiPath {
                (0..quantity)
                    .map(|_| {
                        let subject_alt_names =
                            vec!["hello.world.example".to_string(), "localhost".to_string()];
                        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
                        let cert_der = cert.serialize_der().unwrap();
                        Certificate::from_der(&cert_der).unwrap()
                    })
                    .collect()
            };
            let certs = cert_generator(3);
            let kp = CertificateKeyPair {
                private: vec![].into(),
                certificate_chain: certs,
                signature_scheme: SignatureScheme::ED25519,
            };
            let serialized = serde_json::to_value(&kp).unwrap();
            let deserialized = serde_json::from_value::<CertificateKeyPair>(serialized).unwrap();
            assert_eq!(deserialized.certificate_chain, kp.certificate_chain);
        }
    }
}

/// A signature key pair for the x509 credential.
///
/// This can be used as keys to implement the MLS x509 credential. It simple
/// stores the private key and certificate chain.
#[derive(Serialize, Deserialize)]
pub struct CertificateKeyPair {
    #[serde(serialize_with = "expose_sk")]
    private: SecretVec<u8>,
    #[serde(with = "serde_certificate")]
    certificate_chain: PkiPath,
    signature_scheme: SignatureScheme,
}

impl secrecy::SerializableSecret for CertificateKeyPair {}

impl tls_codec::Size for CertificateKeyPair {
    fn tls_serialized_len(&self) -> usize {
        let cert_len: usize = self
            .certificate_chain
            .encoded_len()
            .unwrap()
            .try_into()
            .unwrap();
        self.private.expose_secret().tls_serialized_len()
            + cert_len
            + self.signature_scheme.tls_serialized_len()
    }
}

impl tls_codec::Deserialize for CertificateKeyPair {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let private = Vec::<u8>::tls_deserialize(bytes)?.into();
        let cert_data = Vec::<u8>::tls_deserialize(bytes)?;
        let certificate = PkiPath::from_der(&cert_data).map_err(|e| {
            tls_codec::Error::DecodingError(format!("Error decoding certificate: {e}"))
        })?;

        let signature_scheme = SignatureScheme::tls_deserialize(bytes)?;
        Ok(Self {
            private,
            certificate_chain: certificate,
            signature_scheme,
        })
    }
}

impl tls_codec::Serialize for CertificateKeyPair {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.private.expose_secret().tls_serialize(writer)?;
        let mut cert_data = Vec::new();
        self.certificate_chain
            .encode_to_vec(&mut cert_data)
            .map_err(|e| {
                tls_codec::Error::EncodingError(format!("Error encoding certificate: {e}"))
            })?;
        written += cert_data.tls_serialize(writer)?;
        written += self.signature_scheme.tls_serialize(writer)?;
        Ok(written)
    }
}

impl Debug for CertificateKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &"***".to_string())
            .field("certificate", &self.certificate_chain)
            .field("signature_scheme", &self.signature_scheme)
            .finish()
    }
}

impl openmls_traits::signatures::DefaultSigner for CertificateKeyPair {
    fn private_key(&self) -> &[u8] {
        self.private.expose_secret().as_slice()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

impl MlsEntity for CertificateKeyPair {
    const ID: MlsEntityId = MlsEntityId::CertificateKeyPair;
}

impl CertificateKeyPair {
    /// Constructs the `CertificateKeyPair` from a private key and a der encoded certificate chain
    pub fn new(private: SecretVec<u8>, cert_chain: Vec<Vec<u8>>) -> Result<Self, CryptoError> {
        if cert_chain.len() < 2 {
            return Err(CryptoError::IncompleteCertificateChain);
        }
        let pki_path = cert_chain.into_iter().try_fold(
            PkiPath::new(),
            |mut acc, cert_data| -> Result<PkiPath, CryptoError> {
                acc.push(
                    Certificate::from_der(&cert_data)
                        .map_err(|_| CryptoError::CertificateDecodingError)?,
                );
                Ok(acc)
            },
        )?;

        let signature_scheme = pki_path[0].signature_scheme()?;

        pki_path
            .iter()
            .try_for_each(|certificate| certificate.is_valid())?;

        Ok(Self {
            private,
            certificate_chain: pki_path,
            signature_scheme,
        })
    }

    /// Store this signature key pair in the key store.
    pub async fn store<T>(&self, key_store: &T) -> Result<(), <T as OpenMlsKeyStore>::Error>
    where
        T: OpenMlsKeyStore,
        <T as OpenMlsKeyStore>::Error: From<CryptoError>,
    {
        key_store.store(self.public()?, self).await
    }

    /// Read a signature key pair from the key store.
    pub async fn read(key_store: &impl OpenMlsKeyStore, public_key: &[u8]) -> Option<Self> {
        key_store.read(public_key).await
    }

    /// Get the public key as byte slice.
    pub fn public(&self) -> Result<&[u8], CryptoError> {
        self.certificate_chain
            .get(0)
            .ok_or(CryptoError::IncompleteCertificateChain)?
            .public_key()
    }

    /// Get the public key as byte vector.
    pub fn to_public_vec(&self) -> Result<Vec<u8>, CryptoError> {
        self.public().map(|p| p.to_owned())
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

pub trait X509Ext {
    fn is_valid(&self) -> Result<(), CryptoError>;

    fn is_time_valid(&self) -> Result<bool, CryptoError>;

    fn public_key(&self) -> Result<&[u8], CryptoError>;

    fn signature_scheme(&self) -> Result<SignatureScheme, CryptoError>;

    fn is_signed_by(
        &self,
        backend: &impl OpenMlsCrypto,
        issuer: &Certificate,
    ) -> Result<(), CryptoError>;
}

impl X509Ext for Certificate {
    fn is_valid(&self) -> Result<(), CryptoError> {
        if !self.is_time_valid()? {
            return Err(CryptoError::InvalidCertificate);
        }
        Ok(())
    }

    fn is_time_valid(&self) -> Result<bool, CryptoError> {
        // 'not_before' < now < 'not_after'
        let x509_cert::time::Validity {
            not_before,
            not_after,
        } = self.tbs_certificate.validity;
        let x509_cert::time::Validity {
            not_before: now, ..
        } = x509_cert::time::Validity::from_now(core::time::Duration::default())
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        let now = now.to_unix_duration();
        let is_nbf = now > not_before.to_unix_duration();
        let is_naf = now < not_after.to_unix_duration();
        Ok(is_nbf && is_naf)
    }

    fn public_key(&self) -> Result<&[u8], CryptoError> {
        self.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(CryptoError::IncompleteCertificate("spki"))
    }

    fn signature_scheme(&self) -> Result<SignatureScheme, CryptoError> {
        let alg = self.tbs_certificate.subject_public_key_info.algorithm.oid;
        let alg = oid_registry::Oid::new(std::borrow::Cow::Borrowed(alg.as_bytes()));

        let scheme = if alg == oid_registry::OID_SIG_ED25519 {
            SignatureScheme::ED25519
        } else if alg == oid_registry::OID_SIG_ED448 {
            SignatureScheme::ED448
        } else if alg == oid_registry::OID_SIG_ECDSA_WITH_SHA256 {
            SignatureScheme::ECDSA_SECP256R1_SHA256
        } else if alg == oid_registry::OID_SIG_ECDSA_WITH_SHA384 {
            SignatureScheme::ECDSA_SECP384R1_SHA384
        } else if alg == oid_registry::OID_SIG_ECDSA_WITH_SHA512 {
            SignatureScheme::ECDSA_SECP521R1_SHA512
        } else {
            return Err(CryptoError::UnsupportedSignatureScheme);
        };
        Ok(scheme)
    }

    fn is_signed_by(
        &self,
        backend: &impl OpenMlsCrypto,
        issuer: &Certificate,
    ) -> Result<(), CryptoError> {
        let issuer_pk = issuer.public_key()?;
        let cert_signature = self
            .signature
            .as_bytes()
            .ok_or(CryptoError::InvalidCertificate)?;

        use x509_cert::der::Encode as _;
        let mut raw_tbs: Vec<u8> = vec![];
        self.tbs_certificate
            .encode(&mut raw_tbs)
            .map_err(|_| CryptoError::CertificateEncodingError)?;
        backend
            .verify_signature(
                self.signature_scheme()?,
                &raw_tbs,
                issuer_pk,
                cert_signature,
            )
            .map_err(|_| CryptoError::InvalidSignature)
    }
}
