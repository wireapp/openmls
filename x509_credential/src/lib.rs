//! # X509 Credential
//!
//! An implementation of the x509 credential from the MLS spec.

use openmls_basic_credential::SignatureKeyPair;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::{MlsEntity, MlsEntityId},
    types::{CryptoError, SignatureScheme},
};

#[derive(std::fmt::Debug, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct CertificateKeyPair(pub SignatureKeyPair);

impl CertificateKeyPair {
    /// Constructs the `CertificateKeyPair` from a private key and a der encoded certificate chain
    pub fn new(sk: Vec<u8>, cert_chain: Vec<Vec<u8>>) -> Result<Self, CryptoError> {
        if cert_chain.len() < 2 {
            return Err(CryptoError::IncompleteCertificateChain);
        }
        let pki_path = cert_chain.into_iter().try_fold(
            x509_cert::PkiPath::new(),
            |mut acc, cert_data| -> Result<x509_cert::PkiPath, CryptoError> {
                let cert = Certificate::from_der(&cert_data)
                    .map_err(|_| CryptoError::CertificateDecodingError)?;
                cert.is_valid()?;
                acc.push(cert);
                Ok(acc)
            },
        )?;

        let leaf = pki_path.get(0).ok_or(CryptoError::CryptoLibraryError)?;

        let signature_scheme = leaf.signature_scheme()?;
        let pk = leaf.public_key()?;

        let kp = SignatureKeyPair::try_from_raw(signature_scheme, sk, pk.to_vec())?;

        Ok(Self(kp))
    }
}

impl std::ops::Deref for CertificateKeyPair {
    type Target = SignatureKeyPair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl secrecy::SerializableSecret for CertificateKeyPair {}

impl tls_codec::Size for CertificateKeyPair {
    fn tls_serialized_len(&self) -> usize {
        self.0.tls_serialized_len()
    }
}

impl tls_codec::Deserialize for CertificateKeyPair {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        SignatureKeyPair::tls_deserialize(bytes).map(Self)
    }
}

impl tls_codec::Serialize for CertificateKeyPair {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.0.tls_serialize(writer)
    }
}

impl openmls_traits::signatures::DefaultSigner for CertificateKeyPair {
    fn private_key(&self) -> &[u8] {
        self.0.private_key()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.0.signature_scheme()
    }
}

impl MlsEntity for CertificateKeyPair {
    const ID: MlsEntityId = MlsEntityId::SignatureKeyPair;
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
            return Err(CryptoError::ExpiredCertificate);
        }
        Ok(())
    }

    fn is_time_valid(&self) -> Result<bool, CryptoError> {
        // 'not_before' < now < 'not_after'
        let x509_cert::time::Validity {
            not_before,
            not_after,
        } = self.tbs_certificate.validity;

        let now = fluvio_wasm_timer::SystemTime::now();
        let now = now
            .duration_since(fluvio_wasm_timer::UNIX_EPOCH)
            .map_err(|_| CryptoError::TimeError)?;

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
