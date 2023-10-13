//! # X509 Credential
//!
//! An implementation of the x509 credential from the MLS spec.

use base64::Engine;
use openmls_basic_credential::SignatureKeyPair;
use rustls_platform_verifier::CertificateDer;
use x509_cert::der::Decode;

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
    pub fn try_new(sk: Vec<u8>, cert_chain: Vec<Vec<u8>>) -> Result<Self, CryptoError> {
        if cert_chain.len() < 2 {
            return Err(CryptoError::IncompleteCertificateChain);
        }

        let verifier = rustls_platform_verifier::WireClientVerifier::new();

        let end_entity = cert_chain
            .get(0)
            .map(|c| CertificateDer::from(c.as_slice()))
            .ok_or(CryptoError::IncompleteCertificateChain)?;

        let intermediates = cert_chain.as_slice()[1..]
            .into_iter()
            .map(|c| CertificateDer::from(c.as_slice()))
            .collect::<Vec<_>>();

        let now = rustls_platform_verifier::UnixTime::now();

        use rustls_platform_verifier::ClientCertVerifier as _;
        verifier
            .verify_client_cert(&end_entity, &intermediates[..], now)
            .map_err(|_| CryptoError::InvalidCertificateChain)?;

        // We use x509_cert crate here because it is better at introspecting certs compared rustls which
        // is more TLS focused and does not come up with handy helpers
        let end_entity = x509_cert::Certificate::from_der(end_entity.as_ref())
            .map_err(|_| CryptoError::InvalidCertificateChain)?;

        let signature_scheme = end_entity.signature_scheme()?;
        let pk = end_entity.public_key()?;

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
    fn public_key(&self) -> Result<&[u8], CryptoError>;

    fn signature_scheme(&self) -> Result<SignatureScheme, CryptoError>;

    fn identity(&self) -> Result<Vec<u8>, CryptoError>;
}

const CLIENT_ID_PREFIX: &str = "im:wireapp=";

impl X509Ext for x509_cert::Certificate {
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

    fn identity(&self) -> Result<Vec<u8>, CryptoError> {
        let extensions = self
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(CryptoError::InvalidCertificate)?;
        let san = extensions
            .iter()
            .find(|e| {
                e.extn_id.as_bytes() == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME.as_bytes()
            })
            .and_then(|e| {
                x509_cert::ext::pkix::SubjectAltName::from_der(e.extn_value.as_bytes()).ok()
            })
            .ok_or(CryptoError::InvalidCertificate)?;
        san.0
            .iter()
            .filter_map(|n| match n {
                x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(ia5_str) => {
                    Some(ia5_str.as_str())
                }
                _ => None,
            })
            .filter_map(|n| {
                n.starts_with(CLIENT_ID_PREFIX)
                    .then(|| n.trim_start_matches(CLIENT_ID_PREFIX))
            })
            .find_map(parse_client_id)
            .map(|i| i.as_bytes().to_vec())
            .ok_or(CryptoError::InvalidCertificate)
    }
}

fn parse_client_id(client_id: &str) -> Option<String> {
    let (user_id, rest) = client_id.split_once('/')?;
    parse_user_id(user_id)?;
    let (device_id, _domain) = rest.split_once('@')?;
    u64::from_str_radix(device_id, 16).ok()?;
    let client_id = client_id.replace('/', ":");
    Some(client_id)
}

fn parse_user_id(user_id: impl AsRef<[u8]>) -> Option<()> {
    let _user_id = base64::prelude::BASE64_URL_SAFE_NO_PAD
        .decode(user_id)
        .ok()?;
    // TODO: this holds for the former (wrong) userId encoding (where we were b64 encoding the uuid string and not byte representation)
    // When  upstream rusty-jwt-tools gets merged, change to `uuid::Uuid::from_slice`. Core-Crypto tests will spot that anyway
    // uuid::Uuid::from_slice(&user_id).ok()
    // TODO: reintroduce this check once all platform got the fix with the correct userId encoding
    Some(())
}
