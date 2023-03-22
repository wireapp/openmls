//! # Credentials
//!
//! A [`Credential`] contains identifying information about the client that
//! created it, as well as a signature public key and the corresponding
//! signature scheme. [`Credential`]s represent clients in MLS groups and are
//! used to authenticate their messages. Each
//! [`KeyPackage`](crate::key_packages::KeyPackage) that is either
//! pre-published, or that represents a client in a group contains a
//! [`Credential`] and is authenticated by it.
//!
//! Clients can create a [`Credential`] by creating a [`CredentialBundle`] which
//! contains the [`Credential`], as well as the corresponding private key
//! material. The [`CredentialBundle`] can in turn be used to generate a
//! [`KeyPackageBundle`](crate::key_packages::KeyPackageBundle).
//!
//! The MLS protocol spec allows the that represents a client in a group to
//! change over time. Concretely, members can issue an Update proposal or a Full
//! Commit to update their [`KeyPackage`](crate::key_packages::KeyPackage), as
//! well as the [`Credential`] in it. The Update has to be authenticated by the
//! signature public key contained in the old [`Credential`].
//!
//! When receiving a credential update from another member, applications must
//! query the Authentication Service to ensure that the new credential is valid.
//!
//! Credentials are specific to a signature scheme, which has to match the
//! ciphersuite of the [`KeyPackage`](crate::key_packages::KeyPackage) that it
//! is embedded in. Clients can use different credentials, potentially with
//! different signature schemes in different groups.
//!
//! There are multiple [`CredentialType`]s, although OpenMLS currently only
//! supports the [`BasicCredential`].

use std::convert::TryFrom;
use std::io::Write;

use openmls_traits::{
    types::{CryptoError, SignatureScheme},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use tls_codec::Serialize as TlsSerializeTrait;
use tls_codec::{Error, TlsByteVecU16, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU16};
use x509_cert::Certificate;

use errors::*;

use crate::{ciphersuite::*, error::LibraryError};

// Private
mod codec;
#[cfg(test)]
mod tests;
// Public
pub mod errors;

/// CredentialType.
///
/// This enum contains variants for the different Credential Types.
#[derive(
    Copy, Clone, Debug, PartialEq, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u16)]
pub enum CredentialType {
    /// A [`BasicCredential`]
    Basic = 1,
    /// An X.509 [`MlsCertificate`]
    X509 = 2,
}

impl TryFrom<u16> for CredentialType {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CredentialType::Basic),
            2 => Ok(CredentialType::X509),
            _ => Err("Undefined CredentialType"),
        }
    }
}

/// X.509 Certificate.
///
/// This struct contains an X.509 certificate chain.  Note that X.509
/// certificates are not yet supported by OpenMLS.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct MlsCertificate {
    identity: TlsByteVecU16,
    cert_chain: TlsVecU16<TlsByteVecU16>,
}

trait X509Ext {
    fn is_valid(&self) -> Result<(), CredentialError>;

    fn is_time_valid(&self) -> Result<bool, CredentialError>;

    fn public_key(&self) -> Result<SignaturePublicKey, CredentialError>;

    fn signature_scheme(&self) -> Result<SignatureScheme, CredentialError>;

    fn is_signed_by(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        issuer: &Certificate,
    ) -> Result<(), CredentialError>;
}

impl X509Ext for Certificate {
    fn is_valid(&self) -> Result<(), CredentialError> {
        if !self.is_time_valid()? {
            return Err(CredentialError::InvalidCertificate);
        }
        Ok(())
    }

    fn is_time_valid(&self) -> Result<bool, CredentialError> {
        // 'not_before' < now < 'not_after'
        let x509_cert::time::Validity {
            not_before,
            not_after,
        } = self.tbs_certificate.validity;
        let x509_cert::time::Validity {
            not_before: now, ..
        } = x509_cert::time::Validity::from_now(core::time::Duration::default())?;

        let now = now.to_unix_duration();
        let is_nbf = now > not_before.to_unix_duration();
        let is_naf = now < not_after.to_unix_duration();
        Ok(is_nbf && is_naf)
    }

    fn public_key(&self) -> Result<SignaturePublicKey, CredentialError> {
        let pk = self
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(CredentialError::IncompleteCertificate("spki"))?;
        let scheme = self.signature_scheme()?;
        SignaturePublicKey::new(pk.to_vec(), scheme)
            .map_err(|_| CredentialError::InvalidCertificate)
    }

    fn signature_scheme(&self) -> Result<SignatureScheme, CredentialError> {
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
            return Err(CredentialError::UnsupportedSignatureScheme);
        };
        Ok(scheme)
    }

    fn is_signed_by(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        issuer: &Certificate,
    ) -> Result<(), CredentialError> {
        let issuer_pk = issuer.public_key()?;
        let cert_signature = self
            .signature
            .as_bytes()
            .ok_or(CredentialError::InvalidCertificate)?;

        use x509_cert::der::Encode as _;
        let mut raw_tbs: Vec<u8> = vec![];
        self.tbs_certificate.encode(&mut raw_tbs)?;
        Ok(issuer_pk
            .verify(backend, &cert_signature.into(), &raw_tbs)
            .map_err(|_| CredentialError::InvalidSignature)?)
    }
}

impl MlsCertificate {
    fn pki_path(&self) -> Result<x509_cert::PkiPath, CredentialError> {
        self.cert_chain.iter().try_fold(
            vec![],
            |mut acc, certificate| -> Result<x509_cert::PkiPath, CredentialError> {
                acc.push(Self::parse_single(certificate)?);
                Ok(acc)
            },
        )
    }

    fn parse_single(certificate: &TlsByteVecU16) -> Result<Certificate, CredentialError> {
        use x509_cert::der::Decode as _;
        Ok(x509_cert::Certificate::from_der(certificate.as_slice())?)
    }

    fn get_leaf_certificate(&self) -> Result<Certificate, CredentialError> {
        let leaf = self
            .cert_chain
            .get(0)
            .ok_or(CredentialError::InvalidCertificateChain)?;
        Self::parse_single(leaf)
    }
}

/// MlsCredentialType.
///
/// This enum contains variants containing the different available credentials.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum MlsCredentialType {
    /// A [`BasicCredential`]
    Basic(BasicCredential),
    /// An X.509 [`MlsCertificate`]
    X509(MlsCertificate),
}

/// Credential.
///
/// This struct contains MLS credential data, where the data depends on the
/// type. The [`CredentialType`] always matches the [`MlsCredentialType`].
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub(crate) credential_type: CredentialType,
    pub(crate) credential: MlsCredentialType,
}

impl Credential {
    /// Verifies a signature of a given payload against the public key contained
    /// in a credential.
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
        signature: &Signature,
    ) -> Result<(), CredentialError> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential
                .public_key
                .verify(backend, signature, payload)
                .map_err(|_| CredentialError::InvalidSignature),
            // TODO: implement verification for X509 certificates. See issue #134.
            MlsCredentialType::X509(certificate_chain) => {
                certificate_chain
                    .pki_path()?
                    .iter()
                    .enumerate()
                    .map(Ok)
                    .reduce(|a, b| -> Result<(usize, &Certificate), CredentialError> {
                        let (child_idx, child_cert) = a?;
                        let (parent_idx, parent_cert) = b?;

                        // leaf certificate
                        if child_idx == 0 {
                            child_cert
                                .public_key()?
                                .verify(backend, signature, payload)
                                .map_err(|_| CredentialError::InvalidSignature)?;
                        }

                        // verify not expired
                        child_cert.is_valid()?;

                        // verify that child is signed by parent
                        child_cert.is_signed_by(backend, &parent_cert)?;

                        Ok((parent_idx, parent_cert))
                    })
                    .ok_or_else(|| {
                        CredentialError::LibraryError(LibraryError::custom(
                            "Cannot have validated an empty certificate chain",
                        ))
                    })?
                    .map(|_| ())
            }
        }
    }

    /// Returns the identity of a given credential.
    pub fn identity(&self) -> &[u8] {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential.identity.as_slice(),
            // TODO: implement getter for identity for X509 certificates. See issue #134.
            MlsCredentialType::X509(certificate_chain) => {
                // TODO: (wire) implement x509 properly. Identity should be extracted from leaf certificate e.g. serial + subj alt name
                certificate_chain.identity.as_slice()
            }
        }
    }

    /// Returns the signature scheme used by the credential.
    pub fn signature_scheme(&self) -> Result<SignatureScheme, CredentialError> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => Ok(basic_credential.signature_scheme),
            MlsCredentialType::X509(certificate_chain) => {
                // TODO: implement getter for signature scheme for X509 certificates. See issue #134.
                // TODO: (wire) highly inefficient, parsing certificate twice to avoid propagating lifetime everywhere
                certificate_chain.get_leaf_certificate()?.signature_scheme()
            }
        }
    }

    /// Returns the public key contained in the credential.
    pub fn signature_key(&self) -> &SignaturePublicKey {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => &basic_credential.public_key,
            MlsCredentialType::X509(certificates) => {
                // TODO: (wire) highly inefficient, parsing certificate twice to avoid propagating lifetime everywhere
                let signature_key = certificates
                    .get_leaf_certificate()
                    .and_then(|l| l.public_key())
                    .unwrap();
                // TODO: conscious memory leak
                Box::leak(Box::new(signature_key))
            }
        }
    }
}

impl From<MlsCredentialType> for Credential {
    fn from(mls_credential_type: MlsCredentialType) -> Self {
        Credential {
            credential_type: match mls_credential_type {
                MlsCredentialType::Basic(_) => CredentialType::Basic,
                MlsCredentialType::X509(_) => CredentialType::X509,
            },
            credential: mls_credential_type,
        }
    }
}

/// Basic Credential.
///
/// A `BasicCredential` as defined in the MLS protocol spec. It exposes an
/// `identity` to represent the client, as well as a signature public key, along
/// with the corresponding signature scheme.
#[derive(Debug, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct BasicCredential {
    pub(crate) identity: TlsByteVecU16,
    pub(crate) signature_scheme: SignatureScheme,
    pub(crate) public_key: SignaturePublicKey,
}

impl BasicCredential {
    /// Verifies a signature issued by a [`BasicCredential`].
    ///
    /// Returns a [`CredentialError`] if the verification fails.
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
        signature: &Signature,
    ) -> Result<(), CredentialError> {
        self.public_key
            .verify(backend, signature, payload)
            .map_err(|_| CredentialError::InvalidSignature)
    }
}

impl PartialEq for BasicCredential {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity && self.public_key == other.public_key
    }
}

/// Credential Bundle.
///
/// This struct contains a [`Credential`] and the private key corresponding to
/// the signature key it contains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq))]
pub struct CredentialBundle {
    credential: Credential,
    signature_private_key: SignaturePrivateKey,
}

impl CredentialBundle {
    /// Creates and returns a new basic [`CredentialBundle`] for the given identity and [`SignatureScheme`].
    /// The corresponding key material is freshly generated.
    pub fn new_basic(
        identity: Vec<u8>,
        signature_scheme: SignatureScheme,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, CredentialError> {
        let (private_key, public_key) = SignatureKeypair::new(signature_scheme, backend)
            .map_err(LibraryError::unexpected_crypto_error)?
            .into_tuple();
        let credential = Credential {
            credential_type: CredentialType::Basic,
            credential: MlsCredentialType::Basic(BasicCredential {
                identity: identity.into(),
                signature_scheme,
                public_key,
            }),
        };
        Ok(CredentialBundle {
            credential,
            signature_private_key: private_key,
        })
    }

    /// Creates and returns a new x509 [`CredentialBundle`]
    pub fn new_x509(
        identity: Vec<u8>,
        cert_chain: Vec<Vec<u8>>,
        private_key: SignaturePrivateKey,
    ) -> Result<Self, CredentialError> {
        if cert_chain.len() < 2 {
            return Err(CredentialError::IncompleteCertificateChain);
        }
        let cert_chain = cert_chain
            .into_iter()
            .map(|c| c.into())
            .collect::<TlsVecU16<_>>();
        let credential = Credential {
            credential_type: CredentialType::X509,
            // TODO: (wire) implement x509 properly. Identity should not be there and extracted from certificate instead
            credential: MlsCredentialType::X509(MlsCertificate {
                identity: identity.into(),
                cert_chain,
            }),
        };
        Ok(CredentialBundle {
            credential,
            signature_private_key: private_key,
        })
    }

    /// Creates a new [`CredentialBundle`] from an identity and a
    /// [`SignatureKeypair`]. Note that only [`BasicCredential`] is currently
    /// supported.
    pub fn from_parts(identity: Vec<u8>, keypair: SignatureKeypair) -> Self {
        let (signature_private_key, public_key) = keypair.into_tuple();
        let basic_credential = BasicCredential {
            identity: identity.into(),
            signature_scheme: public_key.signature_scheme(),
            public_key,
        };
        let credential = Credential {
            credential_type: CredentialType::Basic,
            credential: MlsCredentialType::Basic(basic_credential),
        };
        Self {
            credential,
            signature_private_key,
        }
    }

    /// Returns a reference to the [`Credential`].
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Separates the bundle into the [`Credential`] and the [`SignaturePrivateKey`].
    pub fn into_parts(self) -> (Credential, SignaturePrivateKey) {
        (self.credential, self.signature_private_key)
    }

    /// Signs the given message `msg` using the private key of the credential bundle.
    pub(crate) fn sign(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        msg: &[u8],
    ) -> Result<Signature, CryptoError> {
        self.signature_private_key.sign(backend, msg)
    }

    /// Returns the key pair of the given credential bundle.
    #[cfg(any(feature = "test-utils", test))]
    pub fn key_pair(&self) -> SignatureKeypair {
        let public_key = self.credential().signature_key().clone();
        let private_key = self.signature_private_key.clone();
        SignatureKeypair::from_parts(public_key, private_key)
    }
}
