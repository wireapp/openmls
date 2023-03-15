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
use x509_parser::der_parser::asn1_rs::oid;
use x509_parser::der_parser::Oid;
use x509_parser::prelude::{Logger, Validator, X509Certificate, X509StructureValidator};

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
    /// An X.509 [`Certificate`]
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
pub struct Certificate {
    identity: TlsByteVecU16,
    cert_chain: TlsVecU16<TlsByteVecU16>,
}

impl Certificate {
    fn parse(&self) -> Result<Vec<X509Certificate>, CredentialError> {
        self.cert_chain.iter().try_fold(
            Vec::new(),
            |mut acc, certificate| -> Result<Vec<X509Certificate>, CredentialError> {
                acc.push(Self::parse_single(certificate)?);
                Ok(acc)
            },
        )
    }

    fn parse_single(certificate: &TlsByteVecU16) -> Result<X509Certificate, CredentialError> {
        use x509_parser::nom::Parser as _;

        let mut parser = x509_parser::certificate::X509CertificateParser::new()
            .with_deep_parse_extensions(false);
        parser
            .parse(certificate.as_slice())
            .map(|(_, cert)| cert)
            .map_err(|_| CredentialError::InvalidCertificateFormat)
    }

    /// Is signed by issuer
    fn is_verified(
        certificate: &X509Certificate,
        issuer: &X509Certificate,
    ) -> Result<(), CredentialError> {
        certificate
            .verify_signature(Some(&issuer.subject_pki))
            .map_err(|_| CredentialError::InvalidCertificateChain)
    }

    fn is_valid<'a>(
        certificate: &'a X509Certificate,
    ) -> Result<&'a X509Certificate<'a>, CredentialError> {
        if Self::is_time_valid(certificate) && Self::is_structure_valid(certificate) {
            Ok(certificate)
        } else {
            Err(CredentialError::InvalidCertificate)
        }
    }

    fn is_structure_valid(certificate: &X509Certificate) -> bool {
        // validates structure (fields etc..)
        struct NoopLogger;
        impl Logger for NoopLogger {
            fn warn(&mut self, _: &str) {}
            fn err(&mut self, _: &str) {}
        }
        X509StructureValidator.validate(certificate, &mut NoopLogger)
    }

    fn is_time_valid(certificate: &X509Certificate) -> bool {
        // 'not_before' < now < 'not_after'
        certificate.validity().is_valid()
    }

    fn signature_scheme(certificate: &X509Certificate) -> Result<SignatureScheme, CredentialError> {
        // see https://github.com/bcgit/bc-java/blob/r1rv71/core/src/main/java/org/bouncycastle/asn1/edec/EdECObjectIdentifiers.java
        const ED25519: Oid = oid!(1.3.101 .112);
        const ED448: Oid = oid!(1.3.101 .113);
        // see https://github.com/bcgit/bc-java/blob/r1rv71/core/src/main/java/org/bouncycastle/asn1/x9/X9ObjectIdentifiers.java
        const ECDSA_SHA256: Oid = oid!(1.2.840 .10045 .4 .3 .2);
        const ECDSA_SHA384: Oid = oid!(1.2.840 .10045 .4 .3 .3);
        const ECDSA_SHA512: Oid = oid!(1.2.840 .10045 .4 .3 .4);

        let alg = &certificate.signature_algorithm.algorithm;

        if *alg == ED25519 {
            Ok(SignatureScheme::ED25519)
        } else if *alg == ED448 {
            Ok(SignatureScheme::ED448)
        } else if *alg == ECDSA_SHA256 {
            Ok(SignatureScheme::ECDSA_SECP256R1_SHA256)
        } else if *alg == ECDSA_SHA384 {
            Ok(SignatureScheme::ECDSA_SECP384R1_SHA384)
        } else if *alg == ECDSA_SHA512 {
            Ok(SignatureScheme::ECDSA_SECP521R1_SHA512)
        } else {
            Err(CredentialError::UnsupportedSignatureScheme)
        }
    }

    fn public_key(certificate: &X509Certificate) -> Result<SignaturePublicKey, CredentialError> {
        let public_key = &certificate.subject_pki.subject_public_key;
        let signature_scheme = Self::signature_scheme(certificate);
        SignaturePublicKey::new(public_key.data.to_vec(), signature_scheme?)
            .map_err(|_| CredentialError::IncompleteCertificate("subjectPublicKeyInfo".to_string()))
    }

    fn leaf_certificate(&self) -> &TlsByteVecU16 {
        &self.cert_chain[0]
    }
}

/// MlsCredentialType.
///
/// This enum contains variants containing the different available credentials.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum MlsCredentialType {
    /// A [`BasicCredential`]
    Basic(BasicCredential),
    /// An X.509 [`Certificate`]
    X509(Certificate),
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
                let certificates = certificate_chain.parse()?;
                certificates
                    .iter()
                    .enumerate()
                    .map(Ok)
                    .reduce(
                        |a, b| -> Result<(usize, &X509Certificate), CredentialError> {
                            let (current_index, current) = a?;
                            let (next_index, next) = b?;
                            if current_index == 0 {
                                // this is leaf certificate
                                Certificate::public_key(current)?
                                    // verify that payload is signed by leaf certificate
                                    .verify(backend, signature, payload)
                                    .map_err(|_| CredentialError::InvalidSignature)?;
                            }
                            // is valid in time + x509 structure (fields etc..)
                            Certificate::is_valid(current)
                                // verifies current signed by issuer
                                .and(Certificate::is_verified(current, next))?;
                            Ok((next_index, next))
                        },
                    )
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
                let leaf = certificate_chain.leaf_certificate();
                let leaf = Certificate::parse_single(leaf)?;
                Certificate::signature_scheme(&leaf)
            }
        }
    }

    /// Returns the public key contained in the credential.
    pub fn signature_key(&self) -> &SignaturePublicKey {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => &basic_credential.public_key,
            MlsCredentialType::X509(certificates) => {
                // TODO: (wire) implement x509 properly
                let leaf = certificates.leaf_certificate();
                // should be safe as we already have checked certificate beforehand
                // TODO: (wire) highly inefficient, parsing certificate twice to avoid propagating lifetime everywhere
                let leaf = Certificate::parse_single(leaf).unwrap();
                let signature_key = Certificate::public_key(&leaf).unwrap();
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
            credential: MlsCredentialType::X509(Certificate {
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
