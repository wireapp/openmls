//! # Credentials
//!
//! A [`Credential`] contains identifying information about the client that
//! created it. [`Credential`]s represent clients in MLS groups and are
//! used to authenticate their messages. Each
//! [`KeyPackage`](crate::key_packages::KeyPackage) as well as each client (leaf node)
//! in the group (tree) contains a [`Credential`] and is authenticated.
//! The [`Credential`] must the be checked by an authentication server and the
//! application, which is out of scope of MLS.
//!
//! Clients can create a [`Credential`].
//!
//! The MLS protocol spec allows the [`Credential`] that represents a client in a group to
//! change over time. Concretely, members can issue an Update proposal or a Full
//! Commit to update their [`LeafNode`](crate::treesync::LeafNode), as
//! well as the [`Credential`] in it. The Update has to be authenticated by the
//! signature public key corresponding to the old [`Credential`].
//!
//! When receiving a credential update from another member, applications must
//! query the Authentication Service to ensure that the new credential is valid.
//!
//! There are multiple [`CredentialType`]s, although OpenMLS currently only
//! supports the [`BasicCredential`].

use std::fmt::Formatter;
use std::io::{Read, Write};
use std::process::Stdio;

use openmls_traits::{
    authentication_service::{AuthenticationServiceDelegate, CredentialAuthenticationStatus},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

// Private
mod codec;
#[cfg(test)]
mod tests;

use errors::*;

use openmls_x509_credential::X509Ext;
use x509_cert::{der::Decode, PkiPath};

use crate::ciphersuite::SignaturePublicKey;

// Public
pub mod errors;

/// CredentialType.
///
/// This enum contains variants for the different Credential Types.
///
/// ```c
/// // See IANA registry for registered values
/// uint16 CredentialType;
/// ```
///
/// **IANA Considerations**
///
/// | Value            | Name                     | R | Ref      |
/// |:-----------------|:-------------------------|:--|:---------|
/// | 0x0000           | RESERVED                 | - | RFC XXXX |
/// | 0x0001           | basic                    | Y | RFC XXXX |
/// | 0x0002           | x509                     | Y | RFC XXXX |
/// | 0x0A0A           | GREASE                   | Y | RFC XXXX |
/// | 0x1A1A           | GREASE                   | Y | RFC XXXX |
/// | 0x2A2A           | GREASE                   | Y | RFC XXXX |
/// | 0x3A3A           | GREASE                   | Y | RFC XXXX |
/// | 0x4A4A           | GREASE                   | Y | RFC XXXX |
/// | 0x5A5A           | GREASE                   | Y | RFC XXXX |
/// | 0x6A6A           | GREASE                   | Y | RFC XXXX |
/// | 0x7A7A           | GREASE                   | Y | RFC XXXX |
/// | 0x8A8A           | GREASE                   | Y | RFC XXXX |
/// | 0x9A9A           | GREASE                   | Y | RFC XXXX |
/// | 0xAAAA           | GREASE                   | Y | RFC XXXX |
/// | 0xBABA           | GREASE                   | Y | RFC XXXX |
/// | 0xCACA           | GREASE                   | Y | RFC XXXX |
/// | 0xDADA           | GREASE                   | Y | RFC XXXX |
/// | 0xEAEA           | GREASE                   | Y | RFC XXXX |
/// | 0xF000  - 0xFFFF | Reserved for Private Use | - | RFC XXXX |
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CredentialType {
    /// A [`BasicCredential`]
    Basic,
    /// An X.509 [`Certificate`]
    X509,
    /// A currently unknown credential.
    Unknown(u16),
}

impl tls_codec::Size for CredentialType {
    fn tls_serialized_len(&self) -> usize {
        2
    }
}

impl tls_codec::Deserialize for CredentialType {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
        where
            Self: Sized,
    {
        let mut extension_type = [0u8; 2];
        bytes.read_exact(&mut extension_type)?;

        Ok(CredentialType::from(u16::from_be_bytes(extension_type)))
    }
}

impl tls_codec::Serialize for CredentialType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        writer.write_all(&u16::from(*self).to_be_bytes())?;

        Ok(2)
    }
}

impl From<u16> for CredentialType {
    fn from(value: u16) -> Self {
        match value {
            1 => CredentialType::Basic,
            2 => CredentialType::X509,
            unknown => CredentialType::Unknown(unknown),
        }
    }
}

impl From<CredentialType> for u16 {
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::Basic => 1,
            CredentialType::X509 => 2,
            CredentialType::Unknown(unknown) => unknown,
        }
    }
}

/// X.509 Certificate.
///
/// This struct contains an X.509 certificate chain.  Note that X.509
/// certificates are not yet supported by OpenMLS.
///
/// ```c
/// struct {
///     opaque cert_data<V>;
/// } Certificate;
/// ```
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Certificate {
    // TLS transient
    pub identity: Vec<u8>,
    pub certificates: Vec<VLBytes>,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = String::from_utf8(self.identity.clone()).unwrap_or_default();
        let x509 = if let Some(ee) = self.certificates.first() {
            let process = std::process::Command::new("openssl")
                .args(&["x509", "-text", "-noout"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| std::fmt::Error)?;

            process.stdin.as_ref().ok_or(std::fmt::Error)?
                .write(ee.as_slice()).map_err(|_| std::fmt::Error)?;

            let out = process.wait_with_output().map_err(|_| std::fmt::Error)?.stdout;
            String::from_utf8(out).map_err(|_| std::fmt::Error)?
        } else { "".to_string() };
        write!(f, "id: {id}\nx509: {x509}")?;
        Ok(())
    }
}

impl tls_codec::Size for Certificate {
    fn tls_serialized_len(&self) -> usize {
        self.certificates.tls_serialized_len()
    }
}

impl tls_codec::Serialize for Certificate {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.certificates.tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for Certificate {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
        where
            Self: Sized,
    {
        let certificates = Vec::<Vec<u8>>::tls_deserialize(bytes)?;
        // we should not do this in a deserializer but otherwise we have to deal with a `identity: Option<Vec<u8>>` everywhere
        Certificate::try_new(certificates).map_err(|_| tls_codec::Error::InvalidInput)
    }
}

impl Certificate {
    pub(crate) fn pki_path(&self) -> Result<PkiPath, CredentialError> {
        self.certificates.iter().try_fold(
            PkiPath::new(),
            |mut acc, cert_data| -> Result<PkiPath, CredentialError> {
                acc.push(x509_cert::Certificate::from_der(cert_data.as_slice())?);
                Ok(acc)
            },
        )
    }

    fn try_new(certificates: Vec<Vec<u8>>) -> Result<Self, CredentialError> {
        let leaf = certificates
            .first()
            .ok_or(CredentialError::InvalidCertificateChain)?;
        let leaf = x509_cert::Certificate::from_der(leaf)?;
        let identity = leaf
            .identity()
            .map_err(|_| CredentialError::InvalidCertificateChain)?;
        Ok(Self {
            identity,
            certificates: certificates.into_iter().map(|c| c.into()).collect(),
        })
    }
}

/// MlsCredentialType.
///
/// This enum contains variants containing the different available credentials.
#[derive(
Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
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
///
/// ```c
/// struct {
///     CredentialType credential_type;
///     select (Credential.credential_type) {
///         case basic:
///             opaque identity<V>;
///
///         case x509:
///             Certificate chain<V>;
///     };
/// } Credential;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub(crate) credential_type: CredentialType,
    credential: MlsCredentialType,
}

impl Credential {
    /// Returns the credential type.
    pub fn credential_type(&self) -> CredentialType {
        self.credential_type
    }

    pub fn mls_credential(&self) -> &MlsCredentialType {
        &self.credential
    }

    /// Creates and returns a new basic [`Credential`] for the given identity.
    /// If the credential holds key material, this is generated and stored in
    /// the key store.
    pub fn new_basic(identity: Vec<u8>) -> Self {
        Self {
            credential_type: CredentialType::Basic,
            credential: MlsCredentialType::Basic(BasicCredential {
                identity: identity.into(),
            }),
        }
    }

    /// Creates and returns a new X509 [`Credential`] for the given identity.
    /// If the credential holds key material, this is generated and stored in
    /// the key store.
    pub fn new_x509(certificates: Vec<Vec<u8>>) -> Result<Self, CredentialError> {
        Ok(Self {
            credential_type: CredentialType::X509,
            credential: MlsCredentialType::X509(Certificate::try_new(certificates)?),
        })
    }

    /// Returns the identity of a given credential.
    pub fn identity(&self) -> &[u8] {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential.identity.as_slice(),
            MlsCredentialType::X509(cert) => cert.identity.as_slice(),
        }
    }

    pub async fn validate(
        &self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<(), CredentialError> {
        let tmp_certs = if let MlsCredentialType::X509(x509_certs) = &self.credential {
            Some(
                x509_certs
                    .certificates
                    .iter()
                    .map(|bytes| bytes.as_slice())
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };

        let credential_ref = match &self.credential {
            MlsCredentialType::Basic(basic_cred) => {
                openmls_traits::authentication_service::CredentialRef::Basic {
                    identity: basic_cred.identity.as_slice(),
                }
            }

            MlsCredentialType::X509(_) => {
                let credential_ref = openmls_traits::authentication_service::CredentialRef::X509 {
                    certificates: tmp_certs.as_ref().unwrap().as_slice(),
                };
                credential_ref
            }
        };

        let credential_authentication = backend
            .authentication_service()
            .validate_credential(credential_ref)
            .await;

        if !matches!(
            credential_authentication,
            CredentialAuthenticationStatus::Valid | CredentialAuthenticationStatus::Expired
        ) {
            return Err(CredentialError::AuthenticationServiceValidationFailure(
                credential_authentication,
            ));
        }

        drop(tmp_certs);

        Ok(())
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
/// A `BasicCredential` as defined in the MLS protocol spec. It exposes only an
/// `identity` to represent the client.
///
/// Note that this credential does not contain any key material or any other
/// information.
///
/// OpenMLS provides an implementation of signature keys for convenience in the
/// `openmls_basic_credential` crate.
#[derive(
Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct BasicCredential {
    identity: VLBytes,
}

impl std::fmt::Debug for BasicCredential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", std::str::from_utf8(self.identity.as_slice()).unwrap_or_default())
    }
}

#[derive(Debug, Clone)]
/// A wrapper around a credential with a corresponding public key.
pub struct CredentialWithKey {
    /// The [`Credential`].
    pub credential: Credential,
    /// The corresponding public key as [`SignaturePublicKey`].
    pub signature_key: SignaturePublicKey,
}

#[cfg(test)]
impl CredentialWithKey {
    pub fn from_parts(credential: Credential, key: &[u8]) -> Self {
        Self {
            credential,
            signature_key: key.into(),
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::{random::OpenMlsRand, types::SignatureScheme, OpenMlsCryptoProvider};

    use super::{Credential, CredentialType, CredentialWithKey};

    /// Convenience function that generates a new credential and a key pair for
    /// it (using the x509 credential crate).
    /// The signature keys are stored in the key store.
    ///
    /// Returns the [`Credential`] and the [`SignatureKeyPair`].
    pub async fn new_x509_credential(
        backend: &impl OpenMlsCryptoProvider,
        identity: &[u8],
        signature_scheme: SignatureScheme,
        cert_data: Vec<Vec<u8>>,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        build_credential(
            backend,
            identity,
            CredentialType::X509,
            signature_scheme,
            Some(cert_data),
        )
            .await
    }

    /// Convenience function that generates a new credential and a key pair for
    /// it (using the basic credential crate).
    /// The signature keys are stored in the key store.
    ///
    /// Returns the [`Credential`] and the [`SignatureKeyPair`].
    pub async fn new_credential(
        backend: &impl OpenMlsCryptoProvider,
        identity: &[u8],
        signature_scheme: SignatureScheme,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        build_credential(
            backend,
            identity,
            CredentialType::Basic,
            signature_scheme,
            None,
        )
            .await
    }

    async fn build_credential(
        backend: &impl OpenMlsCryptoProvider,
        identity: &[u8],
        credential_type: CredentialType,
        signature_scheme: SignatureScheme,
        cert_data: Option<Vec<Vec<u8>>>,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let credential = match credential_type {
            CredentialType::Basic => Credential::new_basic(identity.into()),
            CredentialType::X509 => Credential::new_x509(cert_data.unwrap()).unwrap(),
            CredentialType::Unknown(_) => unimplemented!(),
        };
        let signature_keys = SignatureKeyPair::new(
            signature_scheme,
            &mut *backend.rand().borrow_rand().unwrap(),
        )
            .unwrap();
        signature_keys.store(backend.key_store()).await.unwrap();

        (
            CredentialWithKey {
                credential,
                signature_key: signature_keys.public().into(),
            },
            signature_keys,
        )
    }
}
