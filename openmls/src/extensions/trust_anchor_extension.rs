use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::credentials::{errors::CredentialError, MlsCredentialType};

/// Each `PerDomainTrustAnchor` represents a specific identity domain which is expected
/// and authorized to participate in the MLS group. It contains the domain name and
/// the specific trust anchor used to validate identities for members in that domain.
/// ```c
/// // draft-mahy-mls-group-anchors-00
/// struct {
///     opaque domain_name<V>;
///     CredentialType credential_type;
///     select (Credential.credential_type) {
///         case x509:
///             Certificate chain<V>;
///     };
/// } PerDomainTrustAnchor;
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct PerDomainTrustAnchor {
    domain_name: Vec<u8>,
    credential_type: AnchorCredentialType,
}

/// Extension data for the anchors
pub type PerDomainTrustAnchorsExtension = Vec<PerDomainTrustAnchor>;

impl PerDomainTrustAnchor {
    /// Creates a new instance of a `PerDomainTrustAnchor`
    pub fn new(domain_name: Vec<u8>, credential_type: AnchorCredentialType) -> Self {
        Self {
            domain_name,
            credential_type,
        }
    }
}

/// Defines the type of cretential for the domain trust anchor.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct AnchorCredentialType(MlsCredentialType);

impl AnchorCredentialType {
    /// Creates a new instance of `AnchorCredentialType`. Returns an error if the the credential
    /// type is not supported
    pub fn new(credential_type: MlsCredentialType) -> Result<Self, CredentialError> {
        Self::try_from(credential_type)
    }
}

impl TryFrom<MlsCredentialType> for AnchorCredentialType {
    type Error = CredentialError;

    fn try_from(value: MlsCredentialType) -> Result<Self, Self::Error> {
        if matches!(value, MlsCredentialType::Basic(_)) {
            return Err(CredentialError::UnsupportedCredentialType);
        }
        Ok(Self(value))
    }
}
