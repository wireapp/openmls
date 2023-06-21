use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::credentials::{errors::CredentialError, CredentialType};

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
    credential_type: CredentialType,
    certificate_chain: Vec<Vec<u8>>,
}

/// Extension data for the anchors
pub type PerDomainTrustAnchorsExtension = Vec<PerDomainTrustAnchor>;

impl PerDomainTrustAnchor {
    /// Creates a new instance of a `PerDomainTrustAnchor`
    pub fn new(
        domain_name: Vec<u8>,
        credential_type: CredentialType,
        certificate_chain: Vec<Vec<u8>>,
    ) -> Result<Self, CredentialError> {
        match credential_type {
            CredentialType::X509 => Ok(Self {
                domain_name,
                credential_type,
                certificate_chain,
            }),
            CredentialType::Basic | CredentialType::Unknown(_) => {
                Err(CredentialError::UnsupportedCredentialType)
            }
        }
    }

    pub fn domain_name(&self) -> &[u8] {
        self.domain_name.as_ref()
    }

    pub fn credential_type(&self) -> CredentialType {
        self.credential_type
    }

    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        self.certificate_chain.as_ref()
    }
}
