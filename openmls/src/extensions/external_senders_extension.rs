use std::io::Read;

use openmls_traits::types::SignatureScheme;
use tls_codec::{Error, TlsByteVecU16, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU16};

use crate::prelude::{BasicCredential, CredentialType, MlsCredentialType};
use crate::{credentials::Credential, prelude::SignaturePublicKey};

use super::{Deserialize, Serialize};

/// # External Senders
///
/// Allows declaring clients allowed to create external proposals.
/// Clients are ([`ExternalSender`])
#[derive(
    PartialEq, Clone, Debug, Default, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ExternalSendersExtension {
    /// [Credential] of the senders allowed to send external proposals
    pub senders: TlsVecU16<ExternalSender>,
}

/// A client not in a MLS group allowed to create external proposals for a group
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct ExternalSender {
    /// Sender's credential
    pub credential: Credential,
    /// Sender's public signature key
    pub signature_key: SignaturePublicKey,
}

impl tls_codec::Deserialize for ExternalSender {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let credential: Credential = Credential::tls_deserialize(bytes)?.into();
        let public_key_bytes = TlsByteVecU16::tls_deserialize(bytes)?;
        let signature_scheme = credential.signature_scheme().map_err(|_| Error::DecodingError("Could not extract signature scheme from credential while deserializing external sender".to_string()))?;
        let signature_key = SignaturePublicKey::new(public_key_bytes.into(), signature_scheme)
            .map_err(|e| {
                Error::DecodingError(format!("Error deserializing signature public key {:?}", e))
            })?;
        Ok(Self {
            credential,
            signature_key,
        })
    }
}

#[cfg(test)]
impl From<Credential> for ExternalSender {
    fn from(credential: Credential) -> Self {
        Self {
            signature_key: credential.signature_key().clone(),
            credential,
        }
    }
}

impl ExternalSender {
    /// temporary solution for building an [`ExternalSender`] given a public key
    /// TODO: remove as soon as a certificate is available
    pub fn new_basic(identity: &str, signature_key: SignaturePublicKey) -> Self {
        let credential = BasicCredential {
            identity: identity.as_bytes().into(),
            signature_scheme: SignatureScheme::ED25519,
            public_key: signature_key.clone(),
        };
        let credential = Credential {
            credential_type: CredentialType::Basic,
            credential: MlsCredentialType::Basic(credential),
        };
        Self {
            signature_key,
            credential,
        }
    }
}

impl<const N: usize> From<&[ExternalSender; N]> for ExternalSendersExtension {
    fn from(external_senders: &[ExternalSender; N]) -> Self {
        Self {
            senders: TlsVecU16::from_slice(external_senders),
        }
    }
}

impl From<&[ExternalSender]> for ExternalSendersExtension {
    fn from(external_senders: &[ExternalSender]) -> Self {
        Self {
            senders: TlsVecU16::from_slice(external_senders),
        }
    }
}

impl From<ExternalSender> for ExternalSendersExtension {
    fn from(external_senders: ExternalSender) -> Self {
        Self::from(&[external_senders])
    }
}
