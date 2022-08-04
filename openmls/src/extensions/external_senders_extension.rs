use super::{Deserialize, Serialize};
use crate::{
    credentials::Credential,
    prelude::SignaturePublicKey
};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, TlsVecU16};


/// # External Senders
///
/// Allows declaring clients allowed to create external proposals.
/// Clients are ([`ExternalSender`])
#[derive(PartialEq, Clone, Debug, Default, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ExternalSendersExtension {
    /// [Credential] of the senders allowed to send external proposals
    pub senders: TlsVecU16<ExternalSender>,
}

/// A client not in a MLS group allowed to create external proposals for a group
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ExternalSender {
    /// Sender's credential
    pub credential: Credential,
    /// Sender's public signature key
    pub signature_key: SignaturePublicKey,
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
