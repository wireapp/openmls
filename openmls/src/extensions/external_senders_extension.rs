use super::{Deserialize, Serialize};
use crate::credentials::Credential;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, TlsVecU16};

/// # External Senders
///
/// Allows declaring clients allowed to create external proposals.
/// Clients a represented by their identity ([`Credential`])
#[derive(
    PartialEq, Clone, Debug, Default, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ExternalSendersExtension {
    /// [Credential] of the senders allowed to send external proposals
    pub senders: TlsVecU16<Credential>,
}

impl<const N: usize> From<&[Credential; N]> for ExternalSendersExtension {
    fn from(credentials: &[Credential; N]) -> Self {
        Self {
            senders: TlsVecU16::from_slice(credentials),
        }
    }
}

impl From<&[Credential]> for ExternalSendersExtension {
    fn from(credentials: &[Credential]) -> Self {
        Self {
            senders: TlsVecU16::from_slice(credentials),
        }
    }
}

impl From<Credential> for ExternalSendersExtension {
    fn from(credential: Credential) -> Self {
        Self::from(&[credential])
    }
}
