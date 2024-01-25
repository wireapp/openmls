use std::io::Read;

use super::*;

impl tls_codec::Size for Credential {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.credential_type.tls_serialized_len()
            + match &self.credential {
                MlsCredentialType::Basic(c) => c.tls_serialized_len(),
                MlsCredentialType::X509(c) => c.tls_serialized_len(),
            }
    }
}

impl tls_codec::Serialize for Credential {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => {
                let written = CredentialType::Basic.tls_serialize(writer)?;
                basic_credential.tls_serialize(writer).map(|l| l + written)
            }
            // TODO #134: implement encoding for X509 certificates
            MlsCredentialType::X509(credential) => {
                let written = CredentialType::X509.tls_serialize(writer)?;
                credential.tls_serialize(writer).map(|l| l + written)
            }
        }
    }
}

impl tls_codec::Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let val = u16::tls_deserialize(bytes)?;
        let credential_type = CredentialType::from(val);
        match credential_type {
            CredentialType::Basic => Ok(Credential::from(MlsCredentialType::Basic(
                BasicCredential::tls_deserialize(bytes)?,
            ))),
            CredentialType::X509 => Ok(Credential::from(MlsCredentialType::X509(
                Certificate::tls_deserialize(bytes)?,
            ))),
            _ => Err(tls_codec::Error::DecodingError(format!(
                "{credential_type:?} can not be deserialized."
            ))),
        }
    }
}
