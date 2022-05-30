use std::io::Read;

use openmls_traits::types::SignatureScheme;
use tls_codec::TlsByteVecU16;

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
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => {
                let written = CredentialType::Basic.tls_serialize(writer)?;
                basic_credential.tls_serialize(writer).map(|l| l + written)
            }
            MlsCredentialType::X509(certificate) => {
                let written = CredentialType::X509.tls_serialize(writer)?;
                certificate.tls_serialize(writer).map(|l| l + written)
            }
        }
    }
}

impl tls_codec::Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let val = u16::tls_deserialize(bytes)?;
        let credential_type =
            CredentialType::try_from(val).map_err(|e| Error::DecodingError(e.to_string()))?;
        match credential_type {
            CredentialType::Basic => Ok(Credential::from(MlsCredentialType::Basic(
                BasicCredential::tls_deserialize(bytes)?,
            ))),
            CredentialType::X509 => Ok(Credential::from(MlsCredentialType::X509(
                Certificate::tls_deserialize(bytes)?,
            ))),
        }
    }
}

impl tls_codec::Deserialize for BasicCredential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let identity = TlsByteVecU16::tls_deserialize(bytes)?;
        let signature_scheme = SignatureScheme::tls_deserialize(bytes)?;
        let public_key_bytes = TlsByteVecU16::tls_deserialize(bytes)?;
        let public_key = SignaturePublicKey::new(public_key_bytes.into(), signature_scheme)
            .map_err(|e| {
                Error::DecodingError(format!("Error creating signature public key {:?}", e))
            })?;
        Ok(BasicCredential {
            identity,
            signature_scheme,
            public_key,
        })
    }
}
