use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::VLBytes;
use x509_cert::der::Decode;

use openmls_x509_credential::X509Ext;

use crate::prelude::CredentialError;

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
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Certificate {
    // TLS transient
    pub identity: Vec<u8>,
    pub certificates: Vec<VLBytes>,
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
    pub fn try_new(certificates: Vec<Vec<u8>>) -> Result<Self, CredentialError> {
        let end_entity = certificates
            .get(0)
            .ok_or(CredentialError::InvalidCertificateChain)?;
        let end_entity = x509_cert::Certificate::from_der(end_entity)?;
        let identity = end_entity
            .identity()
            .map_err(|_| CredentialError::InvalidCertificateChain)?;
        Ok(Self {
            identity,
            certificates: certificates.into_iter().map(|c| c.into()).collect(),
        })
    }

    fn get_end_entity(&self) -> Result<&[u8], CredentialError> {
        self.certificates
            .first()
            .map(VLBytes::as_slice)
            .ok_or(CredentialError::InvalidCertificateChain)
    }

    fn get_intermediates(&self) -> Result<Vec<&[u8]>, CredentialError> {
        if self.certificates.len() < 2 {
            return Err(CredentialError::InvalidCertificateChain);
        }
        let intermediates = self.certificates.as_slice()[1..]
            .iter()
            .map(VLBytes::as_slice)
            .collect::<Vec<_>>();
        Ok(intermediates)
    }

    pub fn verify(&self) -> Result<(), CredentialError> {
        let mut verifier = rustls_platform_verifier::WireClientVerifier::new();

        let end_entity = self.get_end_entity()?;
        let intermediates = self.get_intermediates()?;

        let options = rustls_platform_verifier::VerifyOptions::try_new(true, &[])?;

        use rustls_platform_verifier::WireVerifier as _;
        verifier.verify_client_cert(&end_entity, intermediates.as_slice(), options)?;

        Ok(())
    }
}
