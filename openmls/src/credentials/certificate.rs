use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::{Error, VLBytes};
use x509_cert::{der::Decode, PkiPath};

use crate::ciphersuite::Signature;
use openmls_x509_credential::X509Ext;

use crate::prelude::{CredentialError, Verifiable};

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
    pub(crate) fn pki_path(&self) -> Result<PkiPath, CredentialError> {
        self.certificates.iter().try_fold(
            PkiPath::new(),
            |mut acc, cert_data| -> Result<PkiPath, CredentialError> {
                acc.push(x509_cert::Certificate::from_der(cert_data.as_slice())?);
                Ok(acc)
            },
        )
    }

    pub fn try_new(certificates: Vec<Vec<u8>>) -> Result<Self, CredentialError> {
        let leaf = certificates
            .get(0)
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
