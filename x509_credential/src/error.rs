use openmls_traits::types::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    #[error(transparent)]
    VerificationError(#[from] rustls_platform_verifier::WireX509Error),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
    #[error("Certificate chain is not long enough")]
    IncompleteCertificateChain,
    #[error("Certificate chain is invalid")]
    InvalidCertificateChain,
}
