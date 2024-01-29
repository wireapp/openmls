//! Credential errors
//!
//! This module exposes [`CredentialError`].

use crate::error::LibraryError;
use openmls_traits::authentication_service::CredentialAuthenticationStatus;
use thiserror::Error;

/// An error that occurs in methods of a [`super::Credential`].
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CredentialError {
    /// A library error occurred.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The type of credential is not supported.
    #[error("Unsupported credential type.")]
    UnsupportedCredentialType,
    /// Verifying the signature with this credential failed.
    #[error("Invalid signature.")]
    InvalidSignature,
    /// Incomplete x509 certificate chain
    #[error("x509 certificate chain is empty")]
    IncompleteCertificateChain,
    /// Failed to decode certificate data
    #[error("Failed to decode certificate data: {0}")]
    CertificateDecodingError(#[from] x509_cert::der::Error),
    /// x509 certificate chain is either unordered or a child is missigned by its issuer
    #[error("Invalid x509 certificate chain.")]
    InvalidCertificateChain,
    #[error("The Authentication Service callback rejected this credential for the following reason: {0}")]
    AuthenticationServiceValidationFailure(CredentialAuthenticationStatus),
}
