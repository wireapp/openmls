//! Credential errors
//!
//! This module exposes [`CredentialError`].

use crate::error::LibraryError;
use thiserror::Error;

/// An error that occurs in methods of a [`super::Credential`].
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialError {
    /// A library error occurred.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// x509 DER decoding error
    #[error(transparent)]
    X509DerError(#[from] x509_cert::der::Error),
    /// The type of credential is not supported.
    #[error("Unsupported credential type.")]
    UnsupportedCredentialType,
    /// The type of cipher is not supported.
    #[error("Unsupported cipher.")]
    UnsupportedSignatureScheme,
    /// Verifying the signature with this credential failed.
    #[error("Invalid signature.")]
    InvalidSignature,
    /// Parsing raw DER x509 certificate failed
    #[error("Invalid x509 certificate format.")]
    // TODO: replace by this when error no longer require Clone and PartialEq
    // InvalidCertificateFormat(#[from] x509_parser::nom::Err<x509_parser::prelude::X509Error>),
    InvalidCertificateFormat,
    /// x509 certificate is expired or not valid yet
    #[error("x509 certificate is expired or not valid yet.")]
    InvalidCertificate,
    /// x509 certificate lacks some fields required by MLS
    #[error("x509 certificate lacks required field {0}.")]
    IncompleteCertificate(&'static str),
    /// Incomplete x509 certificate chain
    #[error("x509 certificate chain is either empty or contains a single self-signed certificate which is not allowed.")]
    IncompleteCertificateChain,
    /// x509 certificate chain is either unordered or a child is missigned by its issuer
    #[error("Invalid x509 certificate chain.")]
    InvalidCertificateChain,
}
