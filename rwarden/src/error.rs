use crate::crypto::{symmetric_encryption, SymmetricKeyError};
use crate::response;
use std::{error::Error as StdError, fmt};
use thiserror::Error as ThisError;

/// Error that can occur while interacting with the Bitwarden API.
#[derive(Debug)]
pub enum Error<TCacheError> {
    /// Failed to send request.
    Request(reqwest::Error),
    /// Server returned an error.
    Response(response::Error),
    /// Failed to read or write cache.
    Cache(TCacheError),
}

impl<TCacheError> fmt::Display for Error<TCacheError> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(_) => f.write_str("failed to send request"),
            Self::Response(_) => f.write_str("server returned an error"),
            Self::Cache(_) => f.write_str("failed to read or write cache"),
        }
    }
}

impl<TCacheError: StdError + 'static> StdError for Error<TCacheError> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(match self {
            Self::Request(e) => e,
            Self::Response(e) => e,
            Self::Cache(e) => e,
        })
    }
}

impl<TCacheError> From<reqwest::Error> for Error<TCacheError> {
    fn from(error: reqwest::Error) -> Self {
        Self::Request(error)
    }
}

impl<TCacheError> From<response::Error> for Error<TCacheError> {
    fn from(error: response::Error) -> Self {
        Self::Response(error)
    }
}

/// Error that can occur when logging in.
#[derive(Debug, ThisError)]
pub enum LoginError {
    /// Request error.
    #[error("request error")]
    Request(#[from] reqwest::Error),
    /// Server returned an error.
    #[error("server returned an error")]
    Response(#[from] response::Error),
    /// Failed to create symmetric key.
    #[error("failed to create symmetric key")]
    CreateSymmetricKey(#[from] SymmetricKeyError),
    /// Two factor authentication is required.
    #[error("two factor authentication is required")]
    TwoFactorRequired {
        two_factor_providers: Vec<response::TwoFactorProvider>,
    },
}

/// Error type for requests and server responses.
#[derive(Debug, ThisError)]
pub enum RequestResponseError {
    /// Failed to send request.
    #[error("failed to send request")]
    Request(#[from] reqwest::Error),
    /// Server returned an error.
    #[error("server returned an error")]
    Response(#[from] response::Error),
}

impl<TCacheError> From<RequestResponseError> for Error<TCacheError> {
    fn from(error: RequestResponseError) -> Self {
        match error {
            RequestResponseError::Request(e) => Self::Request(e),
            RequestResponseError::Response(e) => Self::Response(e),
        }
    }
}

#[derive(Debug, ThisError)]
pub enum PrivateKeyError {
    #[error("failed to create symmetric key")]
    SymmetricKey(#[from] SymmetricKeyError),
    #[error("failed to decrypt private key")]
    Decryption(#[from] symmetric_encryption::DecryptionError),
    #[error("failed to parse private key")]
    Parse(#[from] rsa::pkcs8::Error),
    #[error("private key is not available")]
    NotAvailable,
}
