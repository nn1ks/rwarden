use crate::{crypto, response};
use std::{error::Error as StdError, fmt};
use thiserror::Error as ThisError;

/// Error that can occur while interacting with the Bitwarden API.
#[derive(Debug)]
pub enum Error<TCacheError> {
    /// Failed to send request.
    Request(reqwest::Error),
    /// Failed to decrypt cipher string.
    CipherDecryption(crypto::CipherDecryptionError),
    /// Server returned an error.
    Response(response::Error),
    /// Failed to read or write cache.
    Cache(TCacheError),
}

impl<TCacheError> fmt::Display for Error<TCacheError> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(_) => f.write_str("failed to send request"),
            Self::CipherDecryption(_) => f.write_str("failed to decrypt cipher string"),
            Self::Response(_) => f.write_str("server returned an error"),
            Self::Cache(_) => f.write_str("failed to read or write cache"),
        }
    }
}

impl<TCacheError: StdError + 'static> StdError for Error<TCacheError> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(match self {
            Self::Request(e) => e,
            Self::CipherDecryption(e) => e,
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

impl<TCacheError> From<crypto::CipherDecryptionError> for Error<TCacheError> {
    fn from(error: crypto::CipherDecryptionError) -> Self {
        Self::CipherDecryption(error)
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
    /// Failed to decrypt cipher string.
    #[error("failed to decrypt cipher string")]
    CipherDecryption(#[from] crypto::CipherDecryptionError),
    /// Server returned an error.
    #[error("server returned an error")]
    Response(#[from] response::Error),
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
