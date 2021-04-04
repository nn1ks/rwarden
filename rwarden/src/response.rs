//! Module for responses returned from the Bitwarden API.

use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InnerErrorModel {
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InnerError {
    message: Option<String>,
    validation_errors: Option<HashMap<String, Vec<String>>>,
    error_model: Option<InnerErrorModel>,
    #[serde(rename = "TwoFactorProviders2")]
    two_factor_providers: Option<HashMap<i32, ErrorTwoFactorProvider>>,
}

impl From<InnerError> for Error {
    fn from(value: InnerError) -> Self {
        if let Some(two_factor_providers) = value.two_factor_providers {
            return Self::TwoFactorRequired {
                two_factor_providers,
            };
        }
        Self::Other {
            message: match value.error_model {
                Some(v) if !v.message.is_empty() => v.message,
                _ => value.message.unwrap_or_default(),
            },
            validation_errors: value.validation_errors.unwrap_or_default(),
        }
    }
}

/// An error returned from the Bitwarden API.
#[derive(Debug, Clone, PartialEq, Eq, Error, Deserialize)]
#[serde(from = "InnerError")]
pub enum Error {
    /// Two factor authentication is required.
    #[error("Two factor authentication is required")]
    TwoFactorRequired {
        two_factor_providers: HashMap<i32, ErrorTwoFactorProvider>,
    },
    /// An unknown error occurred.
    #[error("Unknown error: {}", .message)]
    Other {
        message: String,
        validation_errors: HashMap<String, Vec<String>>,
    },
}

/// Provider for two factor authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(untagged)]
pub enum ErrorTwoFactorProvider {
    #[serde(rename_all = "PascalCase")]
    Email { email: String },
    #[serde(rename_all = "PascalCase")]
    U2f {
        challenges: Vec<ErrorTwoFactorProviderU2fChallenge>,
    },
    #[serde(rename_all = "PascalCase")]
    Duo { host: String, signature: String },
    #[serde(rename_all = "PascalCase")]
    Yubikey { nfc: bool },
}

/// Challenge of U2f two factor authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorTwoFactorProviderU2fChallenge {
    pub app_id: String,
    pub challenge: String,
    pub version: String,
    pub key_handle: Option<String>,
}
