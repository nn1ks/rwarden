//! Module for responses returned from the Bitwarden API.

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use thiserror::Error;

/// An error returned from the Bitwarden API.
#[derive(Debug, Clone, PartialEq, Eq, Error, Deserialize)]
#[serde(untagged)]
pub enum Error {
    /// Two factor authentication is required.
    #[error("Two factor authentication is required")]
    TwoFactorRequired {
        #[serde(rename = "TwoFactorProviders2")]
        two_factor_providers: HashMap<i32, ErrorTwoFactorProvider>,
    },
    /// An unknown error occurred.
    #[error("Unknown error: {}", .message)]
    #[serde(deserialize_with = "deserialize_unknown_error")]
    Other {
        message: String,
        validation_errors: HashMap<String, Vec<String>>,
    },
}

#[allow(clippy::type_complexity)]
fn deserialize_unknown_error<'de, D>(
    deserializer: D,
) -> Result<(String, HashMap<String, Vec<String>>), D::Error>
where
    D: Deserializer<'de>,
{
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
    }
    let inner = InnerError::deserialize(deserializer)?;
    let message = match inner.error_model {
        Some(v) if !v.message.is_empty() => v.message,
        _ => inner.message.unwrap_or_default(),
    };
    Ok((message, inner.validation_errors.unwrap_or_default()))
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
