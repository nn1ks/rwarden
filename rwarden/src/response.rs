//! Module for responses returned from the Bitwarden API.

use serde::{de, Deserialize, Deserializer};
use std::{collections::HashMap, fmt};
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
    two_factor_providers: Option<ErrorTwoFactorProviderMap>,
}

impl From<InnerError> for Error {
    fn from(value: InnerError) -> Self {
        if let Some(two_factor_providers) = value.two_factor_providers {
            return Self::TwoFactorRequired {
                two_factor_providers: two_factor_providers.0,
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
        two_factor_providers: Vec<ErrorTwoFactorProvider>,
    },
    /// An unknown error occurred.
    #[error("Unknown error: {}", .message)]
    Other {
        message: String,
        validation_errors: HashMap<String, Vec<String>>,
    },
}

/// Provider for two factor authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorTwoFactorProvider {
    Authenticator,
    Email {
        email: String,
    },
    Duo {
        host: String,
        signature: String,
    },
    YubiKey {
        nfc: bool,
    },
    U2f {
        challenges: Vec<ErrorTwoFactorProviderU2fChallenge>,
    },
    WebAuthn,
}

impl From<&ErrorTwoFactorProvider> for crate::TwoFactorProvider {
    fn from(value: &ErrorTwoFactorProvider) -> Self {
        match value {
            ErrorTwoFactorProvider::Authenticator => Self::Authenticator,
            ErrorTwoFactorProvider::Email { .. } => Self::Email,
            ErrorTwoFactorProvider::Duo { .. } => Self::Duo,
            ErrorTwoFactorProvider::YubiKey { .. } => Self::YubiKey,
            ErrorTwoFactorProvider::U2f { .. } => Self::U2f,
            ErrorTwoFactorProvider::WebAuthn => Self::WebAuthn,
        }
    }
}

impl From<ErrorTwoFactorProvider> for crate::TwoFactorProvider {
    fn from(value: ErrorTwoFactorProvider) -> Self {
        Self::from(&value)
    }
}

struct ErrorTwoFactorProviderMap(Vec<ErrorTwoFactorProvider>);

impl<'de> Deserialize<'de> for ErrorTwoFactorProviderMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ErrorTwoFactorProviderMap;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("two factor provider map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut providers = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(key) = map.next_key::<&str>()? {
                    let provider = match key {
                        "0" => {
                            let _value = map.next_value::<serde_json::Value>()?;
                            ErrorTwoFactorProvider::Authenticator
                        }
                        "1" => {
                            #[derive(Deserialize)]
                            #[serde(rename_all = "PascalCase")]
                            struct Response {
                                email: String,
                            }
                            let value = map.next_value::<Response>()?;
                            ErrorTwoFactorProvider::Email { email: value.email }
                        }
                        "2" => {
                            #[derive(Deserialize)]
                            #[serde(rename_all = "PascalCase")]
                            struct Response {
                                host: String,
                                signature: String,
                            }
                            let value = map.next_value::<Response>()?;
                            ErrorTwoFactorProvider::Duo {
                                host: value.host,
                                signature: value.signature,
                            }
                        }
                        "3" => {
                            #[derive(Deserialize)]
                            #[serde(rename_all = "PascalCase")]
                            struct Response {
                                nfc: bool,
                            }
                            let value = map.next_value::<Response>()?;
                            ErrorTwoFactorProvider::YubiKey { nfc: value.nfc }
                        }
                        "4" => {
                            #[derive(Deserialize)]
                            #[serde(rename_all = "PascalCase")]
                            struct Response {
                                challenges: Vec<ErrorTwoFactorProviderU2fChallenge>,
                            }
                            let value = map.next_value::<Response>()?;
                            ErrorTwoFactorProvider::U2f {
                                challenges: value.challenges,
                            }
                        }
                        "7" => ErrorTwoFactorProvider::WebAuthn,
                        _ => {
                            return Err(de::Error::invalid_value(
                                de::Unexpected::Str(key),
                                &"a valid two factor provider id",
                            ))
                        }
                    };
                    providers.push(provider);
                }
                Ok(ErrorTwoFactorProviderMap(providers))
            }
        }

        deserializer.deserialize_map(Visitor)
    }
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
