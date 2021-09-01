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
pub(crate) struct InnerError {
    message: Option<String>,
    validation_errors: Option<HashMap<String, Vec<String>>>,
    error_model: Option<InnerErrorModel>,
    #[serde(rename = "TwoFactorProviders2")]
    two_factor_providers: Option<TwoFactorProviderMap>,
}

impl InnerError {
    pub(crate) fn two_factor_providers(&self) -> Option<Vec<TwoFactorProvider>> {
        self.two_factor_providers.clone().map(|v| v.0)
    }
}

impl From<InnerError> for Error {
    fn from(value: InnerError) -> Self {
        Self {
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
#[error("{}", .message)]
pub struct Error {
    message: String,
    validation_errors: HashMap<String, Vec<String>>,
}

/// Provider for two factor authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TwoFactorProvider {
    Authenticator,
    Email { email: String },
    Duo { host: String, signature: String },
    YubiKey { nfc: bool },
    U2f { challenges: Vec<U2fChallenge> },
    WebAuthn,
}

impl From<&TwoFactorProvider> for crate::TwoFactorProvider {
    fn from(value: &TwoFactorProvider) -> Self {
        match value {
            TwoFactorProvider::Authenticator => Self::Authenticator,
            TwoFactorProvider::Email { .. } => Self::Email,
            TwoFactorProvider::Duo { .. } => Self::Duo,
            TwoFactorProvider::YubiKey { .. } => Self::YubiKey,
            TwoFactorProvider::U2f { .. } => Self::U2f,
            TwoFactorProvider::WebAuthn => Self::WebAuthn,
        }
    }
}

impl From<TwoFactorProvider> for crate::TwoFactorProvider {
    fn from(value: TwoFactorProvider) -> Self {
        Self::from(&value)
    }
}

#[derive(Clone)]
struct TwoFactorProviderMap(Vec<TwoFactorProvider>);

impl<'de> Deserialize<'de> for TwoFactorProviderMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = TwoFactorProviderMap;

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
                            TwoFactorProvider::Authenticator
                        }
                        "1" => {
                            #[derive(Deserialize)]
                            #[serde(rename_all = "PascalCase")]
                            struct Response {
                                email: String,
                            }
                            let value = map.next_value::<Response>()?;
                            TwoFactorProvider::Email { email: value.email }
                        }
                        "2" => {
                            #[derive(Deserialize)]
                            #[serde(rename_all = "PascalCase")]
                            struct Response {
                                host: String,
                                signature: String,
                            }
                            let value = map.next_value::<Response>()?;
                            TwoFactorProvider::Duo {
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
                            TwoFactorProvider::YubiKey { nfc: value.nfc }
                        }
                        "4" => {
                            #[derive(Deserialize)]
                            #[serde(rename_all = "PascalCase")]
                            struct Response {
                                challenges: Vec<U2fChallenge>,
                            }
                            let value = map.next_value::<Response>()?;
                            TwoFactorProvider::U2f {
                                challenges: value.challenges,
                            }
                        }
                        "7" => TwoFactorProvider::WebAuthn,
                        _ => {
                            return Err(de::Error::invalid_value(
                                de::Unexpected::Str(key),
                                &"a valid two factor provider id",
                            ))
                        }
                    };
                    providers.push(provider);
                }
                Ok(TwoFactorProviderMap(providers))
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

/// U2F challenge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fChallenge {
    pub app_id: String,
    pub challenge: String,
    pub version: String,
    pub key_handle: Option<String>,
}
