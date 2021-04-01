use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::{collections::HashMap, fmt};
use thiserror::Error as ThisError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    InvalidGrant,
}

/// An error that was returned by the Bitwarden API.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ThisError)]
pub struct Error {
    ty: ErrorType,
    description: String,
    // TODO: Add more fields
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl<'de> Deserialize<'de> for Error {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ErrorVisitor;

        impl<'de> Visitor<'de> for ErrorVisitor {
            type Value = Error;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("struct Duration")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut ty = None;
                let mut description = None;
                let mut other_fields = HashMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "error" => {
                            if ty.is_some() {
                                return Err(de::Error::duplicate_field("error"));
                            }
                            ty = Some(map.next_value()?);
                        }
                        "error_description" => {
                            if description.is_some() {
                                return Err(de::Error::duplicate_field("error_description"));
                            }
                            description = Some(map.next_value()?);
                        }
                        _ => {
                            other_fields.insert(key, map.next_value()?);
                        }
                    }
                }
                let ty = ty.ok_or_else(|| de::Error::missing_field("error"))?;
                let description =
                    description.ok_or_else(|| de::Error::missing_field("error_description"))?;
                Ok(Error { ty, description })
            }
        }

        const FIELDS: &[&str] = &["error", "error_description"];
        deserializer.deserialize_struct("Error", FIELDS, ErrorVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TwoFactor {
    #[serde(rename = "TwoFactorProviders2")]
    pub two_factor_providers: HashMap<String, TwoFactorProvider>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub enum TwoFactorProvider {
    Email(String),
}
