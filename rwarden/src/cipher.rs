//! Module for cipher resources.

use crate::crypto::{SymmetricEncryptedBytes, SymmetricEncryptedString};
use crate::util;
use chrono::{DateTime, FixedOffset};
use derive_setters::Setters;
use serde::{de, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr as DeserializeRepr, Serialize_repr as SerializeRepr};
use std::collections::HashMap;
use uuid::Uuid;

pub use request::*;

mod request;

/// The type of a custom field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, DeserializeRepr, SerializeRepr)]
#[repr(u8)]
pub enum FieldType {
    Text = 0,
    Hidden = 1,
    Boolean = 2,
}

/// A custom field of a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Field {
    /// The type of the field.
    #[serde(rename = "Type")]
    pub ty: FieldType,
    /// The name of the field.
    pub name: Option<SymmetricEncryptedString>,
    /// The value of the field.
    pub value: Option<SymmetricEncryptedString>,
}

/// Entry in the password history.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PasswordHistoryEntry {
    /// The password.
    pub password: SymmetricEncryptedString,
    /// The date when the password was last used.
    pub last_used_date: Option<DateTime<FixedOffset>>,
}

/// An attachment of a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AttachmentRequest {
    /// The file name of the attachment.
    pub file_name: SymmetricEncryptedString,
    /// The key of the attachment.
    pub key: SymmetricEncryptedBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Setters, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct RequestModel {
    pub folder_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    #[setters(skip)]
    pub name: SymmetricEncryptedString,
    #[setters(skip)]
    #[serde(flatten)]
    pub ty: Type,
    pub notes: Option<SymmetricEncryptedString>,
    pub fields: Vec<Field>,
    pub favorite: bool,
    pub password_history: Vec<PasswordHistoryEntry>,
    pub attachments: HashMap<Uuid, AttachmentRequest>,
    pub last_known_revision_date: Option<DateTime<FixedOffset>>,
}

impl RequestModel {
    pub fn new(name: SymmetricEncryptedString, ty: Type) -> Self {
        Self {
            folder_id: None,
            organization_id: None,
            name,
            ty,
            notes: None,
            fields: Vec::new(),
            favorite: false,
            password_history: Vec::new(),
            attachments: HashMap::new(),
            last_known_revision_date: None,
        }
    }
}

impl From<Cipher> for RequestModel {
    fn from(cipher: Cipher) -> Self {
        Self {
            folder_id: cipher.folder_id,
            organization_id: cipher.organization_id,
            name: cipher.name,
            ty: cipher.ty,
            notes: cipher.notes,
            fields: cipher.fields,
            favorite: cipher.favorite,
            password_history: cipher.password_history,
            attachments: cipher
                .attachments
                .into_iter()
                .map(|attachment| {
                    (
                        attachment.id,
                        AttachmentRequest {
                            file_name: attachment.file_name,
                            key: attachment.key,
                        },
                    )
                })
                .collect(),
            last_known_revision_date: Some(cipher.revision_date),
        }
    }
}

/// The owner type of a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
pub enum Owner {
    /// The cipher is owned by the user who creates it.
    User,
    /// The cipher is owned by an organization.
    #[serde(rename_all = "PascalCase")]
    Organization {
        /// The IDs of the collections where this cipher will be added.
        collection_ids: Vec<Uuid>,
    },
}

impl Owner {
    pub fn is_user(&self) -> bool {
        match self {
            Self::User => true,
            Self::Organization { .. } => false,
        }
    }

    pub fn is_organization(&self) -> bool {
        match self {
            Self::User => false,
            Self::Organization { .. } => true,
        }
    }
}

/// The type of a cipher.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    Login(Login),
    Card(Card),
    Identity(Identity),
    SecureNote,
}

impl Serialize for Type {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Type", 2)?;
        match self {
            Self::Login(v) => {
                state.serialize_field("Type", &1)?;
                state.serialize_field("Login", &v)?;
            }
            Self::SecureNote => {
                state.serialize_field("Type", &2)?;
                let v = SecureNote {
                    ty: SecureNoteType::Generic,
                };
                state.serialize_field("SecureNote", &v)?;
            }
            Self::Card(v) => {
                state.serialize_field("Type", &3)?;
                state.serialize_field("Card", &v)?;
            }
            Self::Identity(v) => {
                state.serialize_field("Type", &4)?;
                state.serialize_field("Identity", &v)?;
            }
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for Type {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Inner {
            #[serde(rename = "Type")]
            ty: i32,
            login: Option<Login>,
            card: Option<Card>,
            identity: Option<Identity>,
            secure_note: Option<SecureNote>,
        }

        let v = Inner::deserialize(deserializer)?;
        match v.ty {
            1 => {
                let v = v
                    .login
                    .ok_or_else(|| de::Error::custom("Login must not be null"))?;
                Ok(Self::Login(v))
            }
            2 => {
                v.secure_note
                    .ok_or_else(|| de::Error::custom("SecureNote must not be null"))?;
                Ok(Self::SecureNote)
            }
            3 => {
                let v = v
                    .card
                    .ok_or_else(|| de::Error::custom("Card must not be null"))?;
                Ok(Self::Card(v))
            }
            4 => {
                let v = v
                    .identity
                    .ok_or_else(|| de::Error::custom("Identity must not be null"))?;
                Ok(Self::Identity(v))
            }
            _ => Err(de::Error::invalid_value(
                de::Unexpected::Signed(v.ty.into()),
                &"one of `1`, `2`, `3`, or `4`",
            )),
        }
    }
}

// https://github.com/bitwarden/server/blob/v1.40.0/src/Core/Models/Api/CipherLoginModel.cs
/// Login cipher type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Setters, Deserialize, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct Login {
    /// The username of the login cipher.
    pub username: Option<SymmetricEncryptedString>,
    /// The password of the login cipher.
    pub password: Option<SymmetricEncryptedString>,
    /// The authenticator key for the time-based one-time password.
    pub totp: Option<SymmetricEncryptedString>,
    /// The URIs of the login cipher.
    #[serde(deserialize_with = "util::deserialize_optional")]
    pub uris: Vec<LoginUri>,
    /// The revision date of the login cipher.
    pub password_revision_date: Option<DateTime<FixedOffset>>,
}

impl Login {
    /// Creates a new [`Login`].
    pub fn new() -> Self {
        Self::default()
    }
}

/// A URI of a login cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct LoginUri {
    pub uri: SymmetricEncryptedString,
    #[serde(rename = "Match")]
    pub match_type: LoginUriMatchType,
}

impl LoginUri {
    /// Creates a new [`LoginUri`].
    pub fn new(uri: SymmetricEncryptedString, match_type: LoginUriMatchType) -> Self {
        Self { uri, match_type }
    }
}

/// The match type of a URI in a login cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, SerializeRepr)]
#[repr(u8)]
pub enum LoginUriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

/// Card cipher type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Setters, Deserialize, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct Card {
    /// The name of the cardholder.
    pub cardholder_name: Option<SymmetricEncryptedString>,
    /// The brand of the card.
    pub brand: Option<SymmetricEncryptedString>,
    /// The card number.
    pub number: Option<SymmetricEncryptedString>,
    /// The expiration month of the card.
    #[serde(rename = "ExpMonth")]
    pub expiration_month: Option<SymmetricEncryptedString>,
    /// The expiration year of the card.
    #[serde(rename = "ExpYear")]
    pub expiration_year: Option<SymmetricEncryptedString>,
    /// The security code of the card.
    pub code: Option<SymmetricEncryptedString>,
}

/// Identity cipher type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Setters, Deserialize, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct Identity {
    pub title: Option<SymmetricEncryptedString>,
    pub first_name: Option<SymmetricEncryptedString>,
    pub middle_name: Option<SymmetricEncryptedString>,
    pub last_name: Option<SymmetricEncryptedString>,
    pub address_1: Option<SymmetricEncryptedString>,
    pub address_2: Option<SymmetricEncryptedString>,
    pub address_3: Option<SymmetricEncryptedString>,
    pub city: Option<SymmetricEncryptedString>,
    pub state: Option<SymmetricEncryptedString>,
    pub postal_code: Option<SymmetricEncryptedString>,
    pub country: Option<SymmetricEncryptedString>,
    pub company: Option<SymmetricEncryptedString>,
    pub email: Option<SymmetricEncryptedString>,
    pub phone: Option<SymmetricEncryptedString>,
    pub ssn: Option<SymmetricEncryptedString>,
    pub username: Option<SymmetricEncryptedString>,
    pub passport_number: Option<SymmetricEncryptedString>,
    pub license_number: Option<SymmetricEncryptedString>,
}

#[derive(Serialize, Deserialize)]
struct SecureNote {
    #[serde(rename = "Type")]
    ty: SecureNoteType,
}

#[derive(SerializeRepr, DeserializeRepr)]
#[repr(u8)]
enum SecureNoteType {
    Generic = 0,
}

/// An attachment of a cipher.
// NOTE: Serialize is only needed for cache
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Attachment {
    pub id: Uuid,
    pub url: String,
    pub file_name: SymmetricEncryptedString,
    pub key: SymmetricEncryptedBytes,
    pub size: String,
    pub size_name: String,
}

// https://github.com/bitwarden/server/blob/v1.40.0/src/Core/Models/Api/Response/CipherResponseModel.cs
/// A cipher resource.
// NOTE: Serialize is only needed for cache
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Cipher {
    pub id: Uuid,
    pub folder_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub name: SymmetricEncryptedString,
    #[serde(flatten)]
    pub ty: Type,
    pub notes: Option<SymmetricEncryptedString>,
    #[serde(deserialize_with = "util::deserialize_optional")]
    pub fields: Vec<Field>,
    #[serde(deserialize_with = "util::deserialize_optional")]
    pub attachments: Vec<Attachment>,
    pub organization_use_totp: bool,
    #[serde(deserialize_with = "util::deserialize_optional")]
    pub password_history: Vec<PasswordHistoryEntry>,
    pub revision_date: DateTime<FixedOffset>,
    pub deleted_date: Option<DateTime<FixedOffset>>,
    pub favorite: bool,
    pub edit: bool,
    pub view_password: bool,
}

/// A cipher resource with additional information.
// NOTE: Serialize is only needed for cache
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CipherDetails {
    #[serde(flatten)]
    pub inner: Cipher,
    #[serde(deserialize_with = "util::deserialize_optional")]
    pub collection_ids: Vec<Uuid>,
}
