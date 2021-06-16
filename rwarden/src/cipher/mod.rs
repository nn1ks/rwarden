//! Module for cipher resources.

#![allow(clippy::needless_update)] // The `Setters` derive macro causes this clippy warning

use crate::{util, BulkRestore, CipherString, Get, GetAll, ResponseExt, Restore, Session};
use async_trait::async_trait;
use chrono::{DateTime, FixedOffset};
use derive_setters::Setters;
use reqwest::Method;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use serde_repr::{Deserialize_repr as DeserializeRepr, Serialize_repr as SerializeRepr};
use std::collections::HashMap;
use uuid::Uuid;

pub use create::Creator;
pub use delete::{BulkDeleter, Deleter};
pub use import::{
    AccountImporter, AccountImporterEntry, OrganizationImporter, OrganizationImporterEntry,
};
pub use modify::{CollectionModifier, Modifier, PartialModifier};
pub use purge::Purger;
pub use r#move::BulkMover;
pub use share::{BulkSharer, Sharer};

mod create;
mod delete;
mod import;
mod modify;
mod r#move;
mod purge;
mod share;

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
    pub name: Option<CipherString>,
    /// The value of the field.
    pub value: Option<CipherString>,
}

/// Entry in the password history.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PasswordHistoryEntry {
    /// The password.
    pub password: CipherString,
    /// The date when the password was last used.
    pub last_used_date: Option<DateTime<FixedOffset>>,
}

/// An attachment of a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Attachment {
    /// The file name of the attachment.
    pub file_name: CipherString,
    /// The key of the attachment.
    pub key: CipherString,
}

#[derive(Debug, Clone, PartialEq, Eq, Setters, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct RequestModel {
    pub folder_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    #[setters(skip)]
    pub name: CipherString,
    #[setters(skip)]
    #[serde(flatten)]
    pub ty: Type,
    pub notes: Option<CipherString>,
    pub fields: Vec<Field>,
    #[setters(bool)]
    pub favorite: bool,
    pub password_history: Vec<PasswordHistoryEntry>,
    pub attachments: HashMap<String, Attachment>,
    pub last_known_revision_date: Option<DateTime<FixedOffset>>,
}

impl RequestModel {
    pub fn new(name: CipherString, ty: Type) -> Self {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestModelWithId {
    #[serde(flatten)]
    pub inner: RequestModel,
    pub id: Uuid,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Folder {
    pub name: CipherString,
}

impl Folder {
    pub fn new(name: CipherString) -> Self {
        Self { name }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GroupSelection {
    pub id: Uuid,
    pub read_only: bool,
    pub hide_passwords: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Collection {
    pub name: CipherString,
    pub external_id: Option<String>,
    pub groups: Vec<GroupSelection>,
}

impl Collection {
    pub fn new(name: CipherString) -> Self {
        Self {
            name,
            external_id: None,
            groups: Vec::new(),
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TypeSerde {
    #[serde(rename = "Type")]
    ty: i32,
    login: Option<Login>,
    card: Option<Card>,
    identity: Option<Identity>,
    secure_note: Option<SecureNote>,
}

impl Serialize for Type {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let v = TypeSerde {
            ty: match self {
                Self::Login(_) => 1,
                Self::SecureNote => 2,
                Self::Card(_) => 3,
                Self::Identity(_) => 4,
            },
            login: match self {
                Self::Login(v) => Some(v.clone()),
                _ => None,
            },
            card: match self {
                Self::Card(v) => Some(v.clone()),
                _ => None,
            },
            identity: match self {
                Self::Identity(v) => Some(v.clone()),
                _ => None,
            },
            secure_note: match self {
                Self::SecureNote => Some(SecureNote {
                    ty: SecureNoteType::Generic,
                }),
                _ => None,
            },
        };
        v.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Type {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = TypeSerde::deserialize(deserializer)?;
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
/// A login cipher type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Setters, Deserialize, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct Login {
    /// The username of the login cipher.
    pub username: Option<CipherString>,
    /// The password of the login cipher.
    pub password: Option<CipherString>,
    /// The authenticator key for the time-based one-time password.
    pub totp: Option<CipherString>,
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
    pub uri: CipherString,
    #[serde(rename = "Match")]
    pub match_type: LoginUriMatchType,
}

impl LoginUri {
    /// Creates a new [`LoginUri`].
    pub fn new(uri: CipherString, match_type: LoginUriMatchType) -> Self {
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

/// A card cipher type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Setters, Deserialize, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct Card {
    /// The name of the cardholder.
    pub cardholder_name: Option<CipherString>,
    /// The brand of the card.
    pub brand: Option<CipherString>,
    /// The card number.
    pub number: Option<CipherString>,
    /// The expiration month of the card.
    #[serde(rename = "ExpMonth")]
    pub expiration_month: Option<CipherString>,
    /// The expiration year of the card.
    #[serde(rename = "ExpYear")]
    pub expiration_year: Option<CipherString>,
    /// The security code of the card.
    pub code: Option<CipherString>,
}

/// A identity cipher type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Setters, Deserialize, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct Identity {
    pub title: Option<CipherString>,
    pub first_name: Option<CipherString>,
    pub middle_name: Option<CipherString>,
    pub last_name: Option<CipherString>,
    pub address_1: Option<CipherString>,
    pub address_2: Option<CipherString>,
    pub address_3: Option<CipherString>,
    pub city: Option<CipherString>,
    pub state: Option<CipherString>,
    pub postal_code: Option<CipherString>,
    pub country: Option<CipherString>,
    pub company: Option<CipherString>,
    pub email: Option<CipherString>,
    pub phone: Option<CipherString>,
    pub ssn: Option<CipherString>,
    pub username: Option<CipherString>,
    pub passport_number: Option<CipherString>,
    pub license_number: Option<CipherString>,
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

// https://github.com/bitwarden/server/blob/v1.40.0/src/Core/Models/Api/Response/CipherResponseModel.cs
/// A cipher resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Cipher {
    pub id: Uuid,
    pub folder_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub name: String,
    #[serde(flatten)]
    pub ty: Type,
    pub notes: Option<String>,
    #[serde(deserialize_with = "util::deserialize_optional")]
    pub fields: Vec<Field>,
    #[serde(deserialize_with = "util::deserialize_optional")]
    pub attachments: Vec<Attachment>,
    pub organization_use_totp: bool,
    #[serde(deserialize_with = "util::deserialize_optional")]
    pub password_history: Vec<PasswordHistoryEntry>,
    pub revision_date: DateTime<FixedOffset>,
    pub deletion_date: Option<DateTime<FixedOffset>>,
    pub favorite: bool,
    pub edit: bool,
    pub view_password: bool,
}

#[async_trait(?Send)]
impl Get for Cipher {
    type Id = Uuid;
    async fn get(session: &mut Session, id: Self::Id) -> crate::Result<Self> {
        session
            .request_base(Method::GET, format!("ciphers/{}", id))
            .await?
            .send()
            .await?
            .parse()
            .await
    }
}

#[async_trait(?Send)]
impl Restore for Cipher {
    type Id = Uuid;
    async fn restore(session: &mut Session, id: Self::Id) -> crate::Result<Self> {
        session
            .request_base(Method::GET, format!("ciphers/{}/restore", id))
            .await?
            .send()
            .await?
            .parse()
            .await
    }
}

#[async_trait(?Send)]
impl BulkRestore for Cipher {
    type Id = Uuid;
    async fn bulk_restore<I>(session: &mut Session, ids: I) -> crate::Result<Vec<Self>>
    where
        I: IntoIterator<Item = Self::Id>,
    {
        let body = json!({ "ids": ids.into_iter().collect::<Vec<_>>() });
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Response {
            data: Vec<Cipher>,
        }
        let response = session
            .request_base(Method::GET, "ciphers/restore")
            .await?
            .json(&body)
            .send()
            .await?
            .parse::<Response>()
            .await?;
        Ok(response.data)
    }
}

/// A cipher resource with additional information.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CipherDetails {
    #[serde(flatten)]
    pub inner: Cipher,
    #[serde(deserialize_with = "util::deserialize_optional")]
    pub collection_ids: Vec<Uuid>,
}

#[async_trait(?Send)]
impl Get for CipherDetails {
    type Id = Uuid;
    async fn get(session: &mut Session, id: Self::Id) -> crate::Result<Self> {
        session
            .request_base(Method::GET, format!("ciphers/{}/details", id))
            .await?
            .send()
            .await?
            .parse()
            .await
    }
}

#[async_trait(?Send)]
impl GetAll for CipherDetails {
    async fn get_all(session: &mut Session) -> crate::Result<Vec<Self>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Response {
            data: Vec<CipherDetails>,
        }
        let response = session
            .request_base(Method::GET, "ciphers")
            .await?
            .send()
            .await?
            .parse::<Response>()
            .await?;
        Ok(response.data)
    }
}
