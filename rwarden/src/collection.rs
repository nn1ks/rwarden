//! Module for collection resources.

use crate::crypto::SymmetricEncryptedString;
use derive_setters::Setters;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use request::*;

mod request;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SelectionReadOnly {
    pub id: Uuid,
    pub read_only: bool,
    pub hide_passwords: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Setters, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct SelectionReadOnlyRequestModel {
    #[setters(skip)]
    pub id: Uuid,
    pub read_only: Option<bool>,
    pub hide_passwords: Option<bool>,
}

impl SelectionReadOnlyRequestModel {
    pub fn new(id: Uuid) -> Self {
        Self {
            id,
            read_only: None,
            hide_passwords: None,
        }
    }
}

/// A collection resource.
// NOTE: Serialize is only needed for cache
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Collection {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: SymmetricEncryptedString,
    pub external_id: Option<Uuid>,
}

/// A collection resource with additional information.
// NOTE: Serialize is only needed for cache
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CollectionDetails {
    #[serde(flatten)]
    pub inner: Collection,
    pub read_only: bool,
    pub hide_passwords: bool,
}

/// A collection resource with additional information.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CollectionGroupDetails {
    #[serde(flatten)]
    pub inner: Collection,
    pub groups: Vec<SelectionReadOnly>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Users(pub Vec<SelectionReadOnly>);
