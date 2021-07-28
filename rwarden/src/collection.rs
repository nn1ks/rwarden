//! Module for collection resources.

use crate::{crypto::CipherString, Create, Delete, Get, GetAll, Modify};
use derive_setters::Setters;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod request;

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
    pub name: CipherString,
    pub external_id: Uuid,
}

impl<'session, TCache: 'session> Get<'session, TCache> for Collection {
    type Request = request::DefaultGet<'session, TCache>;
}

impl<'session, TCache: 'session> GetAll<'session, TCache> for Collection {
    type Request = request::DefaultGetAll<'session, TCache>;
}

impl<'session, TCache: 'session> Create<'session, TCache> for Collection {
    type Request = request::DefaultCreate<'session, TCache>;
}

impl<'session, TCache: 'session> Delete<'session, TCache> for Collection {
    type Request = request::DefaultDelete<'session, TCache>;
}

impl<'session, TCache: 'session> Modify<'session, TCache> for Collection {
    type Request = request::DefaultModify<'session, TCache>;
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

impl<'session, TCache: 'session> GetAll<'session, TCache> for CollectionDetails {
    type Request = request::GetAllDetails<'session, TCache>;
}

/// A collection resource with additional information.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CollectionGroupDetails {
    #[serde(flatten)]
    pub inner: Collection,
    pub groups: Vec<SelectionReadOnly>,
}

impl<'session, TCache: 'session> Get<'session, TCache> for CollectionGroupDetails {
    type Request = request::DefaultGetGroupDetails<'session, TCache>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Users(pub Vec<SelectionReadOnly>);

impl<'session, TCache: 'session> Get<'session, TCache> for Users {
    type Request = request::DefaultGetUsers<'session, TCache>;
}

impl<'session, TCache: 'session> Delete<'session, TCache> for Users {
    type Request = request::DefaultDeleteUser<'session, TCache>;
}

impl<'session, TCache: 'session> Modify<'session, TCache> for Users {
    type Request = request::DefaultModifyUsers<'session, TCache>;
}
