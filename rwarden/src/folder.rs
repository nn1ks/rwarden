//! Module for folder resources.

use crate::{crypto::CipherString, Create, Delete, Get, GetAll, Modify};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod request;

/// A folder resource.
// NOTE: Serialize is only needed for cache
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Folder {
    pub id: Uuid,
    pub name: CipherString,
    pub revision_date: DateTime<FixedOffset>,
}

impl<'session, TCache: 'session> Get<'session, TCache> for Folder {
    type Request = request::DefaultGet<'session, TCache>;
}

impl<'session, TCache: 'session> GetAll<'session, TCache> for Folder {
    type Request = request::GetAll<'session, TCache>;
}

impl<'session, TCache: 'session> Create<'session, TCache> for Folder {
    type Request = request::DefaultCreate<'session, TCache>;
}

impl<'session, TCache: 'session> Delete<'session, TCache> for Folder {
    type Request = request::DefaultDelete<'session, TCache>;
}

impl<'session, TCache: 'session> Modify<'session, TCache> for Folder {
    type Request = request::DefaultModify<'session, TCache>;
}
