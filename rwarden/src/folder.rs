//! Module for folder resources.

use crate::crypto::CipherString;
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use request::*;

mod request;

/// A folder resource.
// NOTE: Serialize is only needed for cache
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Folder {
    pub id: Uuid,
    pub name: CipherString,
    pub revision_date: DateTime<FixedOffset>,
}
