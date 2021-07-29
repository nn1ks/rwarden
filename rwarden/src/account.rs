//! Module for account resources.

use crate::crypto::CipherString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use request::*;

mod request;

/// An account resource.
// NOTE: Serialize is only needed for cache
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Account {
    pub id: Uuid,
    pub name: Option<String>,
    pub email: String,
    pub email_verified: bool,
    pub premium: bool,
    pub master_password_hint: Option<String>,
    pub culture: String,
    pub two_factor_enabled: bool,
    pub key: CipherString,
    pub private_key: Option<CipherString>,
    pub security_stamp: String,
    // pub organizations: Vec<Organization>, // TODO
}
