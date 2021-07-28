//! Module for synchronization.

use crate::{
    account::Account, cipher::CipherDetails, collection::CollectionDetails, folder::Folder,
    settings::Domains, Get,
};
use serde::Deserialize;

pub mod request;

/// A synchronization response.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Sync {
    #[serde(rename = "Profile")]
    pub account: Account,
    pub folders: Vec<Folder>,
    pub collections: Vec<CollectionDetails>,
    pub ciphers: Vec<CipherDetails>,
    // pub policies: Vec<Policy>,
    // pub sends: Vec<Send>,
    pub domains: Domains,
}

impl<'session, TCache: 'session> Get<'session, TCache> for Sync {
    type Request = request::Get<'session, TCache>;
}
