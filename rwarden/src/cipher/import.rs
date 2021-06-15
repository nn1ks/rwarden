use crate::cipher::{Collection, Folder, RequestModel};
use crate::{util::ResponseExt, Result, Session};
use async_trait::async_trait;
use derive_setters::Setters;
use reqwest::Method;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::{collections::HashMap, result::Result as StdResult};
use uuid::Uuid;

/// Entry of an [`AccountImporter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountImporterEntry {
    pub cipher: RequestModel,
    pub folder: Option<Folder>,
}

impl AccountImporterEntry {
    pub fn new(cipher: RequestModel, folder: Option<Folder>) -> Self {
        Self { cipher, folder }
    }
}

/// A type for importing ciphers into a user account.
#[derive(Debug, Default, Clone, PartialEq, Eq, Setters)]
#[setters(strip_option, prefix = "with_")]
pub struct AccountImporter {
    pub entries: Vec<AccountImporterEntry>,
}

impl AccountImporter {
    /// Creates a new [`AccountImporter`].
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl crate::Importer for AccountImporter {
    async fn execute(&self, session: &mut Session) -> Result<()> {
        session
            .request_base(Method::POST, "ciphers/import")
            .await?
            .json(self)
            .send()
            .await?
            .parse_empty()
            .await
    }
}

impl Serialize for AccountImporter {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ciphers = Vec::with_capacity(self.entries.len());
        let mut folders = Vec::new();
        let mut map = HashMap::new();
        for (i, entry) in self.entries.iter().enumerate() {
            ciphers.push(&entry.cipher);
            if let Some(folder) = &entry.folder {
                map.insert(i, folders.len());
                folders.push(folder);
            }
        }
        let mut state = serializer.serialize_struct("AccountImporter", 3)?;
        state.serialize_field("Folders", &folders)?;
        state.serialize_field("Ciphers", &ciphers)?;
        state.serialize_field("FolderRelationships", &map)?;
        state.end()
    }
}

/// Entry of an [`OrganizationImporter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationImporterEntry {
    pub cipher: RequestModel,
    pub collection: Option<Collection>,
}

impl OrganizationImporterEntry {
    /// Creates a new [`OrganizationImporterEntry`].
    pub fn new(cipher: RequestModel, collection: Option<Collection>) -> Self {
        Self { cipher, collection }
    }
}

/// A type for importing ciphers into an organization.
#[derive(Debug, Clone, PartialEq, Eq, Setters)]
#[setters(strip_option, prefix = "with_")]
pub struct OrganizationImporter {
    pub organization_id: Uuid,
    pub entries: Vec<OrganizationImporterEntry>,
}

impl OrganizationImporter {
    /// Creates a new [`OrganizationImporter`].
    pub fn new(organization_id: Uuid) -> Self {
        Self {
            organization_id,
            entries: Vec::new(),
        }
    }
}

#[async_trait]
impl crate::Importer for OrganizationImporter {
    async fn execute(&self, session: &mut Session) -> Result<()> {
        session
            .request_base(Method::POST, "ciphers/import-organization")
            .await?
            .json(self)
            .query(&[("organizationId", self.organization_id)])
            .send()
            .await?
            .parse()
            .await
    }
}

impl Serialize for OrganizationImporter {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ciphers = Vec::with_capacity(self.entries.len());
        let mut collectins = Vec::new();
        let mut map = HashMap::new();
        for (i, entry) in self.entries.iter().enumerate() {
            ciphers.push(&entry.cipher);
            if let Some(folder) = &entry.collection {
                map.insert(i, collectins.len());
                collectins.push(folder);
            }
        }
        let mut state = serializer.serialize_struct("OrganizationImporter", 3)?;
        state.serialize_field("Collections", &collectins)?;
        state.serialize_field("Ciphers", &ciphers)?;
        state.serialize_field("CollectionRelationships", &map)?;
        state.end()
    }
}
