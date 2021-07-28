use crate::{
    account::Account, cache::Cache, cipher::CipherDetails, collection::CollectionDetails,
    folder::Folder, settings::Domains, sync::Sync,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::Infallible};
use uuid::Uuid;

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct MemoryCache {
    pub account: Option<Account>,
    pub folders: Vec<Folder>,
    pub collections: Vec<CollectionDetails>,
    pub ciphers: Vec<CipherDetails>,
    // pub policies: Vec<Policy>,
    // pub sends: Vec<Send>,
    pub domains: Option<Domains>,
}

#[async_trait(?Send)]
impl Cache for MemoryCache {
    type Error = Infallible;

    async fn save_account<'a>(&mut self, value: &'a Account) -> Result<(), Self::Error> {
        self.account = Some(value.clone());
        Ok(())
    }

    async fn delete_account(&mut self) -> Result<(), Self::Error> {
        self.account = None;
        Ok(())
    }

    async fn save_ciphers<'a, I>(&mut self, values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a CipherDetails>,
    {
        self.ciphers.extend(values.into_iter().cloned());
        Ok(())
    }

    async fn delete_ciphers<I>(&mut self, ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid>,
    {
        let ids = ids.into_iter().collect::<HashSet<_>>();
        self.ciphers.retain(|v| !ids.contains(&v.inner.id));
        Ok(())
    }

    async fn save_folders<'a, I>(&mut self, values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a Folder>,
    {
        self.folders.extend(values.into_iter().cloned());
        Ok(())
    }

    async fn delete_folders<I>(&mut self, ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid>,
    {
        let ids = ids.into_iter().collect::<HashSet<_>>();
        self.folders.retain(|v| !ids.contains(&v.id));
        Ok(())
    }

    async fn save_collections<'a, I>(&mut self, values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a CollectionDetails>,
    {
        self.collections.extend(values.into_iter().cloned());
        Ok(())
    }

    async fn delete_collections<I>(&mut self, ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid>,
    {
        let ids = ids.into_iter().collect::<HashSet<_>>();
        self.collections.retain(|v| !ids.contains(&v.inner.id));
        Ok(())
    }

    async fn save_domains<'a>(&mut self, value: &'a Domains) -> Result<(), Self::Error> {
        self.domains = Some(value.clone());
        Ok(())
    }

    async fn delete_domains(&mut self) -> Result<(), Self::Error> {
        self.domains = None;
        Ok(())
    }

    async fn sync<'a>(&mut self, value: &'a Sync) -> Result<(), Self::Error> {
        self.account = Some(value.account.clone());
        self.folders = value.folders.clone();
        self.collections = value.collections.clone();
        self.ciphers = value.ciphers.clone();
        self.domains = Some(value.domains.clone());
        Ok(())
    }

    async fn clear(&mut self) -> Result<(), Self::Error> {
        *self = Self::default();
        Ok(())
    }
}
