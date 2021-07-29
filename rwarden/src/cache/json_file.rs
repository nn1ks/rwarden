use crate::{
    account::Account, cache::Cache, cipher::CipherDetails, collection::CollectionDetails,
    folder::Folder, settings::Domains, sync::Sync,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::PathBuf};
use thiserror::Error as ThisError;
use tokio::{fs, io};
use uuid::Uuid;

/// The data of a [`JsonFileCache`].
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct JsonFileCacheData {
    pub account: Option<Account>,
    pub folders: Vec<Folder>,
    pub collections: Vec<CollectionDetails>,
    pub ciphers: Vec<CipherDetails>,
    // pub policies: Vec<Policy>,
    // pub sends: Vec<Send>,
    pub domains: Option<Domains>,
}

impl JsonFileCacheData {
    fn from_sync(value: Sync) -> Self {
        Self {
            account: Some(value.account),
            folders: value.folders,
            collections: value.collections,
            ciphers: value.ciphers,
            domains: Some(value.domains),
        }
    }
}

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("failed to serialize/deserialize cache")]
    Serde(#[from] serde_json::Error),
    #[error("IO error while reading or writing cache")]
    Io(#[from] io::Error),
}

/// A cache that writes the data to a JSON file.
#[derive(Debug, Clone)]
pub struct JsonFileCache {
    path: PathBuf,
}

impl JsonFileCache {
    /// Creates a new [`JsonFileCache`].
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self { path: path.into() }
    }

    pub async fn read_data(&self) -> Result<JsonFileCacheData, Error> {
        let bytes = fs::read(&self.path).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub async fn write_data(&self, data: &JsonFileCacheData) -> Result<(), Error> {
        let value = serde_json::to_vec(&data)?;
        fs::write(&self.path, &value).await?;
        Ok(())
    }

    async fn modify_data<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut JsonFileCacheData),
    {
        let mut data = self.read_data().await?;
        f(&mut data);
        self.write_data(&data).await?;
        Ok(())
    }
}

#[async_trait]
impl Cache for JsonFileCache {
    type Error = Error;

    async fn save_account<'a>(&mut self, value: &'a Account) -> Result<(), Self::Error> {
        self.modify_data(|data| data.account = Some(value.clone()))
            .await
    }

    async fn delete_account(&mut self) -> Result<(), Self::Error> {
        self.modify_data(|data| data.account = None).await
    }

    async fn save_ciphers<'a, I>(&mut self, values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a CipherDetails> + Send,
    {
        self.modify_data(|data| data.ciphers.extend(values.into_iter().cloned()))
            .await
    }

    async fn delete_ciphers<I>(&mut self, ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid> + Send,
    {
        self.modify_data(|data| {
            let ids = ids.into_iter().collect::<HashSet<_>>();
            data.ciphers.retain(|v| !ids.contains(&v.inner.id));
        })
        .await
    }

    async fn save_folders<'a, I>(&mut self, values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a Folder> + Send,
    {
        self.modify_data(|data| data.folders.extend(values.into_iter().cloned()))
            .await
    }

    async fn delete_folders<I>(&mut self, ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid> + Send,
    {
        self.modify_data(|data| {
            let ids = ids.into_iter().collect::<HashSet<_>>();
            data.folders.retain(|v| !ids.contains(&v.id));
        })
        .await
    }

    async fn save_collections<'a, I>(&mut self, values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a CollectionDetails> + Send,
    {
        self.modify_data(|data| data.collections.extend(values.into_iter().cloned()))
            .await
    }

    async fn delete_collections<I>(&mut self, ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid> + Send,
    {
        self.modify_data(|data| {
            let ids = ids.into_iter().collect::<HashSet<_>>();
            data.collections.retain(|v| !ids.contains(&v.inner.id));
        })
        .await
    }

    async fn save_domains<'a>(
        &mut self,
        value: &'a crate::settings::Domains,
    ) -> Result<(), Self::Error> {
        self.modify_data(|data| data.domains = Some(value.clone()))
            .await
    }

    async fn delete_domains(&mut self) -> Result<(), Self::Error> {
        self.modify_data(|data| data.domains = None).await
    }

    async fn sync<'a>(&mut self, value: &'a Sync) -> Result<(), Self::Error> {
        self.write_data(&JsonFileCacheData::from_sync(value.clone()))
            .await
    }

    async fn clear(&mut self) -> Result<(), Self::Error> {
        self.write_data(&JsonFileCacheData::default()).await
    }
}
