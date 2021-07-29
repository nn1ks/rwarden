//! Module for caches.

use crate::{
    account::Account, cipher::CipherDetails, collection::CollectionDetails, folder::Folder,
    settings::Domains, sync::Sync,
};
use async_trait::async_trait;
use std::error::Error;
use uuid::Uuid;

mod empty;
mod json_file;
mod memory;

pub use empty::EmptyCache;
pub use json_file::{JsonFileCache, JsonFileCacheData};
pub use memory::MemoryCache;

/// A trait for storing resources offline.
#[async_trait]
pub trait Cache {
    type Error: Error + Send;

    async fn save_account<'a>(&mut self, value: &'a Account) -> Result<(), Self::Error>;
    async fn delete_account(&mut self) -> Result<(), Self::Error>;

    async fn save_ciphers<'a, I>(&mut self, values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a CipherDetails> + Send;
    async fn delete_ciphers<I>(&mut self, ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid> + Send;

    async fn save_folders<'a, I>(&mut self, values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a Folder> + Send;
    async fn delete_folders<I>(&mut self, ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid> + Send;

    async fn save_collections<'a, I>(&mut self, values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a CollectionDetails> + Send;
    async fn delete_collections<I>(&mut self, ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid> + Send;

    async fn save_domains<'a>(&mut self, value: &'a Domains) -> Result<(), Self::Error>;
    async fn delete_domains(&mut self) -> Result<(), Self::Error>;

    async fn sync<'a>(&mut self, value: &'a Sync) -> Result<(), Self::Error>;

    async fn clear(&mut self) -> Result<(), Self::Error>;
}
