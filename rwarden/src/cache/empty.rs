use crate::{
    account::Account, cache::Cache, cipher::CipherDetails, collection::CollectionDetails,
    folder::Folder, settings::Domains, sync::Sync,
};
use async_trait::async_trait;
use std::convert::Infallible;
use uuid::Uuid;

/// A cache that does not store any data.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EmptyCache;

#[async_trait]
impl Cache for EmptyCache {
    type Error = Infallible;

    async fn save_account<'a>(&mut self, _value: &'a Account) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn delete_account(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn save_ciphers<'a, I>(&mut self, _values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a CipherDetails> + Send,
    {
        Ok(())
    }

    async fn delete_ciphers<I>(&mut self, _ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid> + Send,
    {
        Ok(())
    }

    async fn save_folders<'a, I>(&mut self, _values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a Folder> + Send,
    {
        Ok(())
    }

    async fn delete_folders<I>(&mut self, _ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid> + Send,
    {
        Ok(())
    }

    async fn save_collections<'a, I>(&mut self, _values: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = &'a CollectionDetails> + Send,
    {
        Ok(())
    }

    async fn delete_collections<I>(&mut self, _ids: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Uuid> + Send,
    {
        Ok(())
    }

    async fn save_domains<'a>(&mut self, _value: &'a Domains) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn delete_domains(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn sync<'a>(&mut self, _value: &'a Sync) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn clear(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
