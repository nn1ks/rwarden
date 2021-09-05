use crate::{
    cache::Cache, crypto::SymmetricEncryptedString, folder::Folder, util::ResponseExt, Client,
    Error, Request,
};
use futures::{future::BoxFuture, stream::BoxStream};
use reqwest::Method;
use serde::Serialize;
use serde_json::json;
use typed_builder::TypedBuilder;
use uuid::Uuid;

/// A [`Request`] for retrieving a folder.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Get {
    pub id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache> for Get {
    type Output = BoxFuture<'request, crate::Result<Folder, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(
                    Method::GET,
                    format!("{}/folders/{}", client.urls().base, self.id),
                )
                .await?
                .send()
                .await?
                .parse()
                .await?;
            client
                .cache_mut()
                .save_folders(std::iter::once(&value))
                .await
                .map_err(Error::Cache)?;
            Ok(value)
        })
    }
}

/// A [`Request`] for retrieving all folders.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GetAll;

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for GetAll
{
    type Output = BoxStream<'request, crate::Result<Vec<Folder>, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        request_stream! {
            client.request(Method::GET, format!("{}/folders", client.urls().base)).await?,
            response => client
                .cache_mut()
                .save_folders(&response.data)
                .await
                .map_err(Error::Cache)?
        }
    }
}

/// A [`Request`] for creating a folder.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct Create {
    pub name: SymmetricEncryptedString,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Create
{
    type Output = BoxFuture<'request, crate::Result<Folder, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(Method::POST, format!("{}/folders", client.urls().base))
                .await?
                .json(self)
                .send()
                .await?
                .parse()
                .await?;
            client
                .cache_mut()
                .save_folders(std::iter::once(&value))
                .await
                .map_err(Error::Cache)?;
            Ok(value)
        })
    }
}

/// A [`Request`] for deleting a folder.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Delete {
    pub id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Delete
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            client
                .request(
                    Method::DELETE,
                    format!("{}/folders/{}", client.urls().base, self.id),
                )
                .await?
                .send()
                .await?
                .parse_empty()
                .await?;
            client
                .cache_mut()
                .delete_folders(std::iter::once(self.id))
                .await
                .map_err(Error::Cache)?;
            Ok(())
        })
    }
}

/// A [`Request`] for modifying a folder.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Modify {
    pub id: Uuid,
    pub name: SymmetricEncryptedString,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Modify
{
    type Output = BoxFuture<'request, crate::Result<Folder, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(
                    Method::PUT,
                    format!("{}/folders/{}", client.urls().base, self.id),
                )
                .await?
                .json(&json!({
                    "Name": self.name
                }))
                .send()
                .await?
                .parse()
                .await?;
            client
                .cache_mut()
                .save_folders(std::iter::once(&value))
                .await
                .map_err(Error::Cache)?;
            Ok(value)
        })
    }
}
