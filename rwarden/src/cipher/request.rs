use crate::cipher::{Cipher, CipherDetails, Owner, RequestModel};
use crate::util::ResponseExt;
use crate::{cache::Cache, crypto::MasterPasswordHash, Client, Error, Request};
use futures::{future::BoxFuture, stream::BoxStream};
use reqwest::Method;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use typed_builder::TypedBuilder;
use uuid::Uuid;

/// A [`Request`] for retrieving a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Get {
    pub id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache> for Get {
    type Output = BoxFuture<'request, crate::Result<Cipher, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(
                    Method::GET,
                    format!("{}/ciphers/{}", client.urls().base, self.id),
                )
                .await?
                .send()
                .await?
                .parse()
                .await?;
            Ok(value)
        })
    }
}

/// A [`Request`] for creating a cipher.
#[derive(Debug, Clone, PartialEq, Eq, TypedBuilder)]
pub struct Create {
    pub request_model: RequestModel,
    pub owner: Owner,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Create
{
    type Output = BoxFuture<'request, crate::Result<Cipher, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Request<'a> {
            #[serde(flatten)]
            request_model: &'a RequestModel,
            #[serde(skip_serializing_if = "Option::is_none")]
            collection_ids: Option<&'a Vec<Uuid>>,
        }

        Box::pin(async move {
            let (path, collection_ids) = match &self.owner {
                Owner::User => ("ciphers", None),
                Owner::Organization { collection_ids } => ("ciphers/create", Some(collection_ids)),
            };
            let request = Request {
                request_model: &self.request_model,
                collection_ids,
            };
            Ok(client
                .request(Method::POST, format!("{}/{}", client.urls().base, path))
                .await?
                .json(&request)
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for deleting a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Delete {
    pub id: Uuid,
    pub soft_delete: bool,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Delete
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let (method, path) = if self.soft_delete {
                (Method::PUT, format!("ciphers/{}/delete", self.id))
            } else {
                (Method::DELETE, format!("ciphers/{}", self.id))
            };
            client
                .request(method, format!("{}/{}", client.urls().base, path))
                .await?
                .send()
                .await?
                .parse_empty()
                .await?;
            client
                .cache_mut()
                .delete_ciphers(std::iter::once(self.id))
                .await
                .map_err(Error::Cache)?;
            Ok(())
        })
    }
}

/// A [`Request`] for deleting multiple ciphers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct BulkDelete {
    pub ids: Vec<Uuid>,
    pub soft_delete: bool,
    #[builder(default, setter(strip_option))]
    pub organization_id: Option<Uuid>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for BulkDelete
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let (method, path) = if self.soft_delete {
                (Method::PUT, "ciphers/delete")
            } else {
                (Method::DELETE, "ciphers")
            };
            client
                .request(method, format!("{}/{}", client.urls().base, path))
                .await?
                .json(&json!({
                    "Ids": self.ids,
                    "OrganizationId": self.organization_id,
                }))
                .send()
                .await?
                .parse_empty()
                .await?;
            client
                .cache_mut()
                .delete_ciphers(self.ids.iter().copied())
                .await
                .map_err(Error::Cache)?;
            Ok(())
        })
    }
}

/// A [`Request`] for modifying a cipher.
#[derive(Debug, Clone, PartialEq, Eq, TypedBuilder)]
pub struct Modify {
    pub id: Uuid,
    pub request_model: RequestModel,
}

impl Modify {
    pub fn inherit(cipher: Cipher) -> ModifyBuilder<((Uuid,), (RequestModel,))> {
        ModifyBuilder {
            fields: ((cipher.id,), (RequestModel::from(cipher),)),
            phantom: (),
        }
    }
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Modify
{
    type Output = BoxFuture<'request, crate::Result<Cipher, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            Ok(client
                .request(
                    Method::PUT,
                    format!("{}/ciphers/{}", client.urls().base, self.id),
                )
                .await?
                .json(&self.request_model)
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for modifying a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct ModifyPartial {
    pub id: Uuid,
    #[builder(default, setter(strip_option))]
    pub folder_id: Option<Uuid>,
    #[builder(default, setter(strip_option))]
    pub favorite: Option<bool>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for ModifyPartial
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            client
                .request(
                    Method::PUT,
                    format!("{}/ciphers/{}/partial", client.urls().base, self.id),
                )
                .await?
                .json(&json!({
                    "FolderId": self.folder_id,
                    "Favorite": self.favorite,
                }))
                .send()
                .await?
                .parse_empty()
                .await?;
            Ok(())
        })
    }
}

/// A [`Request`] for modifying the collections of a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct ModifyCollections {
    pub id: Uuid,
    pub collection_ids: Vec<Uuid>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for ModifyCollections
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            client
                .request(
                    Method::PUT,
                    format!("{}/ciphers/{}/collections", client.urls().base, self.id),
                )
                .await?
                .json(&json!({
                    "CollectionIds": self.collection_ids
                }))
                .send()
                .await?
                .parse_empty()
                .await?;
            Ok(())
        })
    }
}

/// A [`Request`] for restoring a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Restore {
    pub id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Restore
{
    type Output = BoxFuture<'request, crate::Result<Cipher, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            Ok(client
                .request(
                    Method::PUT,
                    format!("{}/ciphers/{}/restore", client.urls().base, self.id),
                )
                .await?
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for restoring multiple ciphers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct BulkRestore {
    pub ids: Vec<Uuid>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for BulkRestore
{
    type Output = BoxStream<'request, crate::Result<Vec<Cipher>, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        request_stream! {
            client
                .request(Method::PUT, format!("{}/ciphers/restore", client.urls().base))
                .await?
                .json(&self)
        }
    }
}

/// A [`Request`] for sharing a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct Share {
    pub id: Uuid,
    pub cipher: RequestModel,
    pub collection_ids: Vec<Uuid>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Share
{
    type Output = BoxFuture<'request, crate::Result<Cipher, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Request<'a> {
            cipher: &'a RequestModel,
            collection_ids: &'a Vec<Uuid>,
        }

        Box::pin(async move {
            let request = Request {
                cipher: &self.cipher,
                collection_ids: &self.collection_ids,
            };
            Ok(client
                .request(
                    Method::PUT,
                    format!("{}/ciphers/{}/share", client.urls().base, self.id),
                )
                .await?
                .json(&request)
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for sharing multiple ciphers.
#[derive(Debug, Clone, PartialEq, Eq, TypedBuilder)]
pub struct BulkShare {
    pub ciphers: HashMap<Uuid, RequestModel>,
    pub collection_ids: Vec<Uuid>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for BulkShare
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct RequestModelWithId<'a> {
            id: &'a Uuid,
            #[serde(flatten)]
            inner: &'a RequestModel,
        }

        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Request<'a> {
            ciphers: Vec<RequestModelWithId<'a>>,
            collection_ids: &'a Vec<Uuid>,
        }

        Box::pin(async move {
            let request = Request {
                ciphers: self
                    .ciphers
                    .iter()
                    .map(|(id, cipher)| RequestModelWithId { id, inner: cipher })
                    .collect(),
                collection_ids: &self.collection_ids,
            };
            client
                .request(Method::PUT, format!("{}/ciphers/share", client.urls().base))
                .await?
                .json(&request)
                .send()
                .await?
                .parse_empty()
                .await?;
            Ok(())
        })
    }
}

/// A [`Request`] for moving multiple ciphers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct BulkMove {
    pub ids: Vec<Uuid>,
    pub folder_id: Option<Uuid>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for BulkMove
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            client
                .request(Method::PUT, format!("{}/ciphers/move", client.urls().base))
                .await?
                .json(&json!({
                    "Ids": self.ids,
                    "FolderId": self.folder_id,
                }))
                .send()
                .await?
                .parse_empty()
                .await?;
            Ok(())
        })
    }
}

/// A [`Request`] for deleting all ciphers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Purge {
    pub master_password_hash: MasterPasswordHash,
    #[builder(default, setter(strip_option))]
    pub organization_id: Option<Uuid>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Purge
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let mut request = client
                .request(
                    Method::POST,
                    format!("{}/ciphers/purge", client.urls().base),
                )
                .await?
                .json(&json!({
                    "MasterPasswordHash": self.master_password_hash,
                }));
            if let Some(v) = &self.organization_id {
                request = request.query(&[("organizationId", v)]);
            }
            request.send().await?.parse_empty().await?;
            // TODO: Maybe update cache (delete all ciphers)
            Ok(())
        })
    }
}

/// A [`Request`] for retrieving a [`CipherDetails`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct GetDetails {
    pub id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for GetDetails
{
    type Output = BoxFuture<'request, crate::Result<CipherDetails, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(
                    Method::GET,
                    format!("{}/ciphers/{}/details", client.urls().base, self.id),
                )
                .await?
                .send()
                .await?
                .parse()
                .await?;
            client
                .cache_mut()
                .save_ciphers(std::iter::once(&value))
                .await
                .map_err(Error::Cache)?;
            Ok(value)
        })
    }
}

/// A [`Request`] for retrieving all [`CipherDetails`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GetAllDetails;

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for GetAllDetails
{
    type Output = BoxStream<'request, crate::Result<Vec<CipherDetails>, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        request_stream! {
            client.request(Method::GET, format!("{}/ciphers", client.urls().base)).await?,
            response => client
                .cache_mut()
                .save_ciphers(&response.data)
                .await
                .map_err(Error::Cache)?
        }
    }
}
