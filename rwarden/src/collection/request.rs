use crate::collection::{
    Collection, CollectionDetails, CollectionGroupDetails, SelectionReadOnlyRequestModel, Users,
};
use crate::{
    cache::Cache, crypto::SymmetricEncryptedString, util::ResponseExt, Client, Error, Request,
};
use futures_core::{future::BoxFuture, stream::BoxStream};
use reqwest::Method;
use serde_json::json;
use typed_builder::TypedBuilder;
use uuid::Uuid;

/// A [`Request`] for retrieving a collection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Get {
    pub organization_id: Uuid,
    pub collection_id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache> for Get {
    type Output = BoxFuture<'request, crate::Result<Collection, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            Ok(client
                .request(
                    Method::GET,
                    format!(
                        "{}/organizations/{}/collections/{}",
                        client.urls().base,
                        self.organization_id,
                        self.collection_id
                    ),
                )
                .await?
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for retrieving all collections.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct GetAll {
    pub organization_id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for GetAll
{
    type Output = BoxStream<'request, crate::Result<Vec<Collection>, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        request_stream! {
            client.request(
                Method::GET,
                format!(
                    "{}/organizations/{}/collections",
                    client.urls().base,
                    self.organization_id
                )
            )
            .await?
        }
    }
}

/// A [`Request`] for creating a collection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Create {
    pub organization_id: Uuid,
    pub name: SymmetricEncryptedString,
    #[builder(default, setter(strip_option))]
    pub external_id: Option<Uuid>,
    #[builder(default, setter(strip_option))]
    pub groups: Option<Vec<SelectionReadOnlyRequestModel>>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Create
{
    type Output = BoxFuture<'request, crate::Result<Collection, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            Ok(client
                .request(
                    Method::POST,
                    format!(
                        "{}/organizations/{}/collections",
                        client.urls().base,
                        self.organization_id
                    ),
                )
                .await?
                .json(&json!({
                    "Name": self.name,
                    "ExternalId": self.external_id,
                    "Groups": self.groups,
                }))
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for deleting a collection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Delete {
    pub organization_id: Uuid,
    pub collection_id: Uuid,
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
                    format!(
                        "{}/organizations/{}/collections/{}",
                        client.urls().base,
                        self.organization_id,
                        self.collection_id
                    ),
                )
                .await?
                .send()
                .await?
                .parse_empty()
                .await?;
            client
                .cache_mut()
                .delete_collections(std::iter::once(self.collection_id))
                .await
                .map_err(Error::Cache)?;
            Ok(())
        })
    }
}

/// A [`Request`] for modifying a collection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct Modify {
    pub organization_id: Uuid,
    pub collection_id: Uuid,
    pub name: SymmetricEncryptedString,
    #[builder(default, setter(strip_option))]
    pub external_id: Option<Uuid>,
    #[builder(default, setter(strip_option))]
    pub groups: Option<Vec<SelectionReadOnlyRequestModel>>,
}

impl Modify {
    #[allow(clippy::type_complexity)]
    pub fn inherit(
        collection: Collection,
    ) -> ModifyBuilder<(
        (Uuid,),
        (Uuid,),
        (SymmetricEncryptedString,),
        (Option<Uuid>,),
        (),
    )> {
        ModifyBuilder {
            fields: (
                (collection.organization_id,),
                (collection.id,),
                (collection.name,),
                (collection.external_id,),
                (),
            ),
            phantom: (),
        }
    }
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for Modify
{
    type Output = BoxFuture<'request, crate::Result<Collection, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            Ok(client
                .request(
                    Method::PUT,
                    format!(
                        "{}/organizations/{}/collections/{}",
                        client.urls().base,
                        self.organization_id,
                        self.collection_id
                    ),
                )
                .await?
                .json(&json!({
                    "Name": self.name,
                    "ExternalId": self.external_id,
                    "Groups": self.groups,
                }))
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for retrieving [`CollectionGroupDetails`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct GetGroupDetails {
    pub organization_id: Uuid,
    pub collection_id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for GetGroupDetails
{
    type Output = BoxFuture<'request, crate::Result<CollectionGroupDetails, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            Ok(client
                .request(
                    Method::GET,
                    format!(
                        "{}/organizations/{}/collections/{}/details",
                        client.urls().base,
                        self.organization_id,
                        self.collection_id
                    ),
                )
                .await?
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for retrieving all collections.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GetAllDetails;

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for GetAllDetails
{
    type Output = BoxStream<'request, crate::Result<Vec<CollectionDetails>, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        request_stream! {
            client.request(Method::GET, format!("{}/collections", client.urls().base)).await?,
            response => client
                .cache_mut()
                .save_collections(&response.data)
                .await
                .map_err(Error::Cache)?
        }
    }
}

/// A [`Request`] for retrieving users of a collection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct GetUsers {
    pub organization_id: Uuid,
    pub collection_id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for GetUsers
{
    type Output = BoxFuture<'request, crate::Result<Users, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            Ok(client
                .request(
                    Method::GET,
                    format!(
                        "{}/organizations/{}/collections/{}/users",
                        client.urls().base,
                        self.organization_id,
                        self.collection_id
                    ),
                )
                .await?
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for modifying users of a collection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct ModifyUsers {
    pub organization_id: Uuid,
    pub collection_id: Uuid,
    pub users: Users,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for ModifyUsers
{
    type Output = BoxFuture<'request, crate::Result<Users, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            Ok(client
                .request(
                    Method::PUT,
                    format!(
                        "{}/organizations/{}/collections/{}/users",
                        client.urls().base,
                        self.organization_id,
                        self.collection_id
                    ),
                )
                .await?
                .json(&self.users)
                .send()
                .await?
                .parse()
                .await?)
        })
    }
}

/// A [`Request`] for deleting a user of a collection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TypedBuilder)]
pub struct DeleteUser {
    pub organization_id: Uuid,
    pub collection_id: Uuid,
    pub organization_user_id: Uuid,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for DeleteUser
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            client
                .request(
                    Method::PUT,
                    format!(
                        "{}/organizations/{}/collections/{}/user/{}",
                        client.urls().base,
                        self.organization_id,
                        self.collection_id,
                        self.organization_user_id
                    ),
                )
                .await?
                .send()
                .await?
                .parse_empty()
                .await?;
            Ok(())
        })
    }
}
