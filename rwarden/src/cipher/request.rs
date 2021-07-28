use crate::cipher::{Cipher, CipherDetails, Owner, RequestModel};
use crate::util::{ListResponse, ResponseExt};
use crate::{cache::Cache, crypto::MasterPasswordHash, Error, Request, Session};
use async_stream::try_stream;
use futures::stream::Stream;
use reqwest::Method;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug)]
pub struct Get<'session, TCache, PId> {
    session: &'session mut Session<TCache>,
    id: PId,
}

pub type DefaultGet<'session, TCache> = Get<'session, TCache, ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultGet<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session, id: () }
    }
}

impl<'session, TCache, PId> Get<'session, TCache, PId> {
    pub fn id(self, id: Uuid) -> Get<'session, TCache, Uuid> {
        Get {
            session: self.session,
            id,
        }
    }
}

impl<'session, TCache: Cache> Get<'session, TCache, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<Cipher, TCache::Error> {
        Ok(self
            .session
            .request(
                Method::GET,
                format!("{}/ciphers/{}", self.session.urls().base, self.id),
            )
            .await?
            .send()
            .await?
            .parse()
            .await?)
    }
}

#[derive(Debug)]
pub struct Create<'session, TCache, PRequestModel, POwner> {
    session: &'session mut Session<TCache>,
    request_model: PRequestModel,
    owner: POwner,
}

pub type DefaultCreate<'session, TCache> = Create<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultCreate<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            request_model: (),
            owner: (),
        }
    }
}

impl<'session, TCache: Cache, PRequestModel, POwner>
    Create<'session, TCache, PRequestModel, POwner>
{
    pub fn request_model(
        self,
        value: RequestModel,
    ) -> Create<'session, TCache, RequestModel, POwner> {
        Create {
            session: self.session,
            request_model: value,
            owner: self.owner,
        }
    }

    pub fn owner(self, value: Owner) -> Create<'session, TCache, PRequestModel, Owner> {
        Create {
            session: self.session,
            request_model: self.request_model,
            owner: value,
        }
    }
}

impl<'session, TCache: Cache> Create<'session, TCache, RequestModel, Owner> {
    pub async fn execute(&mut self) -> crate::Result<Cipher, TCache::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Request<'a> {
            #[serde(flatten)]
            request_model: &'a RequestModel,
            #[serde(skip_serializing_if = "Option::is_none")]
            collection_ids: Option<&'a Vec<Uuid>>,
        }

        let (path, collection_ids) = match &self.owner {
            Owner::User => ("ciphers", None),
            Owner::Organization { collection_ids } => ("ciphers/create", Some(collection_ids)),
        };
        let request = Request {
            request_model: &self.request_model,
            collection_ids,
        };
        Ok(self
            .session
            .request(
                Method::POST,
                format!("{}/{}", self.session.urls().base, path),
            )
            .await?
            .json(&request)
            .send()
            .await?
            .parse()
            .await?)
    }
}

#[derive(Debug)]
pub struct Delete<'session, TCache, PId, PSoftDelete> {
    session: &'session mut Session<TCache>,
    id: PId,
    soft_delete: PSoftDelete,
}

pub type DefaultDelete<'session, TCache> = Delete<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultDelete<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            id: (),
            soft_delete: (),
        }
    }
}

impl<'session, TCache, PId, PSoftDelete> Delete<'session, TCache, PId, PSoftDelete> {
    pub fn id(self, id: Uuid) -> Delete<'session, TCache, Uuid, PSoftDelete> {
        Delete {
            session: self.session,
            id,
            soft_delete: self.soft_delete,
        }
    }

    pub fn soft_delete(self, value: bool) -> Delete<'session, TCache, PId, bool> {
        Delete {
            session: self.session,
            id: self.id,
            soft_delete: value,
        }
    }
}

impl<'session, TCache: Cache> Delete<'session, TCache, Uuid, bool> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        let (method, path) = if self.soft_delete {
            (Method::PUT, format!("ciphers/{}/delete", self.id))
        } else {
            (Method::DELETE, format!("ciphers/{}", self.id))
        };
        self.session
            .request(method, format!("{}/{}", self.session.urls().base, path))
            .await?
            .send()
            .await?
            .parse_empty()
            .await?;
        self.session
            .cache_mut()
            .delete_ciphers(std::iter::once(self.id))
            .await
            .map_err(Error::Cache)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct BulkDelete<'session, TCache, PIds, PSoftDelete> {
    session: &'session mut Session<TCache>,
    ids: PIds,
    soft_delete: PSoftDelete,
    organization_id: Option<Uuid>,
}

pub type DefaultBulkDelete<'session, TCache> = BulkDelete<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultBulkDelete<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            ids: (),
            soft_delete: (),
            organization_id: None,
        }
    }
}

impl<'session, TCache, PIds, PSoftDelete> BulkDelete<'session, TCache, PIds, PSoftDelete> {
    pub fn ids<I>(self, ids: I) -> BulkDelete<'session, TCache, Vec<Uuid>, PSoftDelete>
    where
        I: IntoIterator<Item = Uuid>,
    {
        BulkDelete {
            session: self.session,
            ids: ids.into_iter().collect(),
            soft_delete: self.soft_delete,
            organization_id: self.organization_id,
        }
    }

    pub fn soft_delete(self, value: bool) -> BulkDelete<'session, TCache, PIds, bool> {
        BulkDelete {
            session: self.session,
            ids: self.ids,
            soft_delete: value,
            organization_id: self.organization_id,
        }
    }

    pub fn organization_id(mut self, id: Uuid) -> Self {
        self.organization_id = Some(id);
        self
    }
}

impl<'session, TCache: Cache> BulkDelete<'session, TCache, Vec<Uuid>, bool> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        let (method, path) = if self.soft_delete {
            (Method::PUT, "ciphers/delete")
        } else {
            (Method::DELETE, "ciphers")
        };
        self.session
            .request(method, format!("{}/{}", self.session.urls().base, path))
            .await?
            .json(&json!({
                "Ids": self.ids,
                "OrganizationId": self.organization_id,
            }))
            .send()
            .await?
            .parse_empty()
            .await?;
        self.session
            .cache_mut()
            .delete_ciphers(self.ids.iter().copied())
            .await
            .map_err(Error::Cache)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Modify<'session, TCache> {
    session: &'session mut Session<TCache>,
}

impl<'session, TCache> Request<'session, TCache> for Modify<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session }
    }
}

impl<'session, TCache> Modify<'session, TCache> {
    pub fn complete(self) -> DefaultModifyComplete<'session, TCache> {
        ModifyComplete::new(self.session)
    }

    pub fn partial(self) -> DefaultModifyPartial<'session, TCache> {
        ModifyPartial::new(self.session)
    }

    pub fn collections(self) -> DefaultModifyCollections<'session, TCache> {
        ModifyCollections::new(self.session)
    }
}

#[derive(Debug)]
pub struct ModifyComplete<'session, TCache, PId, PRequestModel> {
    session: &'session mut Session<TCache>,
    id: PId,
    request_model: PRequestModel,
}

pub type DefaultModifyComplete<'session, TCache> = ModifyComplete<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModifyComplete<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            id: (),
            request_model: (),
        }
    }
}

impl<'session, TCache, PId, PRequestModel> ModifyComplete<'session, TCache, PId, PRequestModel> {
    pub fn id(self, id: Uuid) -> ModifyComplete<'session, TCache, Uuid, PRequestModel> {
        ModifyComplete {
            session: self.session,
            id,
            request_model: self.request_model,
        }
    }

    pub fn request_model(
        self,
        value: RequestModel,
    ) -> ModifyComplete<'session, TCache, PId, RequestModel> {
        ModifyComplete {
            session: self.session,
            id: self.id,
            request_model: value,
        }
    }
}

impl<'session, TCache: Cache> ModifyComplete<'session, TCache, Uuid, RequestModel> {
    pub async fn execute(&mut self) -> crate::Result<Cipher, TCache::Error> {
        Ok(self
            .session
            .request(
                Method::PUT,
                format!("{}/ciphers/{}", self.session.urls().base, self.id),
            )
            .await?
            .json(&self.request_model)
            .send()
            .await?
            .parse()
            .await?)
    }
}

#[derive(Debug)]
pub struct ModifyPartial<'session, TCache, PId> {
    session: &'session mut Session<TCache>,
    id: PId,
    folder_id: Option<Uuid>,
    favorite: Option<bool>,
}

pub type DefaultModifyPartial<'session, TCache> = ModifyPartial<'session, TCache, ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModifyPartial<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            id: (),
            folder_id: None,
            favorite: None,
        }
    }
}

impl<'session, TCache, PId> ModifyPartial<'session, TCache, PId> {
    pub fn id(self, id: Uuid) -> ModifyPartial<'session, TCache, Uuid> {
        ModifyPartial {
            session: self.session,
            id,
            folder_id: self.folder_id,
            favorite: self.favorite,
        }
    }

    pub fn folder_id(mut self, value: Uuid) -> Self {
        self.folder_id = Some(value);
        self
    }

    pub fn favorite(mut self, value: bool) -> Self {
        self.favorite = Some(value);
        self
    }
}

impl<'session, TCache: Cache> ModifyPartial<'session, TCache, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        self.session
            .request(
                Method::PUT,
                format!("{}/ciphers/{}/partial", self.session.urls().base, self.id),
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
    }
}

#[derive(Debug)]
pub struct ModifyCollections<'session, TCache, PId, PCollectionIds> {
    session: &'session mut Session<TCache>,
    id: PId,
    collection_ids: PCollectionIds,
}

pub type DefaultModifyCollections<'session, TCache> = ModifyCollections<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModifyCollections<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            id: (),
            collection_ids: (),
        }
    }
}

impl<'session, TCache, PId, PCollectionIds>
    ModifyCollections<'session, TCache, PId, PCollectionIds>
{
    pub fn id(self, id: Uuid) -> ModifyCollections<'session, TCache, Uuid, PCollectionIds> {
        ModifyCollections {
            session: self.session,
            id,
            collection_ids: self.collection_ids,
        }
    }

    pub fn collection_ids<I>(self, value: I) -> ModifyCollections<'session, TCache, PId, Vec<Uuid>>
    where
        I: IntoIterator<Item = Uuid>,
    {
        ModifyCollections {
            session: self.session,
            id: self.id,
            collection_ids: value.into_iter().collect(),
        }
    }
}

impl<'session, TCache: Cache> ModifyCollections<'session, TCache, Uuid, Vec<Uuid>> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        Ok(self
            .session
            .request(
                Method::PUT,
                format!(
                    "{}/ciphers/{}/collections",
                    self.session.urls().base,
                    self.id
                ),
            )
            .await?
            .json(&json!({
                "CollectionIds": self.collection_ids
            }))
            .send()
            .await?
            .parse()
            .await?)
    }
}

#[derive(Debug)]
pub struct Restore<'session, TCache, PId> {
    session: &'session mut Session<TCache>,
    id: PId,
}

pub type DefaultRestore<'session, TCache> = Restore<'session, TCache, ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultRestore<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session, id: () }
    }
}

impl<'session, TCache, PId> Restore<'session, TCache, PId> {
    pub fn id(self, id: Uuid) -> Restore<'session, TCache, Uuid> {
        Restore {
            session: self.session,
            id,
        }
    }
}

impl<'session, TCache: Cache> Restore<'session, TCache, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<Cipher, TCache::Error> {
        Ok(self
            .session
            .request(
                Method::PUT,
                format!("{}/ciphers/{}/restore", self.session.urls().base, self.id),
            )
            .await?
            .send()
            .await?
            .parse()
            .await?)
    }
}

#[derive(Debug)]
pub struct BulkRestore<'session, TCache, PIds> {
    session: &'session mut Session<TCache>,
    ids: PIds,
}

pub type DefaultBulkRestore<'session, TCache> = BulkRestore<'session, TCache, ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultBulkRestore<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session, ids: () }
    }
}

impl<'session, TCache, PIds> BulkRestore<'session, TCache, PIds> {
    pub fn ids<I>(self, ids: I) -> BulkRestore<'session, TCache, Vec<Uuid>>
    where
        I: IntoIterator<Item = Uuid>,
    {
        BulkRestore {
            session: self.session,
            ids: ids.into_iter().collect(),
        }
    }
}

impl<'session, TCache: Cache> BulkRestore<'session, TCache, Vec<Uuid>> {
    pub fn execute<'a: 'session>(
        &'a mut self,
    ) -> impl Stream<Item = crate::Result<Vec<Cipher>, TCache::Error>> + 'a {
        try_stream! {
            let mut continuation_token = None;
            let mut is_first_iteration = true;
            while continuation_token.is_some() || is_first_iteration {
                let mut request = self
                    .session
                    .request(
                        Method::PUT,
                        format!("{}/ciphers/restore", self.session.urls().base),
                    )
                    .await?
                    .json(&json!({
                        "Ids": self.ids
                    }));
                if let Some(v) = &continuation_token {
                    request = request.query(&[("continuationToken", v)])
                }
                let response = request
                    .send()
                    .await?
                    .parse::<ListResponse<_>>()
                    .await?;
                continuation_token = response.continuation_token;
                is_first_iteration = false;
                yield response.data;
            }
        }
    }
}

#[derive(Debug)]
pub struct Share<'session, TCache, PId, PCipher, PCollectionIds> {
    session: &'session mut Session<TCache>,
    id: PId,
    cipher: PCipher,
    collection_ids: PCollectionIds,
}

pub type DefaultShare<'session, TCache> = Share<'session, TCache, (), (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultShare<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            id: (),
            cipher: (),
            collection_ids: (),
        }
    }
}

impl<'session, TCache, PId, PCipher, PCollectionIds>
    Share<'session, TCache, PId, PCipher, PCollectionIds>
{
    pub fn id(self, id: Uuid) -> Share<'session, TCache, Uuid, PCipher, PCollectionIds> {
        Share {
            session: self.session,
            id,
            cipher: self.cipher,
            collection_ids: self.collection_ids,
        }
    }

    pub fn cipher(
        self,
        value: RequestModel,
    ) -> Share<'session, TCache, PId, RequestModel, PCollectionIds> {
        Share {
            session: self.session,
            id: self.id,
            cipher: value,
            collection_ids: self.collection_ids,
        }
    }

    pub fn collection_ids<I>(self, value: I) -> Share<'session, TCache, PId, PCipher, Vec<Uuid>>
    where
        I: IntoIterator<Item = Uuid>,
    {
        Share {
            session: self.session,
            id: self.id,
            cipher: self.cipher,
            collection_ids: value.into_iter().collect(),
        }
    }
}

impl<'session, TCache: Cache> Share<'session, TCache, Uuid, RequestModel, Vec<Uuid>> {
    pub async fn execute(&mut self) -> crate::Result<Cipher, TCache::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Request<'a> {
            cipher: &'a RequestModel,
            collection_ids: &'a Vec<Uuid>,
        }

        let request = Request {
            cipher: &self.cipher,
            collection_ids: &self.collection_ids,
        };
        Ok(self
            .session
            .request(
                Method::PUT,
                format!("{}/ciphers/{}/share", self.session.urls().base, self.id),
            )
            .await?
            .json(&request)
            .send()
            .await?
            .parse()
            .await?)
    }
}

#[derive(Debug)]
pub struct BulkShare<'session, TCache, PIds, PCiphers, PCollectionIds> {
    session: &'session mut Session<TCache>,
    ids: PIds,
    ciphers: PCiphers,
    collection_ids: PCollectionIds,
}

pub type DefaultBulkShare<'session, TCache> = BulkShare<'session, TCache, (), (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultBulkShare<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            ids: (),
            ciphers: (),
            collection_ids: (),
        }
    }
}

impl<'session, TCache, PIds, PCiphers, PCollectionIds>
    BulkShare<'session, TCache, PIds, PCiphers, PCollectionIds>
{
    pub fn ids<I>(
        self,
        value: I,
    ) -> BulkShare<'session, TCache, Vec<Uuid>, PCiphers, PCollectionIds>
    where
        I: IntoIterator<Item = Uuid>,
    {
        BulkShare {
            session: self.session,
            ids: value.into_iter().collect(),
            ciphers: self.ciphers,
            collection_ids: self.collection_ids,
        }
    }

    pub fn ciphers<I>(
        self,
        value: I,
    ) -> BulkShare<'session, TCache, PIds, HashMap<Uuid, RequestModel>, PCollectionIds>
    where
        I: IntoIterator<Item = (Uuid, RequestModel)>,
    {
        BulkShare {
            session: self.session,
            ids: self.ids,
            ciphers: value.into_iter().collect(),
            collection_ids: self.collection_ids,
        }
    }

    pub fn collection_ids<I>(
        self,
        value: I,
    ) -> BulkShare<'session, TCache, PIds, PCiphers, Vec<Uuid>>
    where
        I: IntoIterator<Item = Uuid>,
    {
        BulkShare {
            session: self.session,
            ids: self.ids,
            ciphers: self.ciphers,
            collection_ids: value.into_iter().collect(),
        }
    }
}

impl<'session, TCache: Cache>
    BulkShare<'session, TCache, Vec<Uuid>, HashMap<Uuid, RequestModel>, Vec<Uuid>>
{
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
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

        let request = Request {
            ciphers: self
                .ciphers
                .iter()
                .map(|(id, cipher)| RequestModelWithId { id, inner: cipher })
                .collect(),
            collection_ids: &self.collection_ids,
        };
        self.session
            .request(
                Method::PUT,
                format!("{}/ciphers/share", self.session.urls().base),
            )
            .await?
            .json(&request)
            .send()
            .await?
            .parse_empty()
            .await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct BulkMove<'session, TCache, PIds, PFolderId> {
    session: &'session mut Session<TCache>,
    ids: PIds,
    folder_id: PFolderId,
}

pub type DefaultBulkMove<'session, TCache> = BulkMove<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultBulkMove<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            ids: (),
            folder_id: (),
        }
    }
}

impl<'session, TCache, PIds, PFolderId> BulkMove<'session, TCache, PIds, PFolderId> {
    pub fn ids<I>(self, value: I) -> BulkMove<'session, TCache, Vec<Uuid>, PFolderId>
    where
        I: IntoIterator<Item = Uuid>,
    {
        BulkMove {
            session: self.session,
            ids: value.into_iter().collect(),
            folder_id: self.folder_id,
        }
    }

    pub fn folder_id(self, value: Option<Uuid>) -> BulkMove<'session, TCache, PIds, Option<Uuid>> {
        BulkMove {
            session: self.session,
            ids: self.ids,
            folder_id: value,
        }
    }
}

impl<'session, TCache: Cache> BulkMove<'session, TCache, Vec<Uuid>, Option<Uuid>> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        self.session
            .request(
                Method::PUT,
                format!("{}/ciphers/move", self.session.urls().base),
            )
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
    }
}

#[derive(Debug)]
pub struct Purge<'session, TCache, PMasterPasswordHash> {
    session: &'session mut Session<TCache>,
    master_password_hash: PMasterPasswordHash,
    organization_id: Option<Uuid>,
}

pub type DefaultPurge<'session, TCache> = Purge<'session, TCache, ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultPurge<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            master_password_hash: (),
            organization_id: None,
        }
    }
}

impl<'session, TCache, PMasterPasswordHash> Purge<'session, TCache, PMasterPasswordHash> {
    pub fn master_password_hash(
        self,
        value: MasterPasswordHash,
    ) -> Purge<'session, TCache, MasterPasswordHash> {
        Purge {
            session: self.session,
            master_password_hash: value,
            organization_id: self.organization_id,
        }
    }

    pub fn organization_id(self, value: Uuid) -> Purge<'session, TCache, PMasterPasswordHash> {
        Purge {
            session: self.session,
            master_password_hash: self.master_password_hash,
            organization_id: Some(value),
        }
    }
}

impl<'session, TCache: Cache> Purge<'session, TCache, MasterPasswordHash> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        let mut request = self
            .session
            .request(
                Method::POST,
                format!("{}/ciphers/purge", self.session.urls().base),
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
    }
}

#[derive(Debug)]
pub struct GetDetails<'session, TCache, PId> {
    session: &'session mut Session<TCache>,
    id: PId,
}

pub type DefaultGetDetails<'session, TCache> = GetDetails<'session, TCache, ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultGetDetails<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session, id: () }
    }
}

impl<'session, TCache, PId> GetDetails<'session, TCache, PId> {
    pub fn id(self, id: Uuid) -> GetDetails<'session, TCache, Uuid> {
        GetDetails {
            session: self.session,
            id,
        }
    }
}

impl<'session, TCache: Cache> GetDetails<'session, TCache, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<CipherDetails, TCache::Error> {
        let value = self
            .session
            .request(
                Method::GET,
                format!("{}/ciphers/{}/details", self.session.urls().base, self.id),
            )
            .await?
            .send()
            .await?
            .parse()
            .await?;
        self.session
            .cache_mut()
            .save_ciphers(std::iter::once(&value))
            .await
            .map_err(Error::Cache)?;
        Ok(value)
    }
}

#[derive(Debug)]
pub struct GetAllDetails<'session, TCache> {
    session: &'session mut Session<TCache>,
}

impl<'session, TCache> Request<'session, TCache> for GetAllDetails<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session }
    }
}

impl<'session, TCache: Cache> GetAllDetails<'session, TCache> {
    pub fn execute<'a: 'session>(
        &'a mut self,
    ) -> impl Stream<Item = crate::Result<Vec<CipherDetails>, TCache::Error>> + 'a {
        try_stream! {
            let mut continuation_token = None;
            let mut is_first_iteration = true;
            while continuation_token.is_some() || is_first_iteration {
                let mut request = self
                    .session
                    .request(
                        Method::GET,
                        format!("{}/ciphers", self.session.urls().base),
                    )
                    .await?;
                if let Some(v) = &continuation_token {
                    request = request.query(&[("continuationToken", v)])
                }
                let response = request
                    .send()
                    .await?
                    .parse::<ListResponse<_>>()
                    .await?;
                self.session
                    .cache_mut()
                    .save_ciphers(&response.data)
                    .await
                    .map_err(Error::Cache)?;
                continuation_token = response.continuation_token;
                is_first_iteration = false;
                yield response.data;
            }
        }
    }
}
