use crate::collection::{
    Collection, CollectionDetails, CollectionGroupDetails, SelectionReadOnlyRequestModel, Users,
};
use crate::util::{ListResponse, ResponseExt};
use crate::{cache::Cache, crypto::CipherString, Error, Request, Session};
use async_stream::try_stream;
use futures::stream::Stream;
use reqwest::Method;
use serde_json::json;
use uuid::Uuid;

#[derive(Debug)]
pub struct Get<'session, TCache, POrganizationId, PCollectionId> {
    session: &'session mut Session<TCache>,
    organization_id: POrganizationId,
    collection_id: PCollectionId,
}

pub type DefaultGet<'session, TCache> = Get<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultGet<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            organization_id: (),
            collection_id: (),
        }
    }
}

impl<'session, TCache, POrganizationId, PCollectionId>
    Get<'session, TCache, POrganizationId, PCollectionId>
{
    pub fn organization_id(self, value: Uuid) -> Get<'session, TCache, Uuid, PCollectionId> {
        Get {
            session: self.session,
            organization_id: value,
            collection_id: self.collection_id,
        }
    }

    pub fn collection_id(self, value: Uuid) -> Get<'session, TCache, POrganizationId, Uuid> {
        Get {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: value,
        }
    }
}

impl<'session, TCache: Cache> Get<'session, TCache, Uuid, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<Collection, TCache::Error> {
        Ok(self
            .session
            .request(
                Method::GET,
                format!(
                    "{}/organizations/{}/collections/{}",
                    self.session.urls().base,
                    self.organization_id,
                    self.collection_id
                ),
            )
            .await?
            .send()
            .await?
            .parse()
            .await?)
    }
}

#[derive(Debug)]
pub struct GetAll<'session, TCache, POrganizationId> {
    session: &'session mut Session<TCache>,
    organization_id: POrganizationId,
}

pub type DefaultGetAll<'session, TCache> = GetAll<'session, TCache, ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultGetAll<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            organization_id: (),
        }
    }
}

impl<'session, TCache: Cache, POrganizationId> GetAll<'session, TCache, POrganizationId> {
    pub fn organization_id(self, value: Uuid) -> GetAll<'session, TCache, Uuid> {
        GetAll {
            session: self.session,
            organization_id: value,
        }
    }
}

impl<'session, TCache: Cache> GetAll<'session, TCache, Uuid> {
    pub fn execute<'a: 'session>(
        &'a mut self,
    ) -> impl Stream<Item = crate::Result<Vec<Collection>, TCache::Error>> + 'a {
        try_stream! {
            let mut continuation_token = None;
            let mut is_first_iteration = true;
            while continuation_token.is_some() || is_first_iteration {
                let mut request = self
                    .session
                    .request(
                        Method::GET,
                        format!(
                            "{}/organizations/{}/collections",
                            self.session.urls().base,
                            self.organization_id
                        ),
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
                continuation_token = response.continuation_token;
                is_first_iteration = false;
                yield response.data;
            }
        }
    }
}

#[derive(Debug)]
pub struct Create<'session, TCache, POrganizationId, PName> {
    session: &'session mut Session<TCache>,
    organization_id: POrganizationId,
    name: PName,
    external_id: Option<Uuid>,
    groups: Option<Vec<SelectionReadOnlyRequestModel>>,
}

pub type DefaultCreate<'session, TCache> = Create<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultCreate<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            organization_id: (),
            name: (),
            external_id: None,
            groups: None,
        }
    }
}

impl<'session, TCache, POrganizationId, PName> Create<'session, TCache, POrganizationId, PName> {
    pub fn organization_id(self, value: Uuid) -> Create<'session, TCache, Uuid, PName> {
        Create {
            session: self.session,
            organization_id: value,
            name: self.name,
            external_id: self.external_id,
            groups: self.groups,
        }
    }

    pub fn name(
        self,
        value: CipherString,
    ) -> Create<'session, TCache, POrganizationId, CipherString> {
        Create {
            session: self.session,
            organization_id: self.organization_id,
            name: value,
            external_id: self.external_id,
            groups: self.groups,
        }
    }

    pub fn external_id(mut self, value: Uuid) -> Self {
        self.external_id = Some(value);
        self
    }

    pub fn groups<I>(mut self, value: I) -> Self
    where
        I: IntoIterator<Item = SelectionReadOnlyRequestModel>,
    {
        self.groups = Some(value.into_iter().collect());
        self
    }
}

impl<'session, TCache: Cache> Create<'session, TCache, Uuid, CipherString> {
    pub async fn execute(&mut self) -> crate::Result<Collection, TCache::Error> {
        Ok(self
            .session
            .request(
                Method::POST,
                format!(
                    "{}/organizations/{}/collections",
                    self.session.urls().base,
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
    }
}

#[derive(Debug)]
pub struct Delete<'session, TCache, POrganizationId, PCollectionId> {
    session: &'session mut Session<TCache>,
    organization_id: POrganizationId,
    collection_id: PCollectionId,
}

pub type DefaultDelete<'session, TCache> = Delete<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultDelete<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            organization_id: (),
            collection_id: (),
        }
    }
}

impl<'session, TCache, POrganizationId, PCollectionId>
    Delete<'session, TCache, POrganizationId, PCollectionId>
{
    pub fn organization_id(self, value: Uuid) -> Delete<'session, TCache, Uuid, PCollectionId> {
        Delete {
            session: self.session,
            organization_id: value,
            collection_id: self.collection_id,
        }
    }

    pub fn collection_id(self, value: Uuid) -> Delete<'session, TCache, POrganizationId, Uuid> {
        Delete {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: value,
        }
    }
}

impl<'session, TCache: Cache> Delete<'session, TCache, Uuid, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        self.session
            .request(
                Method::DELETE,
                format!(
                    "{}/organizations/{}/collections/{}",
                    self.session.urls().base,
                    self.organization_id,
                    self.collection_id
                ),
            )
            .await?
            .send()
            .await?
            .parse_empty()
            .await?;
        self.session
            .cache_mut()
            .delete_collections(std::iter::once(self.collection_id))
            .await
            .map_err(Error::Cache)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Modify<'session, TCache, POrganizationId, PCollectionId, PName> {
    session: &'session mut Session<TCache>,
    organization_id: POrganizationId,
    collection_id: PCollectionId,
    name: PName,
    external_id: Option<Uuid>,
    groups: Option<Vec<SelectionReadOnlyRequestModel>>,
}

pub type DefaultModify<'session, TCache> = Modify<'session, TCache, (), (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModify<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            organization_id: (),
            collection_id: (),
            name: (),
            external_id: None,
            groups: None,
        }
    }
}

impl<'session, TCache, POrganizationId, PCollectionId, PName>
    Modify<'session, TCache, POrganizationId, PCollectionId, PName>
{
    pub fn organization_id(
        self,
        value: Uuid,
    ) -> Modify<'session, TCache, Uuid, PCollectionId, PName> {
        Modify {
            session: self.session,
            organization_id: value,
            collection_id: self.collection_id,
            name: self.name,
            external_id: self.external_id,
            groups: self.groups,
        }
    }

    pub fn collection_id(
        self,
        value: Uuid,
    ) -> Modify<'session, TCache, POrganizationId, Uuid, PName> {
        Modify {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: value,
            name: self.name,
            external_id: self.external_id,
            groups: self.groups,
        }
    }

    pub fn name(
        self,
        value: CipherString,
    ) -> Modify<'session, TCache, POrganizationId, PCollectionId, CipherString> {
        Modify {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: self.collection_id,
            name: value,
            external_id: self.external_id,
            groups: self.groups,
        }
    }

    pub fn external_id(mut self, value: Uuid) -> Self {
        self.external_id = Some(value);
        self
    }

    pub fn groups<I>(mut self, value: I) -> Self
    where
        I: IntoIterator<Item = SelectionReadOnlyRequestModel>,
    {
        self.groups = Some(value.into_iter().collect());
        self
    }
}

impl<'session, TCache: Cache> Modify<'session, TCache, Uuid, Uuid, CipherString> {
    pub async fn execute(&mut self) -> crate::Result<Collection, TCache::Error> {
        Ok(self
            .session
            .request(
                Method::PUT,
                format!(
                    "{}/organizations/{}/collections/{}",
                    self.session.urls().base,
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
    }
}

#[derive(Debug)]
pub struct GetGroupDetails<'session, TCache, POrganizationId, PCollectionId> {
    session: &'session mut Session<TCache>,
    organization_id: POrganizationId,
    collection_id: PCollectionId,
}

pub type DefaultGetGroupDetails<'session, TCache> = GetGroupDetails<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultGetGroupDetails<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            organization_id: (),
            collection_id: (),
        }
    }
}

impl<'session, TCache, POrganizationId, PCollectionId>
    GetGroupDetails<'session, TCache, POrganizationId, PCollectionId>
{
    pub fn organization_id(
        self,
        value: Uuid,
    ) -> GetGroupDetails<'session, TCache, Uuid, PCollectionId> {
        GetGroupDetails {
            session: self.session,
            organization_id: value,
            collection_id: self.collection_id,
        }
    }

    pub fn collection_id(
        self,
        value: Uuid,
    ) -> GetGroupDetails<'session, TCache, POrganizationId, Uuid> {
        GetGroupDetails {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: value,
        }
    }
}

impl<'session, TCache: Cache> GetGroupDetails<'session, TCache, Uuid, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<CollectionGroupDetails, TCache::Error> {
        Ok(self
            .session
            .request(
                Method::GET,
                format!(
                    "{}/organizations/{}/collections/{}/details",
                    self.session.urls().base,
                    self.organization_id,
                    self.collection_id
                ),
            )
            .await?
            .send()
            .await?
            .parse()
            .await?)
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
    ) -> impl Stream<Item = crate::Result<Vec<CollectionDetails>, TCache::Error>> + 'a {
        try_stream! {
            let mut continuation_token = None;
            let mut is_first_iteration = true;
            while continuation_token.is_some() || is_first_iteration {
                let mut request = self
                    .session
                    .request(
                        Method::GET,
                        format!("{}/collections", self.session.urls().base),
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
                self
                    .session
                    .cache_mut()
                    .save_collections(&response.data)
                    .await
                    .map_err(Error::Cache)?;
                continuation_token = response.continuation_token;
                is_first_iteration = false;
                yield response.data;
            }
        }
    }
}

#[derive(Debug)]
pub struct GetUsers<'session, TCache, POrganizationId, PCollectionId> {
    session: &'session mut Session<TCache>,
    organization_id: POrganizationId,
    collection_id: PCollectionId,
}

pub type DefaultGetUsers<'session, TCache> = GetUsers<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultGetUsers<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            organization_id: (),
            collection_id: (),
        }
    }
}

impl<'session, TCache, POrganizationId, PCollectionId>
    GetUsers<'session, TCache, POrganizationId, PCollectionId>
{
    pub fn organization_id(self, value: Uuid) -> GetUsers<'session, TCache, Uuid, PCollectionId> {
        GetUsers {
            session: self.session,
            organization_id: value,
            collection_id: self.collection_id,
        }
    }

    pub fn collection_id(self, value: Uuid) -> GetUsers<'session, TCache, POrganizationId, Uuid> {
        GetUsers {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: value,
        }
    }
}

impl<'session, TCache: Cache> GetUsers<'session, TCache, Uuid, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<Users, TCache::Error> {
        Ok(self
            .session
            .request(
                Method::GET,
                format!(
                    "{}/organizations/{}/collections/{}/users",
                    self.session.urls().base,
                    self.organization_id,
                    self.collection_id
                ),
            )
            .await?
            .send()
            .await?
            .parse()
            .await?)
    }
}

#[derive(Debug)]
pub struct ModifyUsers<'session, TCache, POrganizationId, PCollectionId, PUsers> {
    session: &'session mut Session<TCache>,
    organization_id: POrganizationId,
    collection_id: PCollectionId,
    users: PUsers,
}

pub type DefaultModifyUsers<'session, TCache> = ModifyUsers<'session, TCache, (), (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModifyUsers<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            organization_id: (),
            collection_id: (),
            users: (),
        }
    }
}

impl<'session, TCache, POrganizationId, PCollectionId, PUsers>
    ModifyUsers<'session, TCache, POrganizationId, PCollectionId, PUsers>
{
    pub fn organization_id(
        self,
        value: Uuid,
    ) -> ModifyUsers<'session, TCache, Uuid, PCollectionId, PUsers> {
        ModifyUsers {
            session: self.session,
            organization_id: value,
            collection_id: self.collection_id,
            users: self.users,
        }
    }

    pub fn collection_id(
        self,
        value: Uuid,
    ) -> ModifyUsers<'session, TCache, POrganizationId, Uuid, PUsers> {
        ModifyUsers {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: value,
            users: self.users,
        }
    }

    pub fn users(
        self,
        value: Users,
    ) -> ModifyUsers<'session, TCache, POrganizationId, PCollectionId, Users> {
        ModifyUsers {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: self.collection_id,
            users: value,
        }
    }
}

impl<'session, TCache: Cache> ModifyUsers<'session, TCache, Uuid, Uuid, Users> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        Ok(self
            .session
            .request(
                Method::PUT,
                format!(
                    "{}/organizations/{}/collections/{}/users",
                    self.session.urls().base,
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
    }
}

#[derive(Debug)]
pub struct DeleteUser<'session, TCache, POrganizationId, PCollectionId, POrganizationUserId> {
    session: &'session mut Session<TCache>,
    organization_id: POrganizationId,
    collection_id: PCollectionId,
    organization_user_id: POrganizationUserId,
}

pub type DefaultDeleteUser<'session, TCache> = DeleteUser<'session, TCache, (), (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultDeleteUser<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            organization_id: (),
            collection_id: (),
            organization_user_id: (),
        }
    }
}

impl<'session, TCache, POrganizationId, PCollectionId, POrganizationUserId>
    DeleteUser<'session, TCache, POrganizationId, PCollectionId, POrganizationUserId>
{
    pub fn organization_id(
        self,
        value: Uuid,
    ) -> DeleteUser<'session, TCache, Uuid, PCollectionId, POrganizationUserId> {
        DeleteUser {
            session: self.session,
            organization_id: value,
            collection_id: self.collection_id,
            organization_user_id: self.organization_user_id,
        }
    }

    pub fn collection_id(
        self,
        value: Uuid,
    ) -> DeleteUser<'session, TCache, POrganizationId, Uuid, POrganizationUserId> {
        DeleteUser {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: value,
            organization_user_id: self.organization_user_id,
        }
    }

    pub fn organization_user_id(
        self,
        value: Uuid,
    ) -> DeleteUser<'session, TCache, POrganizationId, PCollectionId, Uuid> {
        DeleteUser {
            session: self.session,
            organization_id: self.organization_id,
            collection_id: self.collection_id,
            organization_user_id: value,
        }
    }
}

impl<'session, TCache: Cache> DeleteUser<'session, TCache, Uuid, Uuid, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        self.session
            .request(
                Method::DELETE,
                format!(
                    "{}/organizations/{}/collections/{}/user/{}",
                    self.session.urls().base,
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
    }
}
