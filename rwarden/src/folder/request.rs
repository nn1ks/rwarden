use crate::util::{ListResponse, ResponseExt};
use crate::{cache::Cache, crypto::CipherString, folder::Folder, Error, Request, Session};
use async_stream::try_stream;
use futures::stream::Stream;
use reqwest::Method;
use serde_json::json;
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
    pub async fn execute(&mut self) -> crate::Result<Folder, TCache::Error> {
        let value = self
            .session
            .request(
                Method::GET,
                format!("{}/folders/{}", self.session.urls().base, self.id),
            )
            .await?
            .send()
            .await?
            .parse()
            .await?;
        self.session
            .cache_mut()
            .save_folders(std::iter::once(&value))
            .await
            .map_err(Error::Cache)?;
        Ok(value)
    }
}

#[derive(Debug)]
pub struct GetAll<'session, TCache> {
    session: &'session mut Session<TCache>,
}

impl<'session, TCache> Request<'session, TCache> for GetAll<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session }
    }
}

impl<'session, TCache: Cache> GetAll<'session, TCache> {
    pub fn execute<'a: 'session>(
        &'a mut self,
    ) -> impl Stream<Item = crate::Result<Vec<Folder>, TCache::Error>> + 'a {
        try_stream! {
            let mut continuation_token = None;
            let mut is_first_iteration = true;
            while continuation_token.is_some() || is_first_iteration {
                let mut request = self
                    .session
                    .request(
                        Method::GET,
                        format!("{}/folders", self.session.urls().base),
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
                    .save_folders(&response.data)
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
pub struct Create<'session, TCache, PName> {
    session: &'session mut Session<TCache>,
    name: PName,
}

pub type DefaultCreate<'session, TCache> = Create<'session, TCache, ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultCreate<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session, name: () }
    }
}

impl<'session, TCache, PName> Create<'session, TCache, PName> {
    pub fn name(self, value: CipherString) -> Create<'session, TCache, CipherString> {
        Create {
            session: self.session,
            name: value,
        }
    }
}

impl<'session, TCache: Cache> Create<'session, TCache, CipherString> {
    pub async fn execute(&mut self) -> crate::Result<Folder, TCache::Error> {
        let value = self
            .session
            .request(
                Method::POST,
                format!("{}/folders", self.session.urls().base),
            )
            .await?
            .json(&json!({
                "Name": self.name
            }))
            .send()
            .await?
            .parse()
            .await?;
        self.session
            .cache_mut()
            .save_folders(std::iter::once(&value))
            .await
            .map_err(Error::Cache)?;
        Ok(value)
    }
}

#[derive(Debug)]
pub struct Delete<'session, TCache, PId> {
    session: &'session mut Session<TCache>,
    id: PId,
}

pub type DefaultDelete<'session, TCache> = Delete<'session, TCache, ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultDelete<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session, id: () }
    }
}

impl<'session, TCache, PId> Delete<'session, TCache, PId> {
    pub fn id(self, id: Uuid) -> Delete<'session, TCache, Uuid> {
        Delete {
            session: self.session,
            id,
        }
    }
}

impl<'session, TCache: Cache> Delete<'session, TCache, Uuid> {
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        self.session
            .request(
                Method::DELETE,
                format!("{}/folders/{}", self.session.urls().base, self.id),
            )
            .await?
            .send()
            .await?
            .parse_empty()
            .await?;
        self.session
            .cache_mut()
            .delete_folders(std::iter::once(self.id))
            .await
            .map_err(Error::Cache)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Modify<'session, TCache, PId, PName> {
    session: &'session mut Session<TCache>,
    id: PId,
    name: PName,
}

pub type DefaultModify<'session, TCache> = Modify<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModify<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            id: (),
            name: (),
        }
    }
}

impl<'session, TCache, PId, PName> Modify<'session, TCache, PId, PName> {
    pub fn id(self, id: Uuid) -> Modify<'session, TCache, Uuid, PName> {
        Modify {
            session: self.session,
            id,
            name: self.name,
        }
    }

    pub fn name(self, value: CipherString) -> Modify<'session, TCache, PId, CipherString> {
        Modify {
            session: self.session,
            id: self.id,
            name: value,
        }
    }
}

impl<'session, TCache: Cache> Modify<'session, TCache, Uuid, CipherString> {
    pub async fn execute(&mut self) -> crate::Result<Folder, TCache::Error> {
        let value = self
            .session
            .request(
                Method::PUT,
                format!("{}/folders/{}", self.session.urls().base, self.id),
            )
            .await?
            .json(&json!({
                "Name": self.name
            }))
            .send()
            .await?
            .parse()
            .await?;
        self.session
            .cache_mut()
            .save_folders(std::iter::once(&value))
            .await
            .map_err(Error::Cache)?;
        Ok(value)
    }
}
