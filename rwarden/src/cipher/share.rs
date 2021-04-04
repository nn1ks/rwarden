use crate::cipher::{Cipher, RequestModel, RequestModelWithId};
use crate::{util::ResponseExt, Result, Session};
use async_trait::async_trait;
use derive_setters::Setters;
use reqwest::Method;
use serde::Serialize;
use uuid::Uuid;

/// A type for sharing a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Setters, Serialize)]
#[setters(prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct Sharer {
    #[setters(skip)]
    pub cipher: RequestModel,
    pub collection_ids: Vec<Uuid>,
}

impl Sharer {
    /// Creates a new [`Sharer`].
    pub fn new(cipher: RequestModel) -> Self {
        Self {
            cipher,
            collection_ids: Vec::new(),
        }
    }
}

#[async_trait(?Send)]
impl crate::Sharer for Sharer {
    type Id = Uuid;
    type Response = Cipher;
    async fn execute(&self, session: &mut Session, id: Self::Id) -> Result<Self::Response> {
        session
            .request(
                Method::PUT,
                |urls| &urls.base,
                path!("ciphers", id, "share"),
            )
            .await?
            .json(self)
            .send()
            .await?
            .parse()
            .await
    }
}

/// A type for sharing multiple ciphers.
#[derive(Debug, Clone, PartialEq, Eq, Setters, Serialize)]
#[setters(prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct BulkSharer {
    #[setters(skip)]
    pub ciphers: Vec<RequestModelWithId>,
    pub collection_ids: Vec<Uuid>,
}

impl BulkSharer {
    /// Creates a new [`BulkSharer`].
    pub fn new(ciphers: Vec<RequestModelWithId>) -> Self {
        Self {
            ciphers,
            collection_ids: Vec::new(),
        }
    }
}

#[async_trait(?Send)]
impl crate::BulkSharer for BulkSharer {
    type Response = ();
    async fn execute(&self, session: &mut Session) -> Result<Self::Response> {
        session
            .request(Method::PUT, |urls| &urls.base, path!("ciphers", "share"))
            .await?
            .json(self)
            .send()
            .await?
            .parse_empty()
            .await
    }
}
