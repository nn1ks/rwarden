use crate::cipher::{Cipher, RequestModel};
use crate::{util::ResponseExt, Result, Session};
use async_trait::async_trait;
use derive_setters::Setters;
use reqwest::Method;
use serde::Serialize;
use uuid::Uuid;

/// A type for modifying a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Modifier {
    #[serde(flatten)]
    pub inner: RequestModel,
}

impl Modifier {
    /// Creates a new [`Modifier`].
    pub fn new(inner: RequestModel) -> Self {
        Self { inner }
    }
}

#[async_trait(?Send)]
impl crate::Modifier for Modifier {
    type Id = Uuid;
    type Response = Cipher;
    async fn execute(&self, session: &mut Session, id: Self::Id) -> crate::Result<Self::Response> {
        session
            .request(Method::PUT, |urls| &urls.base, path!("ciphers", id))
            .await?
            .json(self)
            .send()
            .await?
            .parse()
            .await
    }
}

/// A type for partially modifying a cipher.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Setters, Serialize)]
#[setters(strip_option, prefix = "with_")]
#[serde(rename_all = "PascalCase")]
pub struct PartialModifier {
    pub folder_id: Option<Uuid>,
    pub favorite: Option<bool>,
}

impl PartialModifier {
    /// Creates a new [`PartialModifier`].
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait(?Send)]
impl crate::Modifier for PartialModifier {
    type Id = Uuid;
    type Response = ();
    async fn execute(&self, session: &mut Session, id: Self::Id) -> Result<Self::Response> {
        session
            .request(
                Method::PUT,
                |urls| &urls.base,
                path!("ciphers", id, "partial"),
            )
            .await?
            .json(self)
            .send()
            .await?
            .parse_empty()
            .await
    }
}

/// A type for modifying which collections a cipher is part of.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CollectionModifier {
    pub collection_ids: Vec<Uuid>,
}

impl CollectionModifier {
    /// Creates a new [`CollectionModifier`].
    pub fn new(collection_ids: Vec<Uuid>) -> Self {
        Self { collection_ids }
    }
}

#[async_trait(?Send)]
impl crate::Modifier for CollectionModifier {
    type Id = Uuid;
    type Response = ();
    async fn execute(&self, session: &mut Session, id: Self::Id) -> Result<Self::Response> {
        session
            .request(
                Method::PUT,
                |urls| &urls.base,
                path!("ciphers", id, "collections"),
            )
            .await?
            .json(self)
            .send()
            .await?
            .parse_empty()
            .await
    }
}
