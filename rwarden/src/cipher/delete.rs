use crate::{util::ResponseExt, Result, Session};
use async_trait::async_trait;
use derive_setters::Setters;
use reqwest::Method;
use serde_json::json;
use uuid::Uuid;

/// A type for deleting a cipher.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Deleter {
    pub soft_delete: bool,
}

impl Deleter {
    /// Creates a new [`Deleter`].
    pub fn new(soft_delete: bool) -> Self {
        Self { soft_delete }
    }
}

#[async_trait(?Send)]
impl crate::Deleter for Deleter {
    type Id = Uuid;
    async fn execute(&self, session: &mut Session, id: Self::Id) -> Result<()> {
        let (method, path) = if self.soft_delete {
            (Method::PUT, path!("ciphers", id, "delete"))
        } else {
            (Method::DELETE, path!("ciphers", id))
        };
        session
            .request(method, |urls| &urls.base, path)
            .await?
            .send()
            .await?
            .parse_empty()
            .await
    }
}

// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// pub struct DeleterAdmin {
//     pub soft_delete: bool,
// }

// impl DeleterAdmin {
//     pub fn new(soft_delete: bool) -> Self {
//         Self { soft_delete }
//     }
// }

// impl crate::Deleter for DeleterAdmin {
//     type Id = Uuid;
//     fn path_segments(&self, id: Self::Id) -> Vec<String> {
//         path!("chipers", "delete-admin")
//     }
// }

/// A type for bulk deleting ciphers.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Setters)]
#[setters(strip_option, prefix = "with_")]
pub struct BulkDeleter {
    #[setters(bool)]
    pub soft_delete: bool,
    pub organization_id: Option<Uuid>,
}

impl BulkDeleter {
    /// Creates a new [`BulkDeleter`].
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait(?Send)]
impl crate::BulkDeleter for BulkDeleter {
    type Id = Uuid;
    async fn execute<I>(&self, session: &mut Session, ids: I) -> Result<()>
    where
        I: IntoIterator<Item = Self::Id>,
    {
        let (method, path) = if self.soft_delete {
            (Method::PUT, path!("ciphers", "delete"))
        } else {
            (Method::DELETE, path!("ciphers"))
        };
        let body = json!({
            "Ids": ids.into_iter().collect::<Vec<_>>(),
            "OrganizationId": self.organization_id,
        });
        session
            .request(method, |urls| &urls.base, path)
            .await?
            .json(&body)
            .send()
            .await?
            .parse_empty()
            .await
    }
}
