use crate::{util::ResponseExt, CipherString, Result, Session};
use async_trait::async_trait;
use derive_setters::Setters;
use reqwest::Method;
use serde::Serialize;
use uuid::Uuid;

/// A type for purging all ciphers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Setters, Serialize)]
#[setters(strip_option, prefix = "with_")]
pub struct Purger {
    #[setters(skip)]
    #[serde(rename = "MasterPasswordHash")]
    pub master_password: CipherString,
    #[serde(skip)]
    pub organization_id: Option<Uuid>,
}

impl Purger {
    /// Creates a new [`Purger`].
    pub fn new(master_password: CipherString) -> Self {
        Self {
            master_password,
            organization_id: None,
        }
    }
}

#[async_trait(?Send)]
impl crate::Purger for Purger {
    async fn execute(&self, session: &mut Session) -> Result<()> {
        session
            .request(Method::POST, |urls| &urls.base, path!("ciphers", "purge"))
            .await?
            .query(&[("organizationId", self.organization_id)])
            .json(self)
            .send()
            .await?
            .parse()
            .await
    }
}
