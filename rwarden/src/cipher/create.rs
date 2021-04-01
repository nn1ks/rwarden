use crate::cipher::{Cipher, Owner, RequestModel};
use crate::{util::ResponseExt, Result, Session};
use async_trait::async_trait;
use reqwest::Method;
use serde::Serialize;

// https://github.com/bitwarden/server/blob/v1.40.0/src/Core/Models/Api/Request/CipherRequestModel.cs
/// A type for creating a cipher resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Creator {
    #[serde(flatten)]
    pub inner: RequestModel,
    #[serde(skip_serializing_if = "Owner::is_user")]
    #[serde(flatten)]
    pub owner: Owner,
}

impl Creator {
    pub fn new(inner: RequestModel, owner: Owner) -> Self {
        Self { inner, owner }
    }
}

#[async_trait(?Send)]
impl crate::Creator for Creator {
    type Response = Cipher;
    async fn execute(&self, session: &mut Session) -> Result<Self::Response> {
        let path = match self.owner {
            Owner::User => path!("ciphers"),
            Owner::Organization { .. } => path!("ciphers", "create"),
        };
        session
            .request(Method::POST, |urls| &urls.base, path)
            .await?
            .json(self)
            .send()
            .await?
            .parse()
            .await
    }
}
