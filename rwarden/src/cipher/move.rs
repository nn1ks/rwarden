use crate::{util::ResponseExt, Result, Session};
use async_trait::async_trait;
use reqwest::Method;
use serde_json::json;
use uuid::Uuid;

/// A type for bulk moving ciphers to a folder.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BulkMover {
    pub folder_id: Option<Uuid>,
}

impl BulkMover {
    /// Creates a new [`BulkMover`].
    pub fn new(folder_id: Option<Uuid>) -> Self {
        Self { folder_id }
    }
}

#[async_trait(?Send)]
impl crate::BulkMover for BulkMover {
    type Id = Uuid;
    async fn execute<I>(&self, session: &mut Session, ids: I) -> Result<()>
    where
        I: IntoIterator<Item = Self::Id>,
    {
        let body = json!({
            "FolderId": self.folder_id,
            "Ids": ids.into_iter().collect::<Vec<_>>(),
        });
        session
            .request(Method::PUT, |urls| &urls.base, path!("ciphers", "move"))
            .await?
            .json(&body)
            .send()
            .await?
            .parse()
            .await
    }
}
