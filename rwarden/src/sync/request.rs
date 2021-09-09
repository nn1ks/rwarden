use crate::{cache::Cache, sync::Sync, util::ResponseExt, Client, Error, Request};
use futures_core::future::BoxFuture;
use reqwest::Method;

/// A [`Request`] for retrieving synchronization response.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Get;

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache> for Get {
    type Output = BoxFuture<'request, crate::Result<Sync, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(Method::GET, format!("{}/sync", client.urls().base))
                .await?
                .query(&[("excludeDomains", false)])
                .send()
                .await?
                .parse()
                .await?;
            client
                .cache_mut()
                .sync(&value)
                .await
                .map_err(Error::Cache)?;
            Ok(value)
        })
    }
}
