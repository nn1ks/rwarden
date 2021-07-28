use crate::{cache::Cache, sync::Sync, util::ResponseExt, Error, Request, Session};
use reqwest::Method;

#[derive(Debug)]
pub struct Get<'session, TCache> {
    session: &'session mut Session<TCache>,
}

impl<'session, TCache> Request<'session, TCache> for Get<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session }
    }
}

impl<'session, TCache: Cache> Get<'session, TCache> {
    pub async fn execute(&mut self) -> crate::Result<Sync, TCache::Error> {
        let value = self
            .session
            .request(Method::GET, format!("{}/sync", self.session.urls().base))
            .await?
            .query(&[("excludeDomains", false)])
            .send()
            .await?
            .parse()
            .await?;
        self.session
            .cache_mut()
            .sync(&value)
            .await
            .map_err(Error::Cache)?;
        Ok(value)
    }
}
