use crate::settings::{Domains, EquivalentDomains, GlobalEquivalentDomainsType};
use crate::{cache::Cache, util::ResponseExt, Error, Request, Session};
use reqwest::Method;
use serde_json::json;

#[derive(Debug)]
pub struct GetDomains<'session, TCache> {
    session: &'session mut Session<TCache>,
}

impl<'session, TCache> Request<'session, TCache> for GetDomains<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session }
    }
}

impl<'session, TCache: Cache> GetDomains<'session, TCache> {
    pub async fn execute(&mut self) -> crate::Result<Domains, TCache::Error> {
        let value = self
            .session
            .request(
                Method::GET,
                format!("{}/settings/domains", self.session.urls().base),
            )
            .await?
            .send()
            .await?
            .parse()
            .await?;
        self.session
            .cache_mut()
            .save_domains(&value)
            .await
            .map_err(Error::Cache)?;
        Ok(value)
    }
}

#[derive(Debug)]
pub struct ModifyDomains<'session, TCache, PEquivalentDomains, PGlobalEquivalentDomains> {
    session: &'session mut Session<TCache>,
    equivalent_domains: PEquivalentDomains,
    global_equivalent_domains: PGlobalEquivalentDomains,
}

pub type DefaultModifyDomains<'session, TCache> = ModifyDomains<'session, TCache, (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModifyDomains<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            equivalent_domains: (),
            global_equivalent_domains: (),
        }
    }
}
impl<'session, TCache, PEquivalentDomains, PGlobalEquivalentDomains>
    ModifyDomains<'session, TCache, PEquivalentDomains, PGlobalEquivalentDomains>
{
    pub fn equivalent_domains<I>(
        self,
        value: I,
    ) -> ModifyDomains<'session, TCache, Vec<EquivalentDomains>, PGlobalEquivalentDomains>
    where
        I: IntoIterator<Item = EquivalentDomains>,
    {
        ModifyDomains {
            session: self.session,
            equivalent_domains: value.into_iter().collect(),
            global_equivalent_domains: self.global_equivalent_domains,
        }
    }

    pub fn global_equivalent_domains<I>(
        self,
        value: I,
    ) -> ModifyDomains<'session, TCache, PEquivalentDomains, Vec<GlobalEquivalentDomainsType>>
    where
        I: IntoIterator<Item = GlobalEquivalentDomainsType>,
    {
        ModifyDomains {
            session: self.session,
            equivalent_domains: self.equivalent_domains,
            global_equivalent_domains: value.into_iter().collect(),
        }
    }
}

impl<'session, TCache: Cache>
    ModifyDomains<'session, TCache, Vec<EquivalentDomains>, Vec<GlobalEquivalentDomainsType>>
{
    pub async fn execute(&mut self) -> crate::Result<Domains, TCache::Error> {
        let value = self
            .session
            .request(
                Method::PUT,
                format!("{}/settings/domains", self.session.urls().base),
            )
            .await?
            .json(&json!({
                "EquivalentDomains": self.equivalent_domains,
                "GlobalEquivalentDomains": self.global_equivalent_domains,
            }))
            .send()
            .await?
            .parse()
            .await?;
        self.session
            .cache_mut()
            .save_domains(&value)
            .await
            .map_err(Error::Cache)?;
        Ok(value)
    }
}
