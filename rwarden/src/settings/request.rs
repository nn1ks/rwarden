use crate::settings::{Domains, EquivalentDomains, GlobalEquivalentDomainsType};
use crate::{cache::Cache, util::ResponseExt, Client, Error, Request};
use futures_core::future::BoxFuture;
use reqwest::Method;
use serde::Serialize;
use typed_builder::TypedBuilder;

/// A [`Request`] for retrieving domain settings.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GetDomains;

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for GetDomains
{
    type Output = BoxFuture<'request, crate::Result<Domains, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(
                    Method::GET,
                    format!("{}/settings/domains", client.urls().base),
                )
                .await?
                .send()
                .await?
                .parse()
                .await?;
            client
                .cache_mut()
                .save_domains(&value)
                .await
                .map_err(Error::Cache)?;
            Ok(value)
        })
    }
}

/// A [`Request`] for modifying domain settings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyDomains {
    pub equivalent_domains: Vec<EquivalentDomains>,
    pub excluded_global_equivalent_domains: Vec<GlobalEquivalentDomainsType>,
}

impl ModifyDomains {
    #[allow(clippy::type_complexity)]
    pub fn inherit(
        domains: Domains,
    ) -> ModifyDomainsBuilder<(
        (Vec<EquivalentDomains>,),
        (Vec<GlobalEquivalentDomainsType>,),
    )> {
        ModifyDomainsBuilder {
            fields: (
                (domains.equivalent_domains,),
                (domains
                    .global_equivalent_domains
                    .into_iter()
                    .filter(|v| v.excluded)
                    .map(|v| v.ty)
                    .collect(),),
            ),
            phantom: (),
        }
    }
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for ModifyDomains
{
    type Output = BoxFuture<'request, crate::Result<Domains, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(
                    Method::PUT,
                    format!("{}/settings/domains", client.urls().base),
                )
                .await?
                .json(self)
                .send()
                .await?
                .parse()
                .await?;
            client
                .cache_mut()
                .save_domains(&value)
                .await
                .map_err(Error::Cache)?;
            Ok(value)
        })
    }
}
