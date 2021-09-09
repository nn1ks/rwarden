use crate::crypto::{KdfType, MasterPasswordHash, SymmetricEncryptedBytes};
use crate::{account::Account, cache::Cache, util::ResponseExt, Client, Error, Request};
use futures_core::future::BoxFuture;
use reqwest::Method;
use serde::Serialize;
use typed_builder::TypedBuilder;

/// A [`Request`] for retrieving an account.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Get;

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache> for Get {
    type Output = BoxFuture<'request, crate::Result<Account, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(
                    Method::GET,
                    format!("{}/accounts/profile", client.urls().base),
                )
                .await?
                .send()
                .await?
                .parse()
                .await?;
            client
                .cache_mut()
                .save_account(&value)
                .await
                .map_err(Error::Cache)?;
            Ok(value)
        })
    }
}

/// A [`Request`] for modifying an account.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyProfile {
    #[builder(default, setter(into, strip_option))]
    pub name: Option<String>,
    #[builder(default, setter(into, strip_option))]
    pub master_password_hint: Option<String>,
    #[builder(default, setter(into, strip_option))]
    pub culture: Option<String>,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for ModifyProfile
{
    type Output = BoxFuture<'request, crate::Result<Account, TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            let value = client
                .request(
                    Method::PUT,
                    format!("{}/accounts/profile", client.urls().base),
                )
                .await?
                .json(self)
                .send()
                .await?
                .parse()
                .await?;
            client
                .cache_mut()
                .save_account(&value)
                .await
                .map_err(Error::Cache)?;
            Ok(value)
        })
    }
}

/// A [`Request`] for modifying the email address of an account.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyEmail {
    #[builder(setter(into))]
    pub new_email: String,
    pub master_password_hash: MasterPasswordHash,
    pub new_master_password_hash: MasterPasswordHash,
    #[builder(setter(into))]
    pub token: String,
    pub key: SymmetricEncryptedBytes,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for ModifyEmail
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            client
                .request(
                    Method::PUT,
                    format!("{}/accounts/email", client.urls().base),
                )
                .await?
                .json(self)
                .send()
                .await?
                .parse_empty()
                .await?;
            Ok(())
        })
    }
}

/// A [`Request`] for modifying the password of an account.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyPassword {
    pub master_password_hash: MasterPasswordHash,
    pub new_master_password_hash: MasterPasswordHash,
    pub key: SymmetricEncryptedBytes,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for ModifyPassword
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            client
                .request(
                    Method::PUT,
                    format!("{}/accounts/password", client.urls().base),
                )
                .await?
                .json(self)
                .send()
                .await?
                .parse_empty()
                .await?;
            Ok(())
        })
    }
}

/// A [`Request`] for modifying the KDF type and iterations of an account.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyKdf {
    pub kdf_type: KdfType,
    pub kdf_iterations: u32,
    pub master_password_hash: MasterPasswordHash,
    pub new_master_password_hash: MasterPasswordHash,
    pub key: SymmetricEncryptedBytes,
}

impl<'request, 'client: 'request, TCache: Cache + Send> Request<'request, 'client, TCache>
    for ModifyKdf
{
    type Output = BoxFuture<'request, crate::Result<(), TCache::Error>>;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output {
        Box::pin(async move {
            client
                .request(Method::PUT, format!("{}/accounts/kdf", client.urls().base))
                .await?
                .json(self)
                .send()
                .await?
                .parse_empty()
                .await?;
            Ok(())
        })
    }
}
