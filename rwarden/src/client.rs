use crate::util::{self, ResponseExt};
use crate::{
    account, cache::Cache, AccessTokenData, Request, RequestResponseError, TokenResponse, Urls,
};
use reqwest::{header, IntoUrl, Method, RequestBuilder};
use rwarden_crypto::{Keys, MasterPasswordHash};
use serde_json::json;
use typed_builder::TypedBuilder;

/// A client used for interacting with the Bitwarden API.
///
/// # Example
///
/// Creating a [`Client`]:
///
/// ```ignore
/// use rwarden::{cache::EmptyCache, AccessTokenData, Client, Urls};
/// use std::time::SystemTime;
///
/// let client = Client::builder()
///     .cache(EmptyCache)
///     .urls(Urls::official())
///     .keys(keys)
///     .refresh_token("foo")
///     .access_token_data(AccessTokenData { // optional
///         access_token: "bar".to_owned(),
///         expiry_time: SystemTime::now(),
///     })
///     .build();
/// ```
#[derive(Debug, Clone, TypedBuilder)]
pub struct Client<TCache> {
    #[builder(default, setter(skip))]
    pub(crate) client: reqwest::Client,
    pub(crate) cache: TCache,
    pub(crate) urls: Urls,
    pub(crate) keys: Keys,
    #[builder(setter(into))]
    pub(crate) refresh_token: String,
    #[builder(default, setter(strip_option))]
    pub(crate) access_token_data: Option<AccessTokenData>,
}

impl<TCache> Client<TCache> {
    /// Returns a shared reference to the cache.
    pub fn cache(&self) -> &TCache {
        &self.cache
    }

    /// Returns a mutable reference to the cache.
    pub fn cache_mut(&mut self) -> &mut TCache {
        &mut self.cache
    }

    /// Returns the URLs of the API endpoints.
    pub fn urls(&self) -> &Urls {
        &self.urls
    }

    /// Returns the keys.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub(crate) async fn request<S>(
        &mut self,
        method: Method,
        url: S,
    ) -> Result<RequestBuilder, RequestResponseError>
    where
        S: IntoUrl,
    {
        let refresh_access_token = match &self.access_token_data {
            Some(v) if v.token_has_expired() => true,
            None => true,
            Some(_) => false,
        };
        if refresh_access_token {
            self.refresh_access_token().await?;
        }
        // `unwrap` is safe here because the `refresh_access_token` function sets the access token
        let access_token = &self.access_token_data.as_ref().unwrap().access_token;
        Ok(self
            .client
            .request(method, url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token)))
    }

    /// Refreshes the access token.
    async fn refresh_access_token(&mut self) -> Result<(), RequestResponseError> {
        let token = self
            .client
            .request(Method::POST, self.urls.auth.clone())
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &self.refresh_token),
            ])
            .send()
            .await?
            .parse::<TokenResponse>()
            .await?;
        self.refresh_token = token.refresh_token;
        self.access_token_data = Some(AccessTokenData {
            access_token: token.access_token,
            expiry_time: util::get_token_expiry_time(token.expires_in),
        });
        Ok(())
    }

    /// Sends a token to the given email address that can be used to change the email address.
    ///
    /// To change the email address with the token, [`account::ModifyEmail`] can be used.
    pub async fn send_email_modification_token<S: AsRef<str>>(
        &mut self,
        new_email: S,
        master_password_hash: &MasterPasswordHash,
    ) -> Result<(), RequestResponseError> {
        self.request(
            Method::POST,
            format!("{}/accounts/email-token", self.urls().base),
        )
        .await?
        .json(&json!({
            "NewEmail": new_email.as_ref(),
            "MasterPasswordHash": master_password_hash
        }))
        .send()
        .await?
        .parse_empty()
        .await?;
        Ok(())
    }

    /// Sends a token to this users email address that can be used to verify the email address.
    ///
    /// To verify the email address with the token, the [`Client::verify_email`] function can be
    /// used.
    pub async fn send_email_verification_token(&mut self) -> Result<(), RequestResponseError> {
        self.request(
            Method::POST,
            format!("{}/accounts/verify-email", self.urls().base),
        )
        .await?
        .send()
        .await?
        .parse_empty()
        .await?;
        Ok(())
    }

    pub async fn verify_email<S>(&mut self, token: S) -> crate::Result<(), TCache::Error>
    where
        TCache: Cache + Send,
        S: AsRef<str>,
    {
        let account = self.send(&account::Get).await?;
        self.client
            .request(
                Method::POST,
                format!("{}/accounts/verify-email-token", self.urls().base),
            )
            .json(&json!({ "UserId": account.id, "Token": token.as_ref() }))
            .send()
            .await?
            .parse_empty()
            .await?;
        Ok(())
    }

    pub async fn verify_password(
        &mut self,
        master_password_hash: &MasterPasswordHash,
    ) -> Result<(), RequestResponseError> {
        self.request(
            Method::POST,
            format!("{}/accounts/verify-password", self.urls().base),
        )
        .await?
        .json(&json!({ "MasterPasswordHash": master_password_hash }))
        .send()
        .await?
        .parse_empty()
        .await?;
        Ok(())
    }

    pub fn send<'request, 'client, R>(&'client mut self, request: &'request R) -> R::Output
    where
        R: Request<'request, 'client, TCache>,
    {
        request.send(self)
    }
}
