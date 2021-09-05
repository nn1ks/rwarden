use crate::crypto::{
    self, KdfType, MasterPasswordHash, SourceKey, SymmetricEncryptedBytes, SymmetricKey,
};
use crate::{
    account, cache::Cache, util::ResponseExt, AccessTokenData, LoginData, LoginError, RegisterData,
    Request, RequestResponseError, Urls,
};
use reqwest::{header, IntoUrl, Method, RequestBuilder};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use typed_builder::TypedBuilder;
use uuid::Uuid;

#[derive(Deserialize)]
struct Prelogin {
    #[serde(rename = "Kdf")]
    kdf_type: KdfType,
    #[serde(rename = "KdfIterations")]
    kdf_iterations: u32,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
    refresh_token: String,
    scope: String,
    #[serde(rename = "Key")]
    key: SymmetricEncryptedBytes,
    #[serde(rename = "PrivateKey")]
    private_key: Option<SymmetricEncryptedBytes>,
    #[serde(rename = "Kdf")]
    kdf_type: KdfType,
    #[serde(rename = "KdfIterations")]
    kdf_iterations: u32,
    #[serde(rename = "ResetMasterPassword")]
    reset_master_password: bool,
}

/// Result of successful login.
#[derive(Debug, Clone)]
pub struct LoginResponse<TCache> {
    pub client: Client<TCache>,
    pub access_token_data: AccessTokenData,
    pub refresh_token: String,
    pub key: SymmetricEncryptedBytes,
    pub private_key: Option<SymmetricEncryptedBytes>,
    pub kdf_type: KdfType,
    pub kdf_iterations: u32,
}

/// A client used for logging in and registering users.
#[derive(Debug, Clone)]
pub struct AnonymousClient {
    urls: Urls,
    client: reqwest::Client,
}

impl AnonymousClient {
    pub fn new(urls: Urls) -> Self {
        Self {
            urls,
            client: reqwest::Client::new(),
        }
    }

    pub fn urls(&self) -> &Urls {
        &self.urls
    }

    async fn prelogin(&self, email: &str) -> Result<Prelogin, LoginError> {
        self.client
            .request(
                Method::POST,
                format!("{}/accounts/prelogin", self.urls.base),
            )
            .json(&json!({ "email": email }))
            .send()
            .await?
            .parse_with_login_result()
            .await
    }

    pub async fn login<TCache: Cache>(
        self,
        data: &LoginData,
        cache: TCache,
    ) -> Result<LoginResponse<TCache>, LoginError> {
        let Prelogin {
            kdf_type,
            kdf_iterations,
        } = self.prelogin(&data.email).await?;
        let source_key = SourceKey::new(&data.email, &data.password, kdf_type, kdf_iterations);
        let master_password_hash = MasterPasswordHash::new(&source_key, &data.password, kdf_type);

        let mut req = HashMap::new();
        req.insert("grant_type", "password");
        req.insert("username", &data.email);
        let master_password_hash = master_password_hash.to_string();
        req.insert("password", &master_password_hash);
        req.insert("client_id", &data.client_id);
        req.insert("scope", "api offline_access");
        let device_identifier = Uuid::new_v4().to_hyphenated().to_string();
        req.insert("DeviceIdentifier", &device_identifier);
        if let Some(v) = &data.device_name {
            req.insert("DeviceName", v);
        }
        let device_type = data.device_type.map(|v| (v as u8).to_string());
        if let Some(v) = &device_type {
            req.insert("DeviceType", v);
        }
        if let Some(v) = &data.device_push_token {
            req.insert("DevicePushToken", v);
        }
        let two_factor_provider = data.two_factor_provider.map(|v| (v as u8).to_string());
        if let Some(v) = &two_factor_provider {
            req.insert("TwoFactorProvider", v);
        }
        if let Some(v) = &data.two_factor_token {
            req.insert("TwoFactorToken", v);
        }
        if data.two_factor_remember {
            req.insert("TwoFactorRemember", "1");
        }

        let token = self
            .client
            .request(Method::POST, self.urls.auth.clone())
            .form(&req)
            .send()
            .await?
            .parse_with_login_result::<TokenResponse>()
            .await?;
        let symmetric_key = SymmetricKey::new(&source_key, &token.key)?;
        let access_token_data = AccessTokenData {
            access_token: token.access_token,
            expiry_time: SystemTime::now() + Duration::from_secs(token.expires_in),
        };
        let client = Client {
            client: self.client,
            cache,
            urls: self.urls,
            symmetric_key,
            refresh_token: token.refresh_token.clone(),
            access_token_data: Some(access_token_data.clone()),
        };
        Ok(LoginResponse {
            client,
            access_token_data,
            refresh_token: token.refresh_token,
            key: token.key,
            private_key: token.private_key,
            kdf_type: token.kdf_type,
            kdf_iterations: token.kdf_iterations,
        })
    }

    pub async fn register(&self, data: &RegisterData) -> Result<(), RequestResponseError> {
        let kdf_iterations = data.kdf_iterations.unwrap_or(100_000);
        let kdf_type = data.kdf_type.unwrap_or(KdfType::Pbkdf2Sha256);
        let source_key = SourceKey::new(&data.email, &data.password, kdf_type, kdf_iterations);
        let master_password_hash = MasterPasswordHash::new(&source_key, &data.password, kdf_type);
        let protected_symmetric_key = crypto::generate_protected_symmetric_key(&source_key);

        let req = json!({
            "Email": data.email,
            "MasterPasswordHash": master_password_hash,
            "MasterPasswordHint": data.password_hint,
            "Key": protected_symmetric_key.to_string(),
            "Name": data.name,
            "OrganizationUserId": data.organization_user_id,
            "Kdf": data.kdf_type,
            "KdfIterations": data.kdf_iterations,
        });

        self.client
            .request(
                Method::POST,
                format!("{}/accounts/register", self.urls.base),
            )
            .json(&req)
            .send()
            .await?
            .parse_empty()
            .await?;
        Ok(())
    }
}

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
///     .symmetric_key(symmetric_key)
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
    pub(crate) symmetric_key: SymmetricKey,
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

    /// Returns the symmetric key.
    pub fn symmetric_key(&self) -> &SymmetricKey {
        &self.symmetric_key
    }

    /// Returns the refresh token.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// Returns the access token and its expiry time.
    pub fn access_token_data(&self) -> Option<&AccessTokenData> {
        self.access_token_data.as_ref()
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
            expiry_time: SystemTime::now() + Duration::from_secs(token.expires_in),
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
