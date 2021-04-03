#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

use async_trait::async_trait;
use derive_setters::Setters;
use displaydoc::Display;
use reqwest::{header, Method, RequestBuilder};
use rwarden_crypto::{CipherString, Keys};
use serde::Deserialize;
use serde_json::json;
use serde_repr::Serialize_repr as SerializeRepr;
use std::time::{Duration, SystemTime};
use std::{collections::HashMap, convert::TryInto, result::Result as StdResult};
use thiserror::Error as ThisError;
use url::Url;
use util::ResponseExt;
use uuid::Uuid;

pub use rwarden_crypto as crypto;

#[macro_use]
mod util;

pub mod cipher;
pub mod response;

/// Type alias for `Result<T, Error>`.
pub type Result<T> = StdResult<T, Error>;

/// Errors that can occur while interacting the Bitwarden API.
#[derive(Debug, Display, ThisError)]
pub enum Error {
    /// Failed to send request.
    Request(#[from] reqwest::Error),
    /// Failed to parse URL.
    ParseUrl(#[from] url::ParseError),
    /// Failed to decrypt cipher string.
    CipherDecryption(#[from] crypto::CipherDecryptionError),
    /// Error returned from the server.
    Response(#[from] response::Error),
}

/// Struct for specifying the URLs of API endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Urls {
    pub base: Url,
    pub auth: Url,
    // pub icon_url: Url, // not needed yet
    // pub notifications_url: Url, // what is this URL for?
    // pub events_url: Url, // what is this URL for?
    // pub web_vault_url: Url, // is probably never needed
}

impl Urls {
    /// Creates a new [`Urls`] type with the URLs of the official server.
    ///
    /// | Field    | URL                                          |
    /// |----------|----------------------------------------------|
    /// | [`base`] | https://api.bitwarden.com                    |
    /// | [`auth`] | https://identity.bitwarden.com/connect/token |
    ///
    /// [`base`]: Self::base
    /// [`auth`]: Self::auth
    pub fn official() -> Self {
        Self {
            base: Url::parse("https://api.bitwarden.com").unwrap(),
            auth: Url::parse("https://identity.bitwarden.com/connect/token").unwrap(),
        }
    }

    /// Creates a new [`Urls`] type with the URLs of an unofficial server.
    ///
    /// | Field    | URL                              |
    /// |----------|----------------------------------|
    /// | [`base`] | *\<url\>*/api                    |
    /// | [`auth`] | *\<url\>*/identity/connect/token |
    ///
    /// [`base`]: Self::base
    /// [`auth`]: Self::auth
    pub fn unofficial(url: Url) -> StdResult<Self, url::ParseError> {
        Ok(Self {
            base: url.join("api")?,
            auth: url.join("identity/connect/token")?,
        })
    }
}

#[derive(Deserialize)]
struct Prelogin {
    #[serde(rename = "Kdf")]
    kdf_type: crypto::KdfType,
    #[serde(rename = "KdfIterations")]
    kdf_iterations: u32,
}

/// A client used for logging in and registering users.
#[derive(Debug, Clone)]
pub struct Client {
    urls: Urls,
    client: reqwest::Client,
}

impl Client {
    pub fn new(urls: Urls) -> Self {
        Self {
            urls,
            client: reqwest::Client::new(),
        }
    }

    pub fn urls(&self) -> &Urls {
        &self.urls
    }

    pub(crate) fn request<F, I>(
        &self,
        method: Method,
        url: F,
        path_segments: I,
    ) -> StdResult<RequestBuilder, url::ParseError>
    where
        F: Fn(&Urls) -> &Url,
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut url = url(&self.urls).clone();
        url.path_segments_mut()
            .map_err(|_| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
            .extend(path_segments);
        Ok(self.client.request(method, url))
    }

    pub(crate) fn request_auth(&self) -> StdResult<RequestBuilder, url::ParseError> {
        self.request(Method::POST, |urls| &urls.auth, std::iter::empty::<&str>())
    }

    async fn prelogin(&self, username: &str) -> Result<Prelogin> {
        Ok(self
            .request(Method::POST, |urls| &urls.base, &["accounts", "prelogin"])?
            .json(&json!({ "email": username }))
            .send()
            .await?
            .parse()
            .await?)
    }

    pub async fn login(&self, data: &LoginData) -> Result<Session> {
        let Prelogin {
            kdf_type,
            kdf_iterations,
        } = self.prelogin(&data.username).await?;
        let source_key =
            crypto::SourceKey::new(&data.username, &data.password, kdf_type, kdf_iterations);
        let master_password_hash =
            crypto::MasterPasswordHash::new(&source_key, &data.password, kdf_type);

        let mut req = HashMap::new();
        req.insert("grant_type", "password");
        req.insert("username", &data.username);
        let master_password_hash = master_password_hash.encode();
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
        let two_factor_provider = data.device_type.map(|v| (v as u8).to_string());
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
            .request_auth()?
            .form(&req)
            .send()
            .await?
            .parse::<TokenResponse>()
            .await?;
        let keys = crypto::Keys::new(&source_key, &token.key)?;
        Ok(Session {
            client: self.clone(),
            keys,
            token_expiry_time: get_token_expiry_time(token.expires_in),
            tokens: Tokens {
                refresh_token: token.refresh_token,
                access_token: token.access_token,
            },
        })
    }

    pub async fn register(&self, data: &RegisterData) -> Result<()> {
        let kdf_iterations = data.kdf_iterations.unwrap_or(100_000);
        let kdf_type = data.kdf_type.unwrap_or(crypto::KdfType::Pbkdf2Sha256);
        let source_key =
            crypto::SourceKey::new(&data.username, &data.password, kdf_type, kdf_iterations);
        let master_password_hash =
            crypto::MasterPasswordHash::new(&source_key, &data.password, kdf_type);
        let protected_symmetric_key = crypto::generate_protected_symmetric_key(&source_key);

        let req = json!({
            "Email": data.username,
            "MasterPasswordHash": master_password_hash.encode(),
            "MasterPasswordHint": data.password_hint,
            "Key": protected_symmetric_key.to_string(),
            "Name": data.name,
            "OrganizationUserId": data.organization_user_id,
            "Kdf": data.kdf_type,
            "KdfIterations": data.kdf_iterations,
        });

        self.request(Method::POST, |urls| &urls.base, &["accounts", "register"])?
            .json(&req)
            .send()
            .await?
            .parse()
            .await
    }
}

fn get_token_expiry_time(expires_in: Option<i64>) -> SystemTime {
    SystemTime::now()
        + expires_in
            .map(|v| v.try_into().map(Duration::from_secs).unwrap_or_default())
            .unwrap_or_default()
}

/// Tokens used for accessing the Bitwarden API.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tokens {
    pub refresh_token: String,
    pub access_token: String,
}

/// A session used for interacting with the Bitwarden API.
#[derive(Debug, Clone)]
pub struct Session {
    client: Client,
    keys: Keys,
    token_expiry_time: SystemTime,
    tokens: Tokens,
}

impl Session {
    /// Creates a new [`Session`].
    pub fn new(urls: Urls, keys: Keys, tokens: Tokens) -> Self {
        Self {
            client: Client::new(urls),
            keys,
            token_expiry_time: SystemTime::now(),
            tokens,
        }
    }

    /// Returns the URLs of the API endpoints.
    pub fn urls(&self) -> &Urls {
        &self.client.urls
    }

    /// Returns the keys.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Returns the tokens.
    pub fn tokens(&self) -> &Tokens {
        &self.tokens
    }

    /// Returns whether the token has expired.
    fn token_has_expired(&self) -> bool {
        self.token_expiry_time <= SystemTime::now()
    }

    pub(crate) async fn request<F, I>(
        &mut self,
        method: Method,
        urls: F,
        path_segments: I,
    ) -> Result<RequestBuilder>
    where
        F: Fn(&Urls) -> &Url,
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        if self.token_has_expired() {
            self.refresh_token().await?;
        }
        Ok(self.client.request(method, urls, path_segments)?.header(
            header::AUTHORIZATION,
            format!("Bearer {}", self.tokens.access_token),
        ))
    }

    /// Refreshes the token.
    async fn refresh_token(&mut self) -> Result<()> {
        let req = json!({
            "grant_type": "refresh_token",
            "refresh_token": self.tokens.refresh_token,
        });
        let token = self
            .client
            .request_auth()?
            .json(&req)
            .send()
            .await?
            .parse::<TokenResponse>()
            .await?;
        self.tokens.refresh_token = token.refresh_token;
        self.tokens.access_token = token.access_token;
        self.token_expiry_time = get_token_expiry_time(token.expires_in);
        Ok(())
    }

    pub async fn get<G>(&mut self, id: G::Id) -> Result<G>
    where
        G: Getable,
    {
        G::get(self, id).await
    }

    pub async fn get_all<G>(&mut self) -> Result<Vec<G>>
    where
        G: GetableAll,
    {
        G::get_all(self).await
    }

    pub async fn restore<R>(&mut self, id: R::Id) -> Result<R>
    where
        R: Restorable,
    {
        R::restore(self, id).await
    }

    pub async fn bulk_restore<R, I>(&mut self, ids: I) -> Result<Vec<R>>
    where
        R: BulkRestorable,
        I: IntoIterator<Item = R::Id>,
    {
        R::bulk_restore(self, ids).await
    }

    pub async fn delete<D>(&mut self, deleter: &D, id: D::Id) -> Result<()>
    where
        D: Deleter,
    {
        deleter.execute(self, id).await
    }

    pub async fn bulk_delete<D, I>(&mut self, bulk_deleter: &D, ids: I) -> Result<()>
    where
        D: BulkDeleter,
        I: IntoIterator<Item = D::Id>,
    {
        bulk_deleter.execute(self, ids).await
    }

    pub async fn create<C>(&mut self, creator: &C) -> Result<C::Response>
    where
        C: Creator,
    {
        creator.execute(self).await
    }

    pub async fn modify<M>(&mut self, modifier: &M, id: M::Id) -> Result<M::Response>
    where
        M: Modifier,
    {
        modifier.execute(self, id).await
    }

    pub async fn import<I>(&mut self, importer: &I) -> Result<()>
    where
        I: Importer,
    {
        importer.execute(self).await
    }

    pub async fn share<S>(&mut self, sharer: &S, id: S::Id) -> Result<S::Response>
    where
        S: Sharer,
    {
        sharer.execute(self, id).await
    }

    pub async fn bulk_share<S>(&mut self, bulk_sharer: &S) -> Result<S::Response>
    where
        S: BulkSharer,
    {
        bulk_sharer.execute(self).await
    }

    pub async fn bulk_move<M, I>(&mut self, bulk_mover: &M, ids: I) -> Result<()>
    where
        M: BulkMover,
        I: IntoIterator<Item = M::Id>,
    {
        bulk_mover.execute(self, ids).await
    }

    pub async fn purge<P>(&mut self, purger: &P) -> Result<()>
    where
        P: Purger,
    {
        purger.execute(self).await
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
    token_type: String,
    refresh_token: String,
    scope: String,
    #[serde(rename = "Key")]
    key: CipherString,
    #[serde(rename = "PrivateKey")]
    private_key: Option<CipherString>,
    #[serde(rename = "Kdf")]
    kdf_type: crypto::KdfType,
    #[serde(rename = "KdfIterations")]
    kdf_iterations: u32,
    #[serde(rename = "ResetMasterPassword")]
    reset_master_password: bool,
}

/// The type of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SerializeRepr)]
#[repr(u8)]
pub enum DeviceType {
    Android = 0,
    Ios = 1,
    ChromeExtension = 2,
    FirefoxExtension = 3,
    OperaExtension = 4,
    EdgeExtension = 5,
    WindowsDesktop = 6,
    MacOsDesktop = 7,
    LinuxDesktop = 8,
    ChromeBrowser = 9,
    FirefoxBrowser = 10,
    OperaBrowser = 11,
    EdgeBrowser = 12,
    IeBrowser = 13,
    UnknownBrowser = 14,
    AndroidAmazon = 15,
    Uwp = 16,
    SafariBrowser = 17,
    VivaldiBrowser = 18,
    VivaldiExtension = 19,
    SafariExtension = 20,
}

/// The provider for two factor authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SerializeRepr)]
#[repr(u8)]
pub enum TwoFactorProvider {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
}

/// Data used for performing logins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Setters)]
#[setters(strip_option, prefix = "with_")]
pub struct LoginData {
    /// The username. Usually this is the email address.
    #[setters(skip)]
    pub username: String,
    /// The master password.
    #[setters(skip)]
    pub password: String,
    #[setters(skip)]
    pub client_id: String,
    #[setters(into)]
    pub device_name: Option<String>,
    pub device_type: Option<DeviceType>,
    #[setters(into)]
    pub device_push_token: Option<String>,
    pub two_factor_provider: Option<TwoFactorProvider>,
    #[setters(into)]
    pub two_factor_token: Option<String>,
    #[setters(bool)]
    pub two_factor_remember: bool,
}

impl LoginData {
    /// Creates a new [`LoginData`].
    pub fn new<U, P, C>(username: U, password: P, client_id: C) -> Self
    where
        U: Into<String>,
        P: Into<String>,
        C: Into<String>,
    {
        Self {
            client_id: client_id.into(),
            username: username.into(),
            password: password.into(),
            device_name: None,
            device_type: None,
            device_push_token: None,
            two_factor_provider: None,
            two_factor_token: None,
            two_factor_remember: false,
        }
    }
}

/// Data used for registering a user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Setters)]
#[setters(strip_option, prefix = "with_")]
pub struct RegisterData {
    /// The username. Usually this is the email address.
    #[setters(skip)]
    pub username: String,
    /// The master password.
    #[setters(skip)]
    pub password: String,
    /// The hint for the master password.
    #[setters(into)]
    pub password_hint: Option<String>,
    #[setters(into)]
    pub name: Option<String>,
    pub organization_user_id: Option<Uuid>,
    pub kdf_type: Option<crypto::KdfType>,
    pub kdf_iterations: Option<u32>,
}

impl RegisterData {
    /// Creates a new [`RegisterData`].
    pub fn new<E, P>(username: E, password: P) -> Self
    where
        E: Into<String>,
        P: Into<String>,
    {
        Self {
            username: username.into(),
            password: password.into(),
            password_hint: None,
            name: None,
            organization_user_id: None,
            kdf_type: None,
            kdf_iterations: None,
        }
    }
}

/// Trait for getting a resource.
#[async_trait(?Send)]
pub trait Getable: Sized {
    type Id;
    async fn get(session: &mut Session, id: Self::Id) -> Result<Self>;
}

/// Trait for getting all resources of a type.
#[async_trait(?Send)]
pub trait GetableAll: Sized {
    async fn get_all(session: &mut Session) -> Result<Vec<Self>>;
}

/// Trait for restoring a resource.
#[async_trait(?Send)]
pub trait Restorable: Sized {
    type Id;
    async fn restore(session: &mut Session, id: Self::Id) -> Result<Self>;
}

/// Trait for restoring multiple resources of a type.
#[async_trait(?Send)]
pub trait BulkRestorable: Sized {
    type Id;
    async fn bulk_restore<I>(session: &mut Session, ids: I) -> Result<Vec<Self>>
    where
        I: IntoIterator<Item = Self::Id>;
}

/// Trait for deleting a resource.
#[async_trait(?Send)]
pub trait Deleter {
    type Id;
    async fn execute(&self, session: &mut Session, id: Self::Id) -> Result<()>;
}

/// Trait for bulk deleting resources.
#[async_trait(?Send)]
pub trait BulkDeleter {
    type Id;
    async fn execute<I>(&self, session: &mut Session, ids: I) -> Result<()>
    where
        I: IntoIterator<Item = Self::Id>;
}

/// Trait for creating a resource.
#[async_trait(?Send)]
pub trait Creator {
    type Response;
    async fn execute(&self, session: &mut Session) -> Result<Self::Response>;
}

/// Trait for modifying a resource.
#[async_trait(?Send)]
pub trait Modifier {
    type Id;
    type Response;
    async fn execute(&self, session: &mut Session, id: Self::Id) -> Result<Self::Response>;
}

/// Trait for importing resources.
#[async_trait]
pub trait Importer {
    async fn execute(&self, session: &mut Session) -> Result<()>;
}

/// Trait for sharing a resource.
#[async_trait(?Send)]
pub trait Sharer {
    type Id;
    type Response;
    async fn execute(&self, session: &mut Session, id: Self::Id) -> Result<Self::Response>;
}

/// Trait for bulk sharing resources.
#[async_trait(?Send)]
pub trait BulkSharer {
    type Response;
    async fn execute(&self, session: &mut Session) -> Result<Self::Response>;
}

/// Trait for bulk moving resources.
#[async_trait(?Send)]
pub trait BulkMover {
    type Id;
    async fn execute<I>(&self, session: &mut Session, ids: I) -> Result<()>
    where
        I: IntoIterator<Item = Self::Id>;
}

/// Trait for purging resources.
#[async_trait(?Send)]
pub trait Purger {
    async fn execute(&self, session: &mut Session) -> Result<()>;
}
