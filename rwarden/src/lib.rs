#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

use derive_setters::Setters;
use reqwest::Method;
use rwarden_crypto::CipherString;
use serde::Deserialize;
use serde_json::json;
use serde_repr::Serialize_repr as SerializeRepr;
use std::time::SystemTime;
use std::{collections::HashMap, result::Result as StdResult};
use url::Url;
use uuid::Uuid;

use cache::Cache;
use util::ResponseExt;

pub use client::Client;
pub use error::{Error, RequestResponseError};
pub use rwarden_crypto as crypto;

#[macro_use]
mod util;

mod client;
mod error;

pub mod account;
pub mod cache;
pub mod cipher;
pub mod collection;
pub mod folder;
pub mod response;
pub mod settings;
pub mod sync;

/// Type alias for `Result<TOk, Error<TCacheError>>`.
pub type Result<TOk, TCacheError> = StdResult<TOk, Error<TCacheError>>;

/// Struct for specifying the URLs of API endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Urls {
    pub base: Url,
    pub auth: Url,
    // pub icon: Url,
    // pub notifications: Url,
    // pub events: Url,
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

    /// Creates a new [`Urls`] type with the URLs of a custom server.
    ///
    /// | Field    | URL                              |
    /// |----------|----------------------------------|
    /// | [`base`] | *\<url\>*/api/                   |
    /// | [`auth`] | *\<url\>*/identity/connect/token |
    ///
    /// [`base`]: Self::base
    /// [`auth`]: Self::auth
    ///
    /// # Example
    ///
    /// ```
    /// # use rwarden::Urls;
    /// # use url::Url;
    /// # fn main() -> Result<(), url::ParseError> {
    /// let urls = Urls::custom("https://example.com")?;
    /// assert_eq!(urls.base, Url::parse("https://example.com/api/").unwrap());
    /// assert_eq!(urls.auth, Url::parse("https://example.com/identity/connect/token").unwrap());
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom<S: AsRef<str>>(url: S) -> StdResult<Self, url::ParseError> {
        let url = Url::parse(url.as_ref())?;
        Ok(Self {
            base: url.join("api/")?,
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

    async fn prelogin(&self, email: &str) -> StdResult<Prelogin, RequestResponseError> {
        self.client
            .request(
                Method::POST,
                format!("{}/accounts/prelogin", self.urls.base),
            )
            .json(&json!({ "email": email }))
            .send()
            .await?
            .parse()
            .await
    }

    pub async fn login<TCache: Cache>(
        self,
        data: &LoginData,
        cache: TCache,
    ) -> Result<Client<TCache>, TCache::Error> {
        let Prelogin {
            kdf_type,
            kdf_iterations,
        } = self.prelogin(&data.email).await?;
        let source_key =
            crypto::SourceKey::new(&data.email, &data.password, kdf_type, kdf_iterations);
        let master_password_hash =
            crypto::MasterPasswordHash::new(&source_key, &data.password, kdf_type);

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
            .client
            .request(Method::POST, self.urls.auth.clone())
            .form(&req)
            .send()
            .await?
            .parse::<TokenResponse>()
            .await?;
        let keys = crypto::Keys::new(&source_key, &token.key)?;
        Ok(Client {
            client: self.client,
            cache,
            urls: self.urls,
            keys,
            refresh_token: token.refresh_token,
            access_token_data: Some(AccessTokenData {
                access_token: token.access_token,
                expiry_time: util::get_token_expiry_time(token.expires_in),
            }),
        })
    }

    pub async fn register(&self, data: &RegisterData) -> Result<(), RequestResponseError> {
        let kdf_iterations = data.kdf_iterations.unwrap_or(100_000);
        let kdf_type = data.kdf_type.unwrap_or(crypto::KdfType::Pbkdf2Sha256);
        let source_key =
            crypto::SourceKey::new(&data.email, &data.password, kdf_type, kdf_iterations);
        let master_password_hash =
            crypto::MasterPasswordHash::new(&source_key, &data.password, kdf_type);
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

/// An access token and its expiry time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccessTokenData {
    pub access_token: String,
    pub expiry_time: SystemTime,
}

impl AccessTokenData {
    fn token_has_expired(&self) -> bool {
        self.expiry_time < SystemTime::now()
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
    WebAuthn = 7,
}

/// Data used for performing logins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Setters)]
#[setters(strip_option, prefix = "with_")]
pub struct LoginData {
    /// The email address.
    #[setters(skip)]
    pub email: String,
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
    pub two_factor_remember: bool,
}

impl LoginData {
    /// Creates a new [`LoginData`].
    pub fn new<E, P, C>(email: E, password: P, client_id: C) -> Self
    where
        E: Into<String>,
        P: Into<String>,
        C: Into<String>,
    {
        Self {
            client_id: client_id.into(),
            email: email.into(),
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
    /// The email address.
    #[setters(skip)]
    pub email: String,
    /// The master password.
    #[setters(skip)]
    pub password: String,
    /// The hint for the master password.
    #[setters(into)]
    pub password_hint: Option<String>,
    /// The name of the user.
    #[setters(into)]
    pub name: Option<String>,
    /// The ID of an organization that the user will be part of.
    pub organization_user_id: Option<Uuid>,
    /// The KDF type. Defaults to [`KdfType::Pbkdf2Sha256`].
    ///
    /// [`KdfType::Pbkdf2Sha256`]: crypto::KdfType::Pbkdf2Sha256
    pub kdf_type: Option<crypto::KdfType>,
    /// The number of KDF iterations. Defaults to `100_000`.
    pub kdf_iterations: Option<u32>,
}

impl RegisterData {
    /// Creates a new [`RegisterData`].
    pub fn new<E, P>(email: E, password: P) -> Self
    where
        E: Into<String>,
        P: Into<String>,
    {
        Self {
            email: email.into(),
            password: password.into(),
            password_hint: None,
            name: None,
            organization_user_id: None,
            kdf_type: None,
            kdf_iterations: None,
        }
    }
}

pub trait Request<'request, 'client, TCache> {
    type Output;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output;
}
