#![warn(rust_2018_idioms, missing_debug_implementations)]

use derive_setters::Setters;
use serde::{Deserialize, Serialize};
use serde_repr::Serialize_repr as SerializeRepr;
use std::{result::Result as StdResult, time::SystemTime};
use url::Url;
use uuid::Uuid;

pub use client::{AnonymousClient, Client, ClientBuilder, LoginResponse};
pub use error::{Error, LoginError, RequestResponseError};
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
pub mod organization;
pub mod response;
pub mod settings;
pub mod sync;

/// Type alias for `Result<TOk, Error<TCacheError>>`.
pub type Result<TOk, TCacheError> = StdResult<TOk, Error<TCacheError>>;

pub trait Request<'request, 'client, TCache> {
    type Output;
    fn send(&'request self, client: &'client mut Client<TCache>) -> Self::Output;
}

/// Struct for specifying the URLs of API endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
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
    /// | [`base`] | *\<url\>*/api                    |
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
    /// assert_eq!(urls.base, Url::parse("https://example.com/api").unwrap());
    /// assert_eq!(urls.auth, Url::parse("https://example.com/identity/connect/token").unwrap());
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom<S: AsRef<str>>(url: S) -> StdResult<Self, url::ParseError> {
        let url = Url::parse(url.as_ref())?;
        Ok(Self {
            base: url.join("api")?,
            auth: url.join("identity/connect/token")?,
        })
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
