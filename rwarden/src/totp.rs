//! Module for generating TOTPs.

use std::{collections::HashMap, time::SystemTime};
use thiserror::Error;
use totp_lite::{totp_custom, Sha1, Sha256, Sha512};
use url::{Host, Url};

pub const DEFAULT_ALGORITHM: Algorithm = Algorithm::Sha1;
pub const DEFAULT_DIGITS: u32 = 6;
pub const DEFAULT_TIME_STEP: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Configuration for generating TOTPs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TotpConfig {
    /// The decoded TOTP secret.
    pub secret: Vec<u8>,
    /// The algorithm used for generating the TOTP.
    pub algorithm: Algorithm,
    /// The number of digits the TOTP will have.
    pub digits: u32,
    /// The time step in seconds.
    pub time_step: u64,
}

impl TotpConfig {
    /// Creates a new [`TotpConfig`] from an encoded secret.
    ///
    /// # Examples
    ///
    /// ```
    /// use rwarden::totp::{self, TotpConfig};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let totp = TotpConfig::from_encoded_secret("FOOBAR")?;
    /// assert_eq!(totp.algorithm, totp::DEFAULT_ALGORITHM);
    /// assert_eq!(totp.digits, totp::DEFAULT_DIGITS);
    /// assert_eq!(totp.time_step, totp::DEFAULT_TIME_STEP);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_encoded_secret<S>(secret: S) -> Result<Self, FromEncodedSecretError>
    where
        S: AsRef<str>,
    {
        Ok(Self {
            secret: decode(secret).ok_or(FromEncodedSecretError::DecodeSecret)?,
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            time_step: DEFAULT_TIME_STEP,
        })
    }

    /// Creates a new [`TotpConfig`] from an otpauth URL.
    ///
    /// # Examples
    ///
    /// ```
    /// use rwarden::totp::{self, TotpConfig};
    /// use url::Url;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let url = "otpauth://totp/Example:alice@example.com?secret=FOOBAR";
    /// let url = Url::parse(url)?;
    /// let totp = TotpConfig::from_otpauth_url(&url)?;
    /// assert_eq!(totp.secret, TotpConfig::from_encoded_secret("FOOBAR")?.secret);
    /// assert_eq!(totp.algorithm, totp::DEFAULT_ALGORITHM);
    /// assert_eq!(totp.digits, totp::DEFAULT_DIGITS);
    /// assert_eq!(totp.time_step, totp::DEFAULT_TIME_STEP);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Specifying the algorithm, digits, and period in the URL:
    ///
    /// ```
    /// use rwarden::totp::{TotpConfig, Algorithm};
    /// use std::time::Duration;
    /// use url::Url;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let url = "otpauth://totp/Example:alice@example.com?secret=FOOBAR&algorithm=sha256&digits=8&period=20";
    /// let url = Url::parse(url)?;
    /// let totp = TotpConfig::from_otpauth_url(&url)?;
    /// assert_eq!(totp.secret, TotpConfig::from_encoded_secret("FOOBAR")?.secret);
    /// assert_eq!(totp.algorithm, Algorithm::Sha256);
    /// assert_eq!(totp.digits, 8);
    /// assert_eq!(totp.time_step, 20);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_otpauth_url(url: &Url) -> Result<Self, FromOtpauthUrlError> {
        let scheme = url.scheme();
        if scheme != "otpauth" {
            return Err(FromOtpauthUrlError::InvalidScheme {
                scheme: scheme.to_owned(),
            });
        }
        let host = url.host();
        if host != Some(Host::Domain("totp")) {
            return Err(FromOtpauthUrlError::InvalidHost {
                host: host.map(|v| v.to_owned()),
            });
        }
        let mut queries = url.query_pairs().collect::<HashMap<_, _>>();
        let secret = queries
            .remove("secret")
            .map(|v| v.into_owned())
            .ok_or(FromOtpauthUrlError::SecretNotFound)?;
        let secret = decode(secret).ok_or(FromOtpauthUrlError::DecodeSecret)?;
        let digits = match queries.remove("digits") {
            Some(v) => {
                let value = v
                    .parse::<u32>()
                    .map_err(|_| FromOtpauthUrlError::InvalidDigits {
                        digits: v.into_owned(),
                    })?;
                if value == 0 || value > 10 {
                    return Err(FromOtpauthUrlError::InvalidDigits {
                        digits: value.to_string(),
                    });
                }
                value
            }
            None => DEFAULT_DIGITS,
        };
        let time_step = match queries.remove("period") {
            Some(v) => {
                let value = v
                    .parse::<u64>()
                    .map_err(|_| FromOtpauthUrlError::InvalidPeriod {
                        period: v.into_owned(),
                    })?;
                if value == 0 {
                    return Err(FromOtpauthUrlError::InvalidPeriod {
                        period: value.to_string(),
                    });
                }
                value
            }
            None => DEFAULT_TIME_STEP,
        };
        let algorithm = match queries.get("algorithm").map(|v| v.as_ref()) {
            Some("sha1") => Algorithm::Sha1,
            Some("sha256") => Algorithm::Sha256,
            Some("sha512") => Algorithm::Sha512,
            Some(v) => {
                return Err(FromOtpauthUrlError::InvalidAlgorithm {
                    algorithm: v.to_owned(),
                })
            }
            None => DEFAULT_ALGORITHM,
        };
        Ok(Self {
            secret,
            digits,
            time_step,
            algorithm,
        })
    }

    /// Creates a new [`TotpConfig`] from either an encoded secret or an otpauth URL.
    pub fn parse<S>(value: S) -> Result<Self, ParseError>
    where
        S: AsRef<str>,
    {
        let value = value.as_ref();
        Ok(match Url::parse(value) {
            Ok(url) => Self::from_otpauth_url(&url)?,
            Err(_) => Self::from_encoded_secret(value)?,
        })
    }

    /// Generates the TOTP.
    pub fn generate(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        match &self.algorithm {
            Algorithm::Sha1 => {
                totp_custom::<Sha1>(self.time_step, self.digits, &self.secret, timestamp)
            }
            Algorithm::Sha256 => {
                totp_custom::<Sha256>(self.time_step, self.digits, &self.secret, timestamp)
            }
            Algorithm::Sha512 => {
                totp_custom::<Sha512>(self.time_step, self.digits, &self.secret, timestamp)
            }
        }
    }
}

fn decode<S: AsRef<str>>(secret: S) -> Option<Vec<u8>> {
    base32::decode(
        base32::Alphabet::RFC4648 { padding: false },
        secret.as_ref(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum FromEncodedSecretError {
    #[error("failed to decode secret")]
    DecodeSecret,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum FromOtpauthUrlError {
    #[error("the URL scheme is {:?} but it must be \"otpauth\"", .scheme)]
    InvalidScheme { scheme: String },
    #[error("the URL host is {:?} but it must be \"totp\"", .host.as_ref().map(ToString::to_string))]
    InvalidHost { host: Option<Host> },
    #[error("secret was not found in URL")]
    SecretNotFound,
    #[error("failed to decode secret")]
    DecodeSecret,
    #[error("invalid digits value {:?}", .digits)]
    InvalidDigits { digits: String },
    #[error("invalid period value {:?}", .period)]
    InvalidPeriod { period: String },
    #[error("invalid algorithm {:?}", .algorithm)]
    InvalidAlgorithm { algorithm: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum ParseError {
    #[error(transparent)]
    EncodedSecret(#[from] FromEncodedSecretError),
    #[error(transparent)]
    OtpauthUrl(#[from] FromOtpauthUrlError),
}
