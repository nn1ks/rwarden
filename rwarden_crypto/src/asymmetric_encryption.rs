use crate::{Decrypt, Parse};
use ::rsa::RsaPrivateKey;
use std::{fmt, num::ParseIntError};
use thiserror::Error;

pub use self::rsa::{Rsa2048OaepParseError, Rsa2048OaepSha1, Rsa2048OaepSha256};

mod rsa;

/// Parse error for [`AsymmetricEncryption`].
#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("failed to parse encryption type")]
    ParseEncryptionType(#[from] ParseIntError),
    #[error("invalid encryption type (expected one of `{:?}`, found `{}`)", .expected, .found)]
    InvalidEncryptionType { expected: [usize; 2], found: usize },
    #[error("Rsa2048OaepSha1 parse error")]
    Rsa2048OaepSha1(Rsa2048OaepParseError),
    #[error("Rsa2048OaepSha256 parse error")]
    Rsa2048OaepSha256(Rsa2048OaepParseError),
}

/// Decryption error for [`AsymmetricEncryption`].
#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Rsa2048OaepSha1 decryption error")]
    Rsa2048OaepSha1(::rsa::errors::Error),
    #[error("Rsa2048OaepSha256 decryption error")]
    Rsa2048OaepSha256(::rsa::errors::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AsymmetricEncryption {
    Rsa2048OaepSha1(Rsa2048OaepSha1),
    Rsa2048OaepSha256(Rsa2048OaepSha256),
}

impl From<Rsa2048OaepSha1> for AsymmetricEncryption {
    fn from(v: Rsa2048OaepSha1) -> Self {
        Self::Rsa2048OaepSha1(v)
    }
}

impl From<Rsa2048OaepSha256> for AsymmetricEncryption {
    fn from(v: Rsa2048OaepSha256) -> Self {
        Self::Rsa2048OaepSha256(v)
    }
}

impl Parse for AsymmetricEncryption {
    type Error = ParseError;
    fn parse<S: AsRef<str>>(value: S) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        let mut chars = value.chars();
        let ty_end = chars
            .position(|v| v == '.')
            .unwrap_or_else(|| value.chars().count());
        match value[0..ty_end].parse::<usize>()? {
            3 => Ok(Self::Rsa2048OaepSha256(
                Rsa2048OaepSha256::parse(value).map_err(ParseError::Rsa2048OaepSha256)?,
            )),
            4 => Ok(Self::Rsa2048OaepSha1(
                Rsa2048OaepSha1::parse(value).map_err(ParseError::Rsa2048OaepSha1)?,
            )),
            ty => Err(ParseError::InvalidEncryptionType {
                expected: [3, 4],
                found: ty,
            }),
        }
    }
}

impl Decrypt for AsymmetricEncryption {
    type Params = RsaPrivateKey;
    type Error = DecryptionError;
    fn decrypt(&self, params: &Self::Params) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Rsa2048OaepSha1(v) => v.decrypt(params).map_err(DecryptionError::Rsa2048OaepSha1),
            Self::Rsa2048OaepSha256(v) => v
                .decrypt(params)
                .map_err(DecryptionError::Rsa2048OaepSha256),
        }
    }
}

impl fmt::Display for AsymmetricEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa2048OaepSha1(v) => v.fmt(f),
            Self::Rsa2048OaepSha256(v) => v.fmt(f),
        }
    }
}
