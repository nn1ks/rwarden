use crate::{Decrypt, Encrypt, Parse, SymmetricKey};
use block_modes::BlockModeError;
use std::{fmt, num::ParseIntError};
use thiserror::Error;

pub use self::aes::{
    AesCbc128HmacSha256, AesCbc256, AesCbc256HmacSha256, AesCbc256ParseError,
    AesCbcHmacSha256DecryptionError, AesCbcHmacSha256ParseError,
};

mod aes;

/// Parse error for [`SymmetricEncryption`].
#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("failed to parse encryption type")]
    ParseEncryptionType(#[from] ParseIntError),
    #[error("invalid encryption type (expected one of `{:?}`, found `{}`)", .expected, .found)]
    InvalidEncryptionType { expected: [usize; 3], found: usize },
    #[error("AesCbc256 parse error")]
    AesCbc256(AesCbc256ParseError),
    #[error("AesCbc128HmacSha256 parse error")]
    AesCbc128HmacSha256(AesCbcHmacSha256ParseError),
    #[error("AesCbc256HmacSha256 parse error")]
    AesCbc256HmacSha256(AesCbcHmacSha256ParseError),
}

/// Decryption error for [`SymmetricEncryption`].
#[derive(Debug, Clone, Error)]
pub enum DecryptionError {
    #[error("AesCbc256 decryption error")]
    AesCbc256(BlockModeError),
    #[error("AesCbc256HmacSha256 decryption error")]
    AesCbc256HmacSha256(AesCbcHmacSha256DecryptionError),
    #[error("the encryption type AesCbc128HmacSha256 is not supported for symmetric encryption")]
    UnsupportedEncryptionType,
    #[error("the mac key is required but missing in the symmetric key")]
    MacKeyMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymmetricEncryption {
    AesCbc256(AesCbc256),
    AesCbc128HmacSha256(AesCbc128HmacSha256),
    AesCbc256HmacSha256(AesCbc256HmacSha256),
}

impl From<AesCbc256> for SymmetricEncryption {
    fn from(v: AesCbc256) -> Self {
        Self::AesCbc256(v)
    }
}

impl From<AesCbc128HmacSha256> for SymmetricEncryption {
    fn from(v: AesCbc128HmacSha256) -> Self {
        Self::AesCbc128HmacSha256(v)
    }
}

impl From<AesCbc256HmacSha256> for SymmetricEncryption {
    fn from(v: AesCbc256HmacSha256) -> Self {
        Self::AesCbc256HmacSha256(v)
    }
}

impl Parse for SymmetricEncryption {
    type Error = ParseError;
    fn parse<S: AsRef<str>>(value: S) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        let mut chars = value.chars();
        let ty_end = chars
            .position(|v| v == '.')
            .unwrap_or_else(|| value.chars().count());
        match value[0..ty_end].parse::<usize>()? {
            0 => Ok(Self::AesCbc256(
                AesCbc256::parse(value).map_err(ParseError::AesCbc256)?,
            )),
            1 => Ok(Self::AesCbc128HmacSha256(
                AesCbc128HmacSha256::parse(value).map_err(ParseError::AesCbc128HmacSha256)?,
            )),
            2 => Ok(Self::AesCbc256HmacSha256(
                AesCbc256HmacSha256::parse(value).map_err(ParseError::AesCbc256HmacSha256)?,
            )),
            ty => Err(ParseError::InvalidEncryptionType {
                expected: [0, 1, 2],
                found: ty,
            }),
        }
    }
}

impl Encrypt for SymmetricEncryption {
    type Params = SymmetricKey;
    fn encrypt<P: AsRef<[u8]>>(plaintext: P, params: &Self::Params) -> Self {
        match params.mac {
            Some(mac) => Self::AesCbc256HmacSha256(AesCbc256HmacSha256::encrypt(
                plaintext,
                &(params.enc, mac),
            )),
            None => Self::AesCbc256(AesCbc256::encrypt(plaintext, &params.enc)),
        }
    }
}

impl Decrypt for SymmetricEncryption {
    type Params = SymmetricKey;
    type Error = DecryptionError;
    fn decrypt(&self, params: &Self::Params) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::AesCbc256(v) => v.decrypt(&params.enc).map_err(DecryptionError::AesCbc256),
            Self::AesCbc128HmacSha256(_) => Err(DecryptionError::UnsupportedEncryptionType),
            Self::AesCbc256HmacSha256(v) => match &params.mac {
                Some(mac) => v
                    .decrypt(&(params.enc, *mac))
                    .map_err(DecryptionError::AesCbc256HmacSha256),
                None => Err(DecryptionError::MacKeyMissing),
            },
        }
    }
}

impl fmt::Display for SymmetricEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AesCbc256(v) => v.fmt(f),
            Self::AesCbc128HmacSha256(v) => v.fmt(f),
            Self::AesCbc256HmacSha256(v) => v.fmt(f),
        }
    }
}
