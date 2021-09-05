use crate::{Decrypt, Parse};
use rsa::RsaPrivateKey;
use sha1::Sha1;
use sha2::Sha256;
use std::{fmt, num::ParseIntError};
use thiserror::Error;

/// Parse error for [`Rsa2048OaepSha1`] and [`Rsa2048OaepSha256`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Rsa2048OaepParseError {
    #[error("failed to parse encryption type")]
    ParseEncryptionType(#[from] ParseIntError),
    #[error("invalid encryption type (expected `{}`, found `{}`)", .expected, .found)]
    InvalidEncryptionType { expected: usize, found: usize },
    #[error("ciphertext not found")]
    CiphertextNotFound,
    #[error("failed to decode")]
    Decode(#[from] base64::DecodeError),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rsa2048OaepSha1 {
    pub ciphertext: Vec<u8>,
}

impl Parse for Rsa2048OaepSha1 {
    type Error = Rsa2048OaepParseError;
    fn parse<S: AsRef<str>>(value: S) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        let mut chars = value.chars();
        let ty_end = chars
            .position(|v| v == '.')
            .unwrap_or_else(|| value.chars().count());
        let ty = value[0..ty_end].parse::<usize>()?;
        if ty != 4 {
            return Err(Rsa2048OaepParseError::InvalidEncryptionType {
                expected: 4,
                found: ty,
            });
        }
        let mut parts = chars.as_str().split('|');
        let ciphertext = parts
            .next()
            .ok_or(Rsa2048OaepParseError::CiphertextNotFound)?;
        let ciphertext = base64::decode(ciphertext)?;
        Ok(Self { ciphertext })
    }
}

impl Decrypt for Rsa2048OaepSha1 {
    type Params = RsaPrivateKey;
    type Error = rsa::errors::Error;
    fn decrypt(&self, params: &Self::Params) -> Result<Vec<u8>, Self::Error> {
        let private_key = params;
        let padding = rsa::PaddingScheme::new_oaep::<Sha1>();
        private_key.decrypt(padding, &self.ciphertext)
    }
}

impl fmt::Display for Rsa2048OaepSha1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ciphertext = base64::encode(&self.ciphertext);
        f.write_fmt(format_args!("4.{}", ciphertext))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rsa2048OaepSha256 {
    pub ciphertext: Vec<u8>,
}

impl Parse for Rsa2048OaepSha256 {
    type Error = Rsa2048OaepParseError;
    fn parse<S: AsRef<str>>(value: S) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        let mut chars = value.chars();
        let ty_end = chars
            .position(|v| v == '.')
            .unwrap_or_else(|| value.chars().count());
        let ty = value[0..ty_end].parse::<usize>()?;
        if ty != 3 {
            return Err(Rsa2048OaepParseError::InvalidEncryptionType {
                expected: 3,
                found: ty,
            });
        }
        let mut parts = chars.as_str().split('|');
        let ciphertext = parts
            .next()
            .ok_or(Rsa2048OaepParseError::CiphertextNotFound)?;
        let ciphertext = base64::decode(ciphertext)?;
        Ok(Self { ciphertext })
    }
}

impl Decrypt for Rsa2048OaepSha256 {
    type Params = RsaPrivateKey;
    type Error = rsa::errors::Error;
    fn decrypt(&self, params: &Self::Params) -> Result<Vec<u8>, Self::Error> {
        let private_key = params;
        let padding = rsa::PaddingScheme::new_oaep::<Sha256>();
        private_key.decrypt(padding, &self.ciphertext)
    }
}

impl fmt::Display for Rsa2048OaepSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ciphertext = base64::encode(&self.ciphertext);
        f.write_fmt(format_args!("3.{}", ciphertext))
    }
}
