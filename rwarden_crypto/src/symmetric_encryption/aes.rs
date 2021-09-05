use crate::{Decrypt, Encrypt, Parse};
use aes::{Aes128, Aes256};
use block_modes::{block_padding::Pkcs7, BlockMode, BlockModeError, Cbc};
use generic_array::GenericArray;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use std::{convert::TryInto, fmt, num::ParseIntError};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AesCbc256 {
    pub iv: [u8; 16],
    pub ciphertext: Vec<u8>,
}

/// Parse error for [`AesCbc256`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AesCbc256ParseError {
    #[error("failed to parse encryption type")]
    ParseEncryptionType(#[from] ParseIntError),
    #[error("invalid encryption type (expected `{}`, found `{}`)", .expected, .found)]
    InvalidEncryptionType { expected: usize, found: usize },
    #[error("initialization vector not found")]
    IvNotFound,
    #[error("invalid initialization vector length")]
    InvalidIvLength,
    #[error("ciphertext not found")]
    CiphertextNotFound,
    #[error("failed to decode")]
    Decode(#[from] base64::DecodeError),
}

impl Parse for AesCbc256 {
    type Error = AesCbc256ParseError;
    fn parse<S: AsRef<str>>(value: S) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        let mut chars = value.chars();
        let ty_end = chars
            .position(|v| v == '.')
            .unwrap_or_else(|| value.chars().count());
        let ty = value[0..ty_end].parse::<usize>()?;
        if ty != 0 {
            return Err(AesCbc256ParseError::InvalidEncryptionType {
                expected: 0,
                found: ty,
            });
        }
        let mut parts = chars.as_str().split('|');
        let iv = parts.next().ok_or(AesCbc256ParseError::IvNotFound)?;
        let iv = base64::decode(iv)?;
        let ciphertext = parts
            .next()
            .ok_or(AesCbc256ParseError::CiphertextNotFound)?;
        let ciphertext = base64::decode(ciphertext)?;
        Ok(Self {
            iv: iv
                .try_into()
                .map_err(|_| AesCbc256ParseError::InvalidIvLength)?,
            ciphertext,
        })
    }
}

impl Encrypt for AesCbc256 {
    /// The encryption key.
    type Params = [u8; 32];
    fn encrypt<P: AsRef<[u8]>>(plaintext: P, params: &Self::Params) -> Self {
        let enc = params;
        let iv = crate::generate_iv();
        let ciphertext = Cbc::<Aes256, Pkcs7>::new_fix(
            GenericArray::from_slice(enc),
            GenericArray::from_slice(&iv),
        )
        .encrypt_vec(plaintext.as_ref());
        Self { iv, ciphertext }
    }
}

impl Decrypt for AesCbc256 {
    /// The encryption key.
    type Params = [u8; 32];
    type Error = BlockModeError;
    fn decrypt(&self, params: &Self::Params) -> Result<Vec<u8>, Self::Error> {
        let enc = params;
        Cbc::<Aes128, Pkcs7>::new_fix(
            GenericArray::from_slice(enc),
            GenericArray::from_slice(&self.iv),
        )
        .decrypt_vec(&self.ciphertext)
    }
}

impl fmt::Display for AesCbc256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let iv = base64::encode(&self.iv);
        let ciphertext = base64::encode(&self.ciphertext);
        f.write_fmt(format_args!("0.{}|{}", iv, ciphertext))
    }
}

/// Parse error for [`AesCbc128HmacSha256`] and [`AesCbc256HmacSha256`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AesCbcHmacSha256ParseError {
    #[error("failed to parse encryption type")]
    ParseEncryptionType(#[from] ParseIntError),
    #[error("invalid encryption type (expected `{}`, found `{}`)", .expected, .found)]
    InvalidEncryptionType { expected: usize, found: usize },
    #[error("initialization vector not found")]
    IvNotFound,
    #[error("invalid initialization vector length")]
    InvalidIvLength,
    #[error("mac key not found")]
    MacNotFound,
    #[error("invalid mac key length")]
    InvalidMacLength,
    #[error("ciphertext not found")]
    CiphertextNotFound,
    #[error("failed to decode")]
    Decode(#[from] base64::DecodeError),
}

/// Decryption error for [`AesCbc128HmacSha256`] and [`AesCbc256HmacSha256`].
#[derive(Debug, Clone, Error)]
pub enum AesCbcHmacSha256DecryptionError {
    #[error("mac key verification failed")]
    MacVerification(#[from] hmac::crypto_mac::MacError),
    #[error("block mode error")]
    BlockMode(#[from] BlockModeError),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AesCbc128HmacSha256 {
    pub iv: [u8; 16],
    pub mac: [u8; 32],
    pub ciphertext: Vec<u8>,
}

impl Parse for AesCbc128HmacSha256 {
    type Error = AesCbcHmacSha256ParseError;
    fn parse<S: AsRef<str>>(value: S) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        let mut chars = value.chars();
        let ty_end = chars
            .position(|v| v == '.')
            .unwrap_or_else(|| value.chars().count());
        let ty = value[0..ty_end].parse::<usize>()?;
        if ty != 1 {
            return Err(AesCbcHmacSha256ParseError::InvalidEncryptionType {
                expected: 1,
                found: ty,
            });
        }
        let mut parts = chars.as_str().split('|');
        let iv = parts.next().ok_or(AesCbcHmacSha256ParseError::IvNotFound)?;
        let iv = base64::decode(iv)?;
        let ciphertext = parts
            .next()
            .ok_or(AesCbcHmacSha256ParseError::CiphertextNotFound)?;
        let ciphertext = base64::decode(ciphertext)?;
        let mac = parts
            .next()
            .ok_or(AesCbcHmacSha256ParseError::MacNotFound)?;
        let mac = base64::decode(mac)?;
        Ok(Self {
            iv: iv
                .try_into()
                .map_err(|_| AesCbcHmacSha256ParseError::InvalidIvLength)?,
            mac: mac
                .try_into()
                .map_err(|_| AesCbcHmacSha256ParseError::InvalidMacLength)?,
            ciphertext,
        })
    }
}

impl Encrypt for AesCbc128HmacSha256 {
    /// The encryption key and the MAC key.
    type Params = ([u8; 16], [u8; 16]);
    fn encrypt<P: AsRef<[u8]>>(plaintext: P, params: &Self::Params) -> Self {
        let (enc, mac) = params;
        let iv = crate::generate_iv();
        let ciphertext = Cbc::<Aes128, Pkcs7>::new_fix(
            GenericArray::from_slice(enc),
            GenericArray::from_slice(&iv),
        )
        .encrypt_vec(plaintext.as_ref());
        let mut mac = Hmac::<Sha256>::new_from_slice(mac).unwrap();
        mac.update(&iv);
        mac.update(&ciphertext);
        let mac = mac.finalize().into_bytes().into();
        Self {
            iv,
            mac,
            ciphertext,
        }
    }
}

impl Decrypt for AesCbc128HmacSha256 {
    /// The encryption key and the MAC key.
    type Params = ([u8; 16], [u8; 16]);
    type Error = AesCbcHmacSha256DecryptionError;
    fn decrypt(&self, params: &Self::Params) -> Result<Vec<u8>, Self::Error> {
        let (enc, mac) = params;
        let mut new_mac = Hmac::<Sha256>::new_from_slice(mac).unwrap();
        new_mac.update(&self.iv);
        new_mac.update(&self.ciphertext);
        new_mac.verify(&self.mac)?;
        Ok(Cbc::<Aes128, Pkcs7>::new_fix(
            GenericArray::from_slice(enc),
            GenericArray::from_slice(&self.iv),
        )
        .decrypt_vec(&self.ciphertext)?)
    }
}

impl fmt::Display for AesCbc128HmacSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let iv = base64::encode(&self.iv);
        let ciphertext = base64::encode(&self.ciphertext);
        let mac = base64::encode(&self.mac);
        f.write_fmt(format_args!("1.{}|{}|{}", iv, ciphertext, mac))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AesCbc256HmacSha256 {
    pub iv: [u8; 16],
    pub mac: [u8; 32],
    pub ciphertext: Vec<u8>,
}

impl Parse for AesCbc256HmacSha256 {
    type Error = AesCbcHmacSha256ParseError;
    fn parse<S: AsRef<str>>(value: S) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        let mut chars = value.chars();
        let ty_end = chars
            .position(|v| v == '.')
            .unwrap_or_else(|| value.chars().count());
        let ty = value[0..ty_end].parse::<usize>()?;
        if ty != 2 {
            return Err(AesCbcHmacSha256ParseError::InvalidEncryptionType {
                expected: 2,
                found: ty,
            });
        }
        let mut parts = chars.as_str().split('|');
        let iv = parts.next().ok_or(AesCbcHmacSha256ParseError::IvNotFound)?;
        let iv = base64::decode(iv)?;
        let ciphertext = parts
            .next()
            .ok_or(AesCbcHmacSha256ParseError::CiphertextNotFound)?;
        let ciphertext = base64::decode(ciphertext)?;
        let mac = parts
            .next()
            .ok_or(AesCbcHmacSha256ParseError::MacNotFound)?;
        let mac = base64::decode(mac)?;
        Ok(Self {
            iv: iv
                .try_into()
                .map_err(|_| AesCbcHmacSha256ParseError::InvalidIvLength)?,
            mac: mac
                .try_into()
                .map_err(|_| AesCbcHmacSha256ParseError::InvalidMacLength)?,
            ciphertext,
        })
    }
}

impl Encrypt for AesCbc256HmacSha256 {
    /// The encryption key and the MAC key.
    type Params = ([u8; 32], [u8; 32]);
    fn encrypt<P: AsRef<[u8]>>(plaintext: P, params: &Self::Params) -> Self {
        let (enc, mac) = params;
        let iv = crate::generate_iv();
        let ciphertext = Cbc::<Aes256, Pkcs7>::new_fix(
            GenericArray::from_slice(enc),
            GenericArray::from_slice(&iv),
        )
        .encrypt_vec(plaintext.as_ref());
        let mut mac = Hmac::<Sha256>::new_from_slice(mac).unwrap();
        mac.update(&iv);
        mac.update(&ciphertext);
        let mac = mac.finalize().into_bytes().into();
        Self {
            iv,
            mac,
            ciphertext,
        }
    }
}

impl Decrypt for AesCbc256HmacSha256 {
    /// The encryption key and the MAC key.
    type Params = ([u8; 32], [u8; 32]);
    type Error = AesCbcHmacSha256DecryptionError;
    fn decrypt(&self, params: &Self::Params) -> Result<Vec<u8>, Self::Error> {
        let (enc, mac) = params;
        let mut new_mac = Hmac::<Sha256>::new_from_slice(mac).unwrap();
        new_mac.update(&self.iv);
        new_mac.update(&self.ciphertext);
        new_mac.verify(&self.mac)?;
        Ok(Cbc::<Aes256, Pkcs7>::new_fix(
            GenericArray::from_slice(enc),
            GenericArray::from_slice(&self.iv),
        )
        .decrypt_vec(&self.ciphertext)?)
    }
}

impl fmt::Display for AesCbc256HmacSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let iv = base64::encode(&self.iv);
        let ciphertext = base64::encode(&self.ciphertext);
        let mac = base64::encode(&self.mac);
        f.write_fmt(format_args!("2.{}|{}|{}", iv, ciphertext, mac))
    }
}
