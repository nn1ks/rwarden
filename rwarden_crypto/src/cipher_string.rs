use crate::{CipherDecryptionError, CipherDecryptionStringError, CipherParseError, Keys};
use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use generic_array::GenericArray;
use hmac::{Hmac, Mac, NewMac};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::convert::{TryFrom, TryInto};
use std::{fmt, str::FromStr};

/// An encrypted string using AES-CBC 256-bit encryption.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CipherString {
    iv: [u8; 16],
    mac: [u8; 32],
    ciphertext: Vec<u8>,
}

impl CipherString {
    /// Creates a new [`CipherString`] from an initialization vector (`iv`), a MAC key (`mac`), and
    /// the ciphertext.
    pub fn new(iv: [u8; 16], mac: [u8; 32], ciphertext: Vec<u8>) -> Self {
        Self {
            iv,
            mac,
            ciphertext,
        }
    }

    /// Parse an encrypted string in the format `<ty>.<iv>|<ct>|<mac>`.
    ///
    /// - `<ty>`: The encryption type (currently only type `2` is supported)
    /// - `<iv>`: The initialization vector with 16 bytes and encoded as base64
    /// - `<ct>`: The ciphertext encoded as base64
    /// - `<mac>`: The MAC key with 32 bytes and encoded as base64
    ///
    /// # Example
    ///
    /// ```
    /// use rwarden_crypto::CipherString;
    ///
    /// # fn main() -> Result<(), rwarden_crypto::CipherParseError> {
    /// let cipher = CipherString::parse("2.84IzoGc1ydvK9T3MKJD4WQ==|rNZ/2EpbFT4YgQbRcSExgA==|Uy3Zwk0PUNo+rWMZluN83pA8Gm1Ivy3CvO4YvboW8TU=")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse<S>(value: S) -> Result<Self, CipherParseError>
    where
        S: AsRef<str>,
    {
        let value = value.as_ref();
        let mut chars = value.chars();
        let ty_end = chars
            .position(|v| v == '.')
            .unwrap_or_else(|| value.chars().count());
        let ty = value[0..ty_end].parse::<usize>()?;
        if ty != 2 {
            return Err(CipherParseError::UnsupportedEncryptionType);
        }
        let mut parts = chars.as_str().split('|');
        let iv = parts.next().ok_or(CipherParseError::IvNotFound)?;
        let iv = base64::decode(iv)?;
        let ciphertext = parts.next().ok_or(CipherParseError::CiphertextNotFound)?;
        let ciphertext = base64::decode(ciphertext)?;
        let mac = parts.next().ok_or(CipherParseError::MacNotFound)?;
        let mac = base64::decode(mac)?;
        Ok(Self {
            iv: iv
                .try_into()
                .map_err(|_| CipherParseError::InvalidIvLength)?,
            mac: mac
                .try_into()
                .map_err(|_| CipherParseError::InvalidMacKeyLength)?,
            ciphertext,
        })
    }

    /// Encrypt `plaintext` using the given encryption and MAC key.
    pub fn encrypt<P>(plaintext: P, enc: &[u8; 32], mac: &[u8; 32]) -> Self
    where
        P: AsRef<[u8]>,
    {
        let iv = crate::generate_iv();
        let ciphertext = Cbc::<Aes256, Pkcs7>::new_fix(
            GenericArray::from_slice(enc.as_ref()),
            GenericArray::from_slice(&iv),
        )
        .encrypt_vec(plaintext.as_ref());
        // let mut mac = Hmac::<Sha256>::new(GenericArray::from_slice(mac));
        let mut mac = Hmac::<Sha256>::new_from_slice(mac).unwrap();
        mac.update(&iv);
        mac.update(&ciphertext);
        let mac = mac.finalize().into_bytes().into();
        Self {
            iv,
            ciphertext,
            mac,
        }
    }

    /// Encrypt `plaintext` using the encryption and MAC key from `keys`.
    pub fn encrypt_with_keys<P>(plaintext: P, keys: &Keys) -> Self
    where
        P: AsRef<[u8]>,
    {
        Self::encrypt(plaintext, keys.enc(), keys.mac())
    }

    /// Decrypt this encrypted string using the given encryption and MAC key.
    pub fn decrypt_raw(
        &self,
        enc: &[u8; 32],
        mac: &[u8; 32],
    ) -> Result<Vec<u8>, CipherDecryptionError> {
        // let mut mac = Hmac::<Sha256>::new(GenericArray::from_slice(mac));
        let mut mac = Hmac::<Sha256>::new_from_slice(mac).unwrap();
        mac.update(&self.iv);
        mac.update(&self.ciphertext);
        mac.verify(&self.mac)?;
        Ok(Cbc::<Aes256, Pkcs7>::new_fix(
            GenericArray::from_slice(enc),
            GenericArray::from_slice(&self.iv),
        )
        .decrypt_vec(&self.ciphertext)?)
    }

    /// Decrypt this encrypted string using the given encryption and MAC key and convert the
    /// decrypted data to a [`String`].
    pub fn decrypt(
        &self,
        enc: &[u8; 32],
        mac: &[u8; 32],
    ) -> Result<String, CipherDecryptionStringError> {
        let bytes = self.decrypt_raw(enc, mac)?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Decrypt this encrypted string using the encryption and MAC key from `keys`.
    pub fn decrypt_with_keys_raw(&self, keys: &Keys) -> Result<Vec<u8>, CipherDecryptionError> {
        self.decrypt_raw(keys.enc(), keys.mac())
    }

    /// Decrypt this encrypted string using the encryption and MAC key from `keys` and convert the
    /// decrypted data to a [`String`].
    pub fn decrypt_with_keys(&self, keys: &Keys) -> Result<String, CipherDecryptionStringError> {
        self.decrypt(keys.enc(), keys.mac())
    }
}

impl fmt::Display for CipherString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "2.{}|{}|{}",
            base64::encode(&self.iv),
            base64::encode(&self.ciphertext),
            base64::encode(&self.mac),
        )
    }
}

impl FromStr for CipherString {
    type Err = CipherParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for CipherString {
    type Error = CipherParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

struct CipherStringVisitor;

impl<'de> de::Visitor<'de> for CipherStringVisitor {
    type Value = CipherString;

    fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("valid cipher string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<CipherString, E> {
        CipherString::from_str(value)
            .map_err(|e| E::custom(format!("invalid cipher string: {}", e)))
    }
}

impl<'de> Deserialize<'de> for CipherString {
    fn deserialize<D>(deserializer: D) -> Result<CipherString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CipherStringVisitor)
    }
}

impl Serialize for CipherString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
