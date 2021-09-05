use rand::{rngs::OsRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr as DeserializeRepr, Serialize_repr as SerializeRepr};
use std::{error::Error as StdError, fmt, marker::PhantomData, string::FromUtf8Error};

pub use asymmetric_encryption::AsymmetricEncryption;
pub use master_password_hash::MasterPasswordHash;
pub use source_key::SourceKey;
pub use symmetric_encryption::SymmetricEncryption;
pub use symmetric_key::{SymmetricKey, SymmetricKeyError};

pub mod asymmetric_encryption;
pub mod symmetric_encryption;

mod master_password_hash;
mod source_key;
mod symmetric_key;

pub trait Encrypt {
    type Params;
    fn encrypt<P: AsRef<[u8]>>(plaintext: P, params: &Self::Params) -> Self;
}

pub trait Decrypt {
    type Params;
    type Error;
    fn decrypt(&self, params: &Self::Params) -> Result<Vec<u8>, Self::Error>;
}

pub trait Parse: Sized {
    type Error: StdError;
    fn parse<S: AsRef<str>>(value: S) -> Result<Self, Self::Error>;
}

/// The KDF type that is used to hash the master password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SerializeRepr, DeserializeRepr)]
#[repr(u8)]
pub enum KdfType {
    /// PBKDF2 SHA-256.
    Pbkdf2Sha256 = 0,
}

pub(crate) fn generate_iv() -> [u8; 16] {
    let mut iv = [0; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

/// Generates a new protected symmetric key.
pub fn generate_protected_symmetric_key(
    source_key: &SourceKey,
) -> GenericEncryptedBytes<symmetric_encryption::AesCbc256HmacSha256> {
    let (enc, mac) = source_key.expand();
    let keys = SymmetricKey::generate();
    // unwrap is safe here because `SymmetricKey::generate()` always sets the mac field to `Some`
    let data = [keys.enc, keys.mac.unwrap()].concat();
    GenericEncryptedBytes(symmetric_encryption::AesCbc256HmacSha256::encrypt(
        data,
        &(enc, mac),
    ))
}

pub type SymmetricEncryptedBytes = GenericEncryptedBytes<SymmetricEncryption>;
pub type AsymmetricEncryptedBytes = GenericEncryptedBytes<AsymmetricEncryption>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenericEncryptedBytes<E>(pub E);

impl<E: Parse> GenericEncryptedBytes<E> {
    pub fn parse<S: AsRef<str>>(value: S) -> Result<Self, E::Error> {
        Ok(Self(E::parse(value)?))
    }
}

impl<E: Encrypt> GenericEncryptedBytes<E> {
    pub fn encrypt<P: AsRef<[u8]>>(plaintext: P, params: &E::Params) -> Self {
        Self(E::encrypt(plaintext, params))
    }
}

impl<E: Decrypt> GenericEncryptedBytes<E> {
    pub fn decrypt(&self, params: &E::Params) -> Result<Vec<u8>, E::Error> {
        self.0.decrypt(params)
    }
}

impl<E: Into<SymmetricEncryption>> GenericEncryptedBytes<E> {
    pub fn into_symmetric(self) -> SymmetricEncryptedBytes {
        GenericEncryptedBytes(self.0.into())
    }
}

impl<E: Into<AsymmetricEncryption>> GenericEncryptedBytes<E> {
    pub fn into_asymmetric(self) -> AsymmetricEncryptedBytes {
        GenericEncryptedBytes(self.0.into())
    }
}

impl<E> From<E> for GenericEncryptedBytes<E> {
    fn from(encryption: E) -> Self {
        Self(encryption)
    }
}

impl<E: fmt::Display> fmt::Display for GenericEncryptedBytes<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

struct GenericEncryptedBytesVisitor<E>(PhantomData<E>);

impl<'de, E: Parse> de::Visitor<'de> for GenericEncryptedBytesVisitor<E> {
    type Value = GenericEncryptedBytes<E>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("valid cipher string")
    }

    fn visit_str<Error: de::Error>(self, value: &str) -> Result<Self::Value, Error> {
        GenericEncryptedBytes::parse(value)
            .map_err(|e| Error::custom(format!("invalid cipher string: {}", e)))
    }
}

impl<'de, E: Parse> Deserialize<'de> for GenericEncryptedBytes<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let visitor = GenericEncryptedBytesVisitor(PhantomData);
        deserializer.deserialize_str(visitor)
    }
}

impl<E: fmt::Display> Serialize for GenericEncryptedBytes<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringDecryptionError<E> {
    InvalidUtf8(FromUtf8Error),
    Other(E),
}

impl<E: StdError> StdError for StringDecryptionError<E> {}

impl<E: StdError> fmt::Display for StringDecryptionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8(_) => f.write_str("invalid utf8"),
            Self::Other(e) => fmt::Display::fmt(&e, f),
        }
    }
}

impl<E> From<FromUtf8Error> for StringDecryptionError<E> {
    fn from(e: FromUtf8Error) -> Self {
        Self::InvalidUtf8(e)
    }
}

pub type SymmetricEncryptedString = GenericEncryptedString<SymmetricEncryption>;
pub type AsymmetricEncryptedString = GenericEncryptedString<AsymmetricEncryption>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenericEncryptedString<E>(pub GenericEncryptedBytes<E>);

impl<E: Parse> GenericEncryptedString<E> {
    pub fn parse<S: AsRef<str>>(value: S) -> Result<Self, E::Error> {
        Ok(Self(GenericEncryptedBytes::parse(value)?))
    }
}

impl<E: Encrypt> GenericEncryptedString<E> {
    pub fn encrypt<P: AsRef<str>>(plaintext: P, params: &E::Params) -> Self {
        Self(GenericEncryptedBytes::encrypt(plaintext.as_ref(), params))
    }
}

impl<E: Decrypt> GenericEncryptedString<E> {
    pub fn decrypt(&self, params: &E::Params) -> Result<String, StringDecryptionError<E::Error>> {
        let bytes = self
            .0
            .decrypt(params)
            .map_err(StringDecryptionError::Other)?;
        Ok(String::from_utf8(bytes)?)
    }
}

impl<E: Into<SymmetricEncryption>> GenericEncryptedString<E> {
    pub fn into_symmetric(self) -> SymmetricEncryptedString {
        GenericEncryptedString(self.0.into_symmetric())
    }
}

impl<E: Into<AsymmetricEncryption>> GenericEncryptedString<E> {
    pub fn into_asymmetric(self) -> AsymmetricEncryptedString {
        GenericEncryptedString(self.0.into_asymmetric())
    }
}

impl<E> From<E> for GenericEncryptedString<E> {
    fn from(encryption: E) -> Self {
        Self(GenericEncryptedBytes(encryption))
    }
}

impl<E> From<GenericEncryptedBytes<E>> for GenericEncryptedString<E> {
    fn from(encrypted_bytes: GenericEncryptedBytes<E>) -> Self {
        Self(encrypted_bytes)
    }
}

impl<E: fmt::Display> fmt::Display for GenericEncryptedString<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

struct GenericEncryptedStringVisitor<E>(PhantomData<E>);

impl<'de, E: Parse> de::Visitor<'de> for GenericEncryptedStringVisitor<E> {
    type Value = GenericEncryptedString<E>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("valid cipher string")
    }

    fn visit_str<Error: de::Error>(self, value: &str) -> Result<Self::Value, Error> {
        GenericEncryptedString::parse(value)
            .map_err(|e| Error::custom(format!("invalid cipher string: {}", e)))
    }
}

impl<'de, E: Parse> Deserialize<'de> for GenericEncryptedString<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let visitor = GenericEncryptedStringVisitor(PhantomData);
        deserializer.deserialize_str(visitor)
    }
}

impl<E: fmt::Display> Serialize for GenericEncryptedString<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
