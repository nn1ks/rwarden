use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use displaydoc::Display;
use generic_array::GenericArray;
use hkdf::Hkdf;
use hmac::crypto_mac;
use hmac::{Hmac, Mac, NewMac};
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr as DeserializeRepr, Serialize_repr as SerializeRepr};
use sha2::Sha256;
use std::convert::{TryFrom, TryInto};
use std::{fmt, num::ParseIntError, str::FromStr, string::FromUtf8Error};
use thiserror::Error;

/// Error that can occur while parsing a cipher string.
#[derive(Debug, Display, Error)]
pub enum CipherParseError {
    /// Type is not supported.
    UnsupportedType,
    /// IV not found.
    IvNotFound,
    /// Ciphertext not found.
    CiphertextNotFound,
    /// Mac key not found.
    MacNotFound,
    /// Length of IV is invalid.
    InvalidIvLength,
    /// Length of mac key is invalid.
    InvalidMacKeyLength,
    /// Failed to parse type.
    ParseType(#[from] ParseIntError),
    /// Failed to decode.
    Decode(#[from] base64::DecodeError),
}

/// Error that can occur while decrypting a cipher string.
#[derive(Debug, Display, Error)]
pub enum CipherDecryptionError {
    /// The verification of the mac key failed.
    MacVerification(#[from] crypto_mac::MacError),
    /// Block mode error.
    BlockMode(#[from] block_modes::BlockModeError),
}

/// Error that can occur while decrypting a cipher string.
#[derive(Debug, Error)]
pub enum CipherDecryptionStringError {
    #[error(transparent)]
    Other(#[from] CipherDecryptionError),
    /// Decrypted data contains invalid UTF-8.
    #[error("Decrypted data contains invalid UTF-8")]
    InvalidUtf8(#[from] FromUtf8Error),
}

/// An encrypted string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CipherString {
    iv: [u8; 16],
    mac: [u8; 32],
    ciphertext: Vec<u8>,
}

impl CipherString {
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
            return Err(CipherParseError::UnsupportedType);
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

    pub fn encrypt<P>(plaintext: P, enc: &[u8; 32], mac: &[u8; 32]) -> Self
    where
        P: AsRef<[u8]>,
    {
        let iv = generate_iv();
        let ciphertext = Cbc::<Aes256, Pkcs7>::new_fix(
            GenericArray::from_slice(enc.as_ref()),
            GenericArray::from_slice(&iv),
        )
        .encrypt_vec(plaintext.as_ref());
        // let mut mac = Hmac::<Sha256>::new(GenericArray::from_slice(mac));
        let mut mac = Hmac::<Sha256>::new_varkey(mac).unwrap();
        mac.update(&iv);
        mac.update(&ciphertext);
        let mac = mac.finalize().into_bytes().into();
        Self {
            iv,
            ciphertext,
            mac,
        }
    }

    pub fn encrypt_with_keys<P>(plaintext: P, keys: &Keys) -> Self
    where
        P: AsRef<[u8]>,
    {
        Self::encrypt(plaintext, keys.enc(), keys.mac())
    }

    pub fn decrypt_raw(
        &self,
        enc: &[u8; 32],
        mac: &[u8; 32],
    ) -> Result<Vec<u8>, CipherDecryptionError> {
        // let mut mac = Hmac::<Sha256>::new(GenericArray::from_slice(mac));
        let mut mac = Hmac::<Sha256>::new_varkey(mac).unwrap();
        mac.update(&self.iv);
        mac.update(&self.ciphertext);
        mac.verify(&self.mac)?;
        Ok(Cbc::<Aes256, Pkcs7>::new_fix(
            GenericArray::from_slice(enc),
            GenericArray::from_slice(&self.iv),
        )
        .decrypt_vec(&self.ciphertext)?)
    }

    pub fn decrypt(
        &self,
        enc: &[u8; 32],
        mac: &[u8; 32],
    ) -> Result<String, CipherDecryptionStringError> {
        let bytes = self.decrypt_raw(enc, mac)?;
        Ok(String::from_utf8(bytes)?)
    }

    pub fn decrypt_with_keys_raw(&self, keys: &Keys) -> Result<Vec<u8>, CipherDecryptionError> {
        self.decrypt_raw(keys.enc(), keys.mac())
    }

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

/// The KDF type that is used to hash the master password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SerializeRepr, DeserializeRepr)]
#[repr(u8)]
pub enum KdfType {
    /// PBKDF2 SHA-256.
    Pbkdf2Sha256 = 0,
}

/// Keys used for decrypting cipher strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Keys {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl Keys {
    /// Creates the keys.
    pub fn new<U, P>(
        username: U,
        password: P,
        kdf_type: KdfType,
        kdf_iterations: u32,
        protected_symmetric_key: &CipherString,
    ) -> Result<Self, CipherDecryptionError>
    where
        U: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        match kdf_type {
            KdfType::Pbkdf2Sha256 => {
                let master_key = make_master_key(
                    username.as_ref(),
                    password.as_ref(),
                    kdf_type,
                    kdf_iterations,
                );
                Self::derive(&master_key, protected_symmetric_key)
            }
        }
    }

    /// Derives the keys from the master key and a protected symmetric key.
    pub fn derive(
        master_key: &[u8; 32],
        protected_symmetric_key: &CipherString,
    ) -> Result<Self, CipherDecryptionError> {
        let (enc, mac) = expand_keys(master_key);
        let keys = protected_symmetric_key.decrypt_raw(&enc, &mac)?;
        Ok(Self {
            enc: keys[0..32].try_into().unwrap(),
            mac: keys[32..64].try_into().unwrap(),
        })
    }

    fn generate() -> Self {
        let mut enc = [0; 32];
        OsRng.fill_bytes(&mut enc);
        let mut mac = [0; 32];
        OsRng.fill_bytes(&mut mac);
        Self { enc, mac }
    }

    fn into_vec(self) -> Vec<u8> {
        [self.enc, self.mac].concat()
    }

    /// Returns the encryption key.
    pub fn enc(&self) -> &[u8; 32] {
        &self.enc
    }

    /// Returns the MAC key.
    pub fn mac(&self) -> &[u8; 32] {
        &self.mac
    }
}

fn generate_iv() -> [u8; 16] {
    let mut iv = [0; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

fn expand_keys(master_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::from_prk(master_key).unwrap();
    let mut enc = [0; 32];
    hkdf.expand(b"enc", &mut enc).unwrap();
    let mut mac = [0; 32];
    hkdf.expand(b"mac", &mut mac).unwrap();
    (enc, mac)
}

/// Creates the master key.
pub fn make_master_key<U, P>(
    username: U,
    password: P,
    kdf_type: KdfType,
    kdf_iterations: u32,
) -> [u8; 32]
where
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    match kdf_type {
        KdfType::Pbkdf2Sha256 => {
            let mut master_key = [0; 32];
            pbkdf2::<Hmac<Sha256>>(
                password.as_ref(),
                username.as_ref(),
                kdf_iterations,
                &mut master_key,
            );
            master_key
        }
    }
}

/// Creates the master password hash from a master key and password.
pub fn make_master_password_hash<P>(
    master_key: &[u8; 32],
    password: P,
    kdf_type: KdfType,
) -> [u8; 32]
where
    P: AsRef<[u8]>,
{
    match kdf_type {
        KdfType::Pbkdf2Sha256 => {
            let mut master_password_hash = [0; 32];
            pbkdf2::<Hmac<Sha256>>(master_key, password.as_ref(), 1, &mut master_password_hash);
            master_password_hash
        }
    }
}

/// Generates a new protected symmetric key.
pub fn make_protected_symmetric_key(master_key: &[u8; 32]) -> CipherString {
    let (enc, mac) = expand_keys(master_key);
    let keys = Keys::generate();
    CipherString::encrypt(keys.into_vec(), &enc, &mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let keys = Keys::generate();
        let plaintext = "test123";
        let encrypted = CipherString::encrypt_with_keys(plaintext, &keys);
        let decrypted = encrypted.decrypt_with_keys(&keys).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
