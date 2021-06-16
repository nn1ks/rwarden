use displaydoc::Display;
use hmac::crypto_mac;
use rand::{rngs::OsRng, RngCore};
use serde_repr::{Deserialize_repr as DeserializeRepr, Serialize_repr as SerializeRepr};
use std::{num::ParseIntError, string::FromUtf8Error};
use thiserror::Error;

pub use cipher_string::CipherString;
pub use keys::Keys;
pub use master_password_hash::MasterPasswordHash;
pub use source_key::SourceKey;

mod cipher_string;
mod keys;
mod master_password_hash;
mod source_key;

/// Error that can occur while parsing a cipher string.
#[derive(Debug, Display, Error)]
pub enum CipherParseError {
    /// Encryption type is not supported.
    UnsupportedEncryptionType,
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
#[derive(Debug, Clone, Display, Error)]
pub enum CipherDecryptionError {
    /// The verification of the mac key failed.
    MacVerification(#[from] crypto_mac::MacError),
    /// Block mode error.
    BlockMode(#[from] block_modes::BlockModeError),
}

/// Error that can occur while decrypting a cipher string.
#[derive(Debug, Clone, Error)]
pub enum CipherDecryptionStringError {
    #[error(transparent)]
    Other(#[from] CipherDecryptionError),
    /// Decrypted data contains invalid UTF-8.
    #[error("Decrypted data contains invalid UTF-8")]
    InvalidUtf8(#[from] FromUtf8Error),
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
pub fn generate_protected_symmetric_key(source_key: &SourceKey) -> CipherString {
    let (enc, mac) = source_key.expand();
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
