use crate::symmetric_encryption::{AesCbcHmacSha256DecryptionError, SymmetricEncryption};
use crate::{Decrypt, SourceKey, SymmetricEncryptedBytes};
use block_modes::BlockModeError;
use rand::{rngs::OsRng, RngCore};
use std::convert::TryInto;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum SymmetricKeyError {
    #[error("invalid length")]
    InvalidLength,
    #[error("the encryption type AesCbc128HmacSha256 is not supported for symmetric keys")]
    UnsupportedEncryptionType,
    #[error("decryption error")]
    AesCbc256Decryption(#[from] BlockModeError),
    #[error("decryption error")]
    AesCbc256HmacSha256Decryption(#[from] AesCbcHmacSha256DecryptionError),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymmetricKey {
    pub enc: [u8; 32],
    pub mac: Option<[u8; 32]>,
}

impl SymmetricKey {
    pub fn new(
        source_key: &SourceKey,
        protected_symmetric_key: &SymmetricEncryptedBytes,
    ) -> Result<Self, SymmetricKeyError> {
        match &protected_symmetric_key.0 {
            SymmetricEncryption::AesCbc256(v) => {
                let enc_key = v.decrypt(&source_key.0)?;
                Ok(Self {
                    enc: enc_key
                        .try_into()
                        .map_err(|_| SymmetricKeyError::InvalidLength)?,
                    mac: None,
                })
            }
            SymmetricEncryption::AesCbc128HmacSha256(_) => {
                Err(SymmetricKeyError::UnsupportedEncryptionType)
            }
            SymmetricEncryption::AesCbc256HmacSha256(v) => {
                let (enc, mac) = source_key.expand();
                let keys = v.decrypt(&(enc, mac))?;
                if keys.len() != 64 {
                    return Err(SymmetricKeyError::InvalidLength);
                }
                Ok(Self {
                    enc: keys[0..32].try_into().unwrap(),
                    mac: Some(keys[32..64].try_into().unwrap()),
                })
            }
        }
    }

    pub(crate) fn generate() -> Self {
        let mut enc = [0; 32];
        OsRng.fill_bytes(&mut enc);
        let mut mac = [0; 32];
        OsRng.fill_bytes(&mut mac);
        Self {
            enc,
            mac: Some(mac),
        }
    }
}
