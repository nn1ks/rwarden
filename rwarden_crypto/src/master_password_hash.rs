use crate::{KdfType, SourceKey};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

/// A hashed master password.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MasterPasswordHash([u8; 32]);

impl MasterPasswordHash {
    /// Creates a new [`MasterPasswordHash`].
    pub fn new<P>(source_key: &SourceKey, password: P, kdf_type: KdfType) -> Self
    where
        P: AsRef<[u8]>,
    {
        match kdf_type {
            KdfType::Pbkdf2Sha256 => {
                let mut master_password_hash = [0; 32];
                pbkdf2::<Hmac<Sha256>>(
                    source_key.as_ref(),
                    password.as_ref(),
                    1,
                    &mut master_password_hash,
                );
                Self(master_password_hash)
            }
        }
    }

    /// Encodes the master password hash as base64.
    pub fn encode(&self) -> String {
        base64::encode(self.0)
    }
}

impl From<[u8; 32]> for MasterPasswordHash {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<MasterPasswordHash> for [u8; 32] {
    fn from(value: MasterPasswordHash) -> [u8; 32] {
        value.0
    }
}

impl AsRef<[u8; 32]> for MasterPasswordHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
