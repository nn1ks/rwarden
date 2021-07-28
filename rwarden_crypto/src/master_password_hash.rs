use crate::{KdfType, SourceKey};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use serde::{Serialize, Serializer};
use sha2::Sha256;
use std::fmt;

/// A hashed master password.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MasterPasswordHash(pub [u8; 32]);

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
                    &source_key.0,
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

impl fmt::Display for MasterPasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl Serialize for MasterPasswordHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
