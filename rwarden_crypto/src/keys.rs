use crate::{CipherDecryptionError, CipherString, SourceKey};
use rand::{rngs::OsRng, RngCore};
use std::convert::TryInto;

/// Keys used for decrypting cipher strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Keys {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl Keys {
    /// Creates new [`Keys`].
    pub fn new(
        source_key: &SourceKey,
        protected_symmetric_key: &CipherString,
    ) -> Result<Self, CipherDecryptionError> {
        let (enc, mac) = source_key.expand();
        let keys = protected_symmetric_key.decrypt_raw(&enc, &mac)?;
        Ok(Self {
            enc: keys[0..32].try_into().unwrap(),
            mac: keys[32..64].try_into().unwrap(),
        })
    }

    pub(crate) fn generate() -> Self {
        let mut enc = [0; 32];
        OsRng.fill_bytes(&mut enc);
        let mut mac = [0; 32];
        OsRng.fill_bytes(&mut mac);
        Self { enc, mac }
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
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
