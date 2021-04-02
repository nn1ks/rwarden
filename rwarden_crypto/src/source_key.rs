use crate::KdfType;
use hkdf::Hkdf;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

/// An intermediate type used for creating [`Keys`] and [`MasterPasswordHash`].
///
/// [`Keys`]: crate::Keys
/// [`MasterPasswordHash`]: crate::MasterPasswordHash
pub struct SourceKey([u8; 32]);

impl SourceKey {
    /// Creates a new [`SourceKey`].
    pub fn new<U, P>(username: U, password: P, kdf_type: KdfType, kdf_iterations: u32) -> Self
    where
        U: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        match kdf_type {
            KdfType::Pbkdf2Sha256 => {
                let mut source_key = [0; 32];
                pbkdf2::<Hmac<Sha256>>(
                    password.as_ref(),
                    username.as_ref(),
                    kdf_iterations,
                    &mut source_key,
                );
                Self(source_key)
            }
        }
    }

    pub(crate) fn expand(&self) -> ([u8; 32], [u8; 32]) {
        let hkdf = Hkdf::<Sha256>::from_prk(&self.0).unwrap();
        let mut enc = [0; 32];
        hkdf.expand(b"enc", &mut enc).unwrap();
        let mut mac = [0; 32];
        hkdf.expand(b"mac", &mut mac).unwrap();
        (enc, mac)
    }
}

impl From<[u8; 32]> for SourceKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<SourceKey> for [u8; 32] {
    fn from(value: SourceKey) -> [u8; 32] {
        value.0
    }
}

impl AsRef<[u8; 32]> for SourceKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}