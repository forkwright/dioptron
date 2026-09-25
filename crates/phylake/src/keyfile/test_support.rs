//! Test-only constructors for the root key.

use secrecy::SecretBox;

use super::{ROOT_KEY_LEN, RootKey};

impl RootKey {
    /// A root key holding `bytes`, without touching the filesystem.
    pub(crate) fn from_bytes(bytes: [u8; ROOT_KEY_LEN]) -> Self {
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
        }
    }
}
