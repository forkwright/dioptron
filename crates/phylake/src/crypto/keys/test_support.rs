//! Test-only constructors for key types.

use secrecy::SecretBox;

use super::{KEY_LEN, SubKey};

impl SubKey {
    /// A subkey holding `bytes`, for known-answer tests.
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
        }
    }
}
