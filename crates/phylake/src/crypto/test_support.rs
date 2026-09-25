#![expect(clippy::expect_used, reason = "test helpers must fail loudly")]

use secrecy::SecretBox;
use snafu::IntoError;

use super::{Entropy, KEY_LEN, KeyId, StoreKeys, StoreSalt, TenantDataKey};
use crate::Result;
use crate::error::EntropySnafu;
use crate::keyfile::RootKey;

/// Root key bytes shared by the crypto test modules.
pub(crate) const ROOT_BYTES: [u8; 32] = [0x11; 32];
/// Root key id shared by the crypto test modules.
pub(crate) const ROOT_ID: KeyId = KeyId::new(1);

/// Store keys derived from [`ROOT_BYTES`] under a fixed salt.
pub(crate) fn store_keys() -> StoreKeys {
    let root = RootKey::from_bytes(ROOT_BYTES);
    StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([0x22; 32])).expect("derive")
}

/// A tenant data key with id `id` whose bytes are all `fill`.
pub(crate) fn tenant_key(id: u32, fill: u8) -> TenantDataKey {
    TenantDataKey::from_secret(KeyId::new(id), SecretBox::new(Box::new([fill; KEY_LEN])))
}

/// An entropy source that always fails.
pub(crate) struct FailingEntropy;

impl Entropy for FailingEntropy {
    fn fill(&mut self, _dest: &mut [u8]) -> Result<()> {
        Err(EntropySnafu.into_error(getrandom::Error::UNSUPPORTED))
    }
}

/// An entropy source that returns the fixed nonce 0xa0..=0xb7, so a
/// sealed value can be compared byte for byte with a known answer.
pub(crate) struct FixedNonce;

impl Entropy for FixedNonce {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        assert_eq!(
            dest.len(),
            super::NONCE_LEN,
            "FixedNonce serves nonces only"
        );
        for (byte, value) in dest.iter_mut().zip(0xa0_u8..) {
            *byte = value;
        }
        Ok(())
    }
}

/// Decode hex, ignoring any non-hex characters between digits.
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    clean
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ascii");
            u8::from_str_radix(pair, 16).expect("hex")
        })
        .collect()
}

/// Lowercase hex of `bytes`, for asserting key bytes are absent from text.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
