//! Wrapping tenant data keys under the store's key-encryption subkey.
//!
//! Wrapped format (82 bytes):
//! `version u16 LE ‖ kek_id u32 LE ‖ data_key_id u32 LE ‖ nonce [24] ‖ ct [32] ‖ tag [16]`.
//!
//! Additional data: `"dioptron/v1/wrap" ‖ kek_id u32 LE ‖ data_key_id u32 LE
//! ‖ tenant_id [16]`. Every field is fixed length, so the concatenation is
//! unambiguous without length prefixes. Binding the tenant id means a
//! wrapped key copied under another tenant's entry fails to unwrap; binding
//! both key ids means neither header id can be rewritten.

use chacha20poly1305::aead::{Aead, Payload};
use secrecy::{ExposeSecretMut, SecretBox};
use snafu::{OptionExt, ensure};
use zeroize::Zeroizing;

use super::TenantDataKey;
use super::seal::{cipher, encrypt, random_nonce, xnonce};
use super::{Entropy, KEY_LEN, KeyId, NONCE_LEN, OsEntropy, StoreKeys, TAG_LEN, TENANT_ID_LEN};
use crate::Result;
use crate::error::{
    MalformedSnafu, TenantKeyUnwrapSnafu, UnknownKeyIdSnafu, UnsupportedRecordVersionSnafu,
};

/// Version of the wrapped-key encoding.
pub const WRAPPED_KEY_VERSION: u16 = 1;

/// Length of a wrapped tenant data key in bytes.
pub const WRAPPED_KEY_LEN: usize = 2 + 4 + 4 + NONCE_LEN + KEY_LEN + TAG_LEN;

const WRAP_LABEL: &[u8] = b"dioptron/v1/wrap";

const WRAP_AAD_LEN: usize = WRAP_LABEL.len() + 4 + 4 + TENANT_ID_LEN;

fn wrap_aad(kek_id: KeyId, data_key_id: KeyId, tenant_id: &[u8; TENANT_ID_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_AAD_LEN);
    aad.extend_from_slice(WRAP_LABEL);
    aad.extend_from_slice(&kek_id.get().to_le_bytes());
    aad.extend_from_slice(&data_key_id.get().to_le_bytes());
    aad.extend_from_slice(tenant_id);
    aad
}

impl StoreKeys {
    /// Wrap `key` for storage in the `keys` keyspace under `tenant_id`.
    ///
    /// # Errors
    ///
    /// - [`crate::Error::Entropy`] when the nonce cannot be drawn.
    /// - [`crate::Error::KeyMaterial`] if the cipher rejects the key.
    pub fn wrap_tenant_key(
        &self,
        tenant_id: &[u8; TENANT_ID_LEN],
        key: &TenantDataKey,
    ) -> Result<Vec<u8>> {
        self.wrap_tenant_key_with(tenant_id, key, &mut OsEntropy)
    }

    pub(crate) fn wrap_tenant_key_with(
        &self,
        tenant_id: &[u8; TENANT_ID_LEN],
        key: &TenantDataKey,
        entropy: &mut impl Entropy,
    ) -> Result<Vec<u8>> {
        let kek_id = self.root_key_id();
        let nonce = random_nonce(entropy)?;
        let aad = wrap_aad(kek_id, key.id(), tenant_id);
        let ct = encrypt(self.kek(), &nonce, &aad, key.expose())?;
        let mut out = Vec::with_capacity(WRAPPED_KEY_LEN);
        out.extend_from_slice(&WRAPPED_KEY_VERSION.to_le_bytes());
        out.extend_from_slice(&kek_id.get().to_le_bytes());
        out.extend_from_slice(&key.id().get().to_le_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Unwrap a tenant data key stored under `tenant_id`.
    ///
    /// # Errors
    ///
    /// - [`crate::Error::Malformed`] when `wrapped` is not 82 bytes.
    /// - [`crate::Error::UnsupportedRecordVersion`] for an unknown version.
    /// - [`crate::Error::UnknownKeyId`] when it was wrapped under another root key id.
    /// - [`crate::Error::TenantKeyUnwrap`] when authentication fails (wrong
    ///   tenant, wrong root key, or tampered bytes).
    pub fn unwrap_tenant_key(
        &self,
        tenant_id: &[u8; TENANT_ID_LEN],
        wrapped: &[u8],
    ) -> Result<TenantDataKey> {
        ensure!(
            wrapped.len() == WRAPPED_KEY_LEN,
            MalformedSnafu {
                what: "wrapped tenant key",
                len: wrapped.len(),
            }
        );
        let malformed = || MalformedSnafu {
            what: "wrapped tenant key",
            len: wrapped.len(),
        };
        let (version, rest) = wrapped.split_first_chunk::<2>().with_context(malformed)?;
        let (kek_id, rest) = rest.split_first_chunk::<4>().with_context(malformed)?;
        let (data_key_id, rest) = rest.split_first_chunk::<4>().with_context(malformed)?;
        let (nonce, ct) = rest
            .split_first_chunk::<NONCE_LEN>()
            .with_context(malformed)?;
        let version = u16::from_le_bytes(*version);
        ensure!(
            version == WRAPPED_KEY_VERSION,
            UnsupportedRecordVersionSnafu { found: version }
        );
        let kek_id = KeyId::new(u32::from_le_bytes(*kek_id));
        ensure!(
            kek_id == self.root_key_id(),
            UnknownKeyIdSnafu { found: kek_id }
        );
        let data_key_id = KeyId::new(u32::from_le_bytes(*data_key_id));
        let aad = wrap_aad(kek_id, data_key_id, tenant_id);
        let cipher = cipher(self.kek())?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(xnonce(nonce), Payload { msg: ct, aad: &aad })
                .ok()
                .context(TenantKeyUnwrapSnafu)?,
        );
        let mut bytes = SecretBox::new(Box::new([0_u8; KEY_LEN]));
        let dest = bytes.expose_secret_mut();
        ensure!(
            plain.len() == dest.len(),
            MalformedSnafu {
                what: "unwrapped tenant key",
                len: plain.len(),
            }
        );
        dest.copy_from_slice(&plain);
        Ok(TenantDataKey::from_secret(data_key_id, bytes))
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

    use super::*;
    use crate::Error;
    use crate::crypto::keys::tests::{ROOT_BYTES, store_keys, tenant_key};
    use crate::crypto::test_support::{FailingEntropy, FixedNonce};
    use crate::crypto::{StoreSalt, TenantDataKey};
    use crate::keyfile::RootKey;

    const TENANT_A: [u8; TENANT_ID_LEN] = *b"tenant-marker-A1";
    const TENANT_B: [u8; TENANT_ID_LEN] = *b"tenant-marker-B2";

    #[test]
    fn wrap_unwrap_round_trips() {
        let store = store_keys();
        let key = tenant_key(42, 0x7e);
        let wrapped = store.wrap_tenant_key(&TENANT_A, &key).expect("wrap");
        assert_eq!(wrapped.len(), WRAPPED_KEY_LEN, "fixed wrapped length");
        let back = store
            .unwrap_tenant_key(&TENANT_A, &wrapped)
            .expect("unwrap");
        assert_eq!(back.id(), KeyId::new(42), "key id preserved");
        assert_eq!(back.expose(), key.expose(), "key bytes preserved");
        assert!(
            !wrapped.windows(KEY_LEN).any(|w| w == key.expose()),
            "plaintext data key absent from wrapped bytes"
        );
    }

    // WHY: expected bytes computed outside this crate with the same
    // independent Python reference as the seal known answer (see
    // `seal::tests::seal_matches_known_answer_for_documented_layout`), over
    // the documented wrapped layout and additional data.
    #[test]
    fn wrap_matches_known_answer_for_documented_layout() {
        let store = store_keys();
        let wrapped = store
            .wrap_tenant_key_with(&TENANT_A, &tenant_key(42, 0x7e), &mut FixedNonce)
            .expect("wrap");
        let expected = concat!(
            "0100",
            "01000000",
            "2a000000",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7",
            "5e7c059a7b24e29675bf1ab6a3c6a6f33aee4b2f9fedf1322923ff9017dba74e",
            "c287d1ff0fc9b9d69ddcc13a50464652",
        );
        assert_eq!(
            crate::crypto::test_support::hex(&wrapped),
            expected,
            "wrapped bytes match the reference"
        );
    }

    #[test]
    fn unwrap_under_wrong_tenant_fails() {
        let store = store_keys();
        let wrapped = store
            .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
            .expect("wrap");
        let err = store
            .unwrap_tenant_key(&TENANT_B, &wrapped)
            .expect_err("wrong tenant");
        assert!(matches!(err, Error::TenantKeyUnwrap { .. }), "got {err:?}");
    }

    #[test]
    fn unwrap_with_rewritten_data_key_id_fails() {
        let store = store_keys();
        let mut wrapped = store
            .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
            .expect("wrap");
        if let Some(b) = wrapped.get_mut(6) {
            *b ^= 1;
        }
        let err = store
            .unwrap_tenant_key(&TENANT_A, &wrapped)
            .expect_err("id rewritten");
        assert!(matches!(err, Error::TenantKeyUnwrap { .. }), "got {err:?}");
    }

    #[test]
    fn unwrap_with_other_root_key_fails() {
        let store = store_keys();
        let wrapped = store
            .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
            .expect("wrap");
        let mut other = ROOT_BYTES;
        other[0] ^= 1;
        let other = StoreKeys::derive(
            &RootKey::from_bytes(other),
            store.root_key_id(),
            &StoreSalt::from_bytes([0x22; 32]),
        )
        .expect("derive");
        let err = other
            .unwrap_tenant_key(&TENANT_A, &wrapped)
            .expect_err("other root");
        assert!(matches!(err, Error::TenantKeyUnwrap { .. }), "got {err:?}");
    }

    #[test]
    fn unwrap_rejects_unknown_kek_id_version_and_length() {
        let store = store_keys();
        let wrapped = store
            .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
            .expect("wrap");

        let mut other_kek = wrapped.clone();
        if let Some(b) = other_kek.get_mut(2) {
            *b ^= 1;
        }
        let err = store
            .unwrap_tenant_key(&TENANT_A, &other_kek)
            .expect_err("kek id");
        assert!(matches!(err, Error::UnknownKeyId { .. }), "got {err:?}");

        let mut other_version = wrapped.clone();
        if let Some(b) = other_version.get_mut(0) {
            *b = 9;
        }
        let err = store
            .unwrap_tenant_key(&TENANT_A, &other_version)
            .expect_err("version");
        assert!(
            matches!(err, Error::UnsupportedRecordVersion { found: 9, .. }),
            "got {err:?}"
        );

        let short = wrapped.get(..WRAPPED_KEY_LEN - 1).expect("prefix");
        let err = store
            .unwrap_tenant_key(&TENANT_A, short)
            .expect_err("short");
        assert!(matches!(err, Error::Malformed { .. }), "got {err:?}");
    }

    #[test]
    fn unwrap_rejects_tampered_nonce_ciphertext_and_tag() {
        let store = store_keys();
        let wrapped = store
            .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
            .expect("wrap");
        for index in [10, 10 + NONCE_LEN, WRAPPED_KEY_LEN - 1] {
            let mut tampered = wrapped.clone();
            if let Some(b) = tampered.get_mut(index) {
                *b ^= 0x80;
            }
            let err = store
                .unwrap_tenant_key(&TENANT_A, &tampered)
                .expect_err("tampered");
            assert!(
                matches!(err, Error::TenantKeyUnwrap { .. }),
                "byte {index}: {err:?}"
            );
        }
    }

    #[test]
    fn wrap_surfaces_entropy_failure() {
        let store = store_keys();
        let err = store.wrap_tenant_key_with(&TENANT_A, &tenant_key(1, 0x7e), &mut FailingEntropy);
        assert!(
            matches!(err, Err(Error::Entropy { .. })),
            "entropy failure surfaces"
        );
    }

    #[test]
    fn unwrapped_key_derives_same_subkeys() {
        let store = store_keys();
        let key = TenantDataKey::generate(KeyId::new(3)).expect("generate");
        let wrapped = store.wrap_tenant_key(&TENANT_A, &key).expect("wrap");
        let back = store
            .unwrap_tenant_key(&TENANT_A, &wrapped)
            .expect("unwrap");
        let body = b"same body";
        assert_eq!(
            key.derive()
                .and_then(|k| k.blob_address(body))
                .expect("orig"),
            back.derive()
                .and_then(|k| k.blob_address(body))
                .expect("back"),
            "unwrapped key is the same key"
        );
    }
}
