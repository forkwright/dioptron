//! Wrapping tenant data keys under the store's key-encryption subkey.
//!
//! Tenant data keys and, once a tenant's data key has rotated, the
//! tenant's addressing subkeys are wrapped here.
//!
//! Wrapped format (82 bytes):
//! `version u16 LE ‖ kek_id u32 LE ‖ data_key_id u32 LE ‖ nonce [24] ‖ ct [32] ‖ tag [16]`.
//!
//! Additional data: `"dioptron/v1/wrap" ‖ kek_id u32 LE ‖ data_key_id u32 LE
//! ‖ tenant_id [16]`. Every field is fixed length, so the concatenation is
//! unambiguous without length prefixes. Binding the tenant id means a
//! wrapped key copied under another tenant's entry fails to unwrap; binding
//! both key ids means neither header id can be rewritten.
//!
//! Wrapped addressing subkeys (118 bytes):
//! `version u16 LE ‖ kek_id u32 LE ‖ nonce [24] ‖ ct [64] ‖ tag [16]`, where
//! the plaintext is the index subkey followed by the blob-address subkey.
//! Additional data: `"dioptron/v1/wrap-address" ‖ kek_id u32 LE ‖
//! tenant_id [16]`. The distinct label keeps a wrapped data key and wrapped
//! addressing subkeys from opening as each other.

use chacha20poly1305::aead::{Aead, Payload};
use secrecy::{ExposeSecretMut, SecretBox};
use snafu::{OptionExt, ensure};
use zeroize::Zeroizing;

use super::seal::{cipher, encrypt, random_nonce, xnonce};
use super::{AddressKeys, TenantDataKey};
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

/// Version of the wrapped addressing-subkey encoding.
const WRAPPED_ADDRESS_VERSION: u16 = 1;

/// Length of wrapped addressing subkeys in bytes.
pub(crate) const WRAPPED_ADDRESS_LEN: usize = 2 + 4 + NONCE_LEN + 2 * KEY_LEN + TAG_LEN;

const ADDRESS_WRAP_LABEL: &[u8] = b"dioptron/v1/wrap-address";

const ADDRESS_AAD_LEN: usize = ADDRESS_WRAP_LABEL.len() + 4 + TENANT_ID_LEN;

fn address_aad(kek_id: KeyId, tenant_id: &[u8; TENANT_ID_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ADDRESS_AAD_LEN);
    aad.extend_from_slice(ADDRESS_WRAP_LABEL);
    aad.extend_from_slice(&kek_id.get().to_le_bytes());
    aad.extend_from_slice(tenant_id);
    aad
}

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

impl StoreKeys {
    /// Wrap `keys`, a tenant's addressing subkeys, for storage in the
    /// `keys` keyspace under `tenant_id`.
    pub(crate) fn wrap_address_keys_with(
        &self,
        tenant_id: &[u8; TENANT_ID_LEN],
        keys: &AddressKeys,
        entropy: &mut impl Entropy,
    ) -> Result<Vec<u8>> {
        let kek_id = self.root_key_id();
        let nonce = random_nonce(entropy)?;
        let mut plain = Zeroizing::new([0_u8; 2 * KEY_LEN]);
        let (index, blob_addr) = plain.split_at_mut(KEY_LEN);
        index.copy_from_slice(keys.index().expose());
        blob_addr.copy_from_slice(keys.blob_addr().expose());
        let ct = encrypt(self.kek(), &nonce, &address_aad(kek_id, tenant_id), &*plain)?;
        let mut out = Vec::with_capacity(WRAPPED_ADDRESS_LEN);
        out.extend_from_slice(&WRAPPED_ADDRESS_VERSION.to_le_bytes());
        out.extend_from_slice(&kek_id.get().to_le_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Unwrap a tenant's addressing subkeys stored under `tenant_id`.
    ///
    /// Errors as [`StoreKeys::unwrap_tenant_key`].
    pub(crate) fn unwrap_address_keys(
        &self,
        tenant_id: &[u8; TENANT_ID_LEN],
        wrapped: &[u8],
    ) -> Result<AddressKeys> {
        let malformed = || MalformedSnafu {
            what: "wrapped addressing subkeys",
            len: wrapped.len(),
        };
        ensure!(wrapped.len() == WRAPPED_ADDRESS_LEN, malformed());
        let (version, rest) = wrapped.split_first_chunk::<2>().with_context(malformed)?;
        let (kek_id, rest) = rest.split_first_chunk::<4>().with_context(malformed)?;
        let (nonce, ct) = rest
            .split_first_chunk::<NONCE_LEN>()
            .with_context(malformed)?;
        let version = u16::from_le_bytes(*version);
        ensure!(
            version == WRAPPED_ADDRESS_VERSION,
            UnsupportedRecordVersionSnafu { found: version }
        );
        let kek_id = KeyId::new(u32::from_le_bytes(*kek_id));
        ensure!(
            kek_id == self.root_key_id(),
            UnknownKeyIdSnafu { found: kek_id }
        );
        let aad = address_aad(kek_id, tenant_id);
        let plain = Zeroizing::new(
            cipher(self.kek())?
                .decrypt(xnonce(nonce), Payload { msg: ct, aad: &aad })
                .ok()
                .context(TenantKeyUnwrapSnafu)?,
        );
        let (index, blob_addr) = plain
            .split_first_chunk::<KEY_LEN>()
            .context(MalformedSnafu {
                what: "unwrapped addressing subkeys",
                len: plain.len(),
            })?;
        let blob_addr = <&[u8; KEY_LEN]>::try_from(blob_addr)
            .ok()
            .context(MalformedSnafu {
                what: "unwrapped addressing subkeys",
                len: plain.len(),
            })?;
        Ok(AddressKeys::copy_from(index, blob_addr))
    }
}

#[cfg(test)]
mod tests;
