//! Key hierarchy: store subkeys from the root key, tenant data keys, and
//! tenant subkeys.

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use snafu::ensure;
use zeroize::ZeroizeOnDrop;

use super::{
    BlobAddress, Entropy, KEY_LEN, KeyCheck, KeyId, OsEntropy, hkdf_expand, hkdf_extract,
    hmac_sha256, hmac_sha256_verify, random_array,
};
use crate::Result;
use crate::error::StoreLockedSnafu;
use crate::keyfile::RootKey;

/// HKDF info labels for store subkeys derived from the root key. The
/// version segment changes only with a new derivation scheme.
mod label {
    pub(super) const BLOB: &[u8] = b"dioptron/v1/blob";
    pub(super) const META: &[u8] = b"dioptron/v1/meta";
    pub(super) const AUDIT: &[u8] = b"dioptron/v1/audit";
    pub(super) const INDEX: &[u8] = b"dioptron/v1/index";
    pub(super) const KEK: &[u8] = b"dioptron/v1/kek";
    pub(super) const CHECK: &[u8] = b"dioptron/v1/check";

    pub(super) const TENANT_BLOB: &[u8] = b"dioptron/v1/tenant/blob";
    pub(super) const TENANT_BLOB_ADDR: &[u8] = b"dioptron/v1/tenant/blob-addr";
    pub(super) const TENANT_META: &[u8] = b"dioptron/v1/tenant/meta";
    pub(super) const TENANT_AUDIT: &[u8] = b"dioptron/v1/tenant/audit";
    pub(super) const TENANT_INDEX: &[u8] = b"dioptron/v1/tenant/index";
}

/// Message the key-check MAC is computed over.
const KEY_CHECK_MESSAGE: &[u8] = b"dioptron-key-check";

/// A 32-byte derived subkey, zeroed on drop.
pub struct SubKey {
    bytes: SecretBox<[u8; KEY_LEN]>,
}

impl SubKey {
    fn derive(hk: &hkdf::Hkdf<sha2::Sha256>, info: &[u8]) -> Result<Self> {
        let mut bytes = SecretBox::new(Box::new([0_u8; KEY_LEN]));
        hkdf_expand(hk, info, bytes.expose_secret_mut())?;
        Ok(Self { bytes })
    }

    /// HMAC-SHA256 of `input` under this subkey, for keyed index entries.
    ///
    /// # Errors
    ///
    /// [`crate::Error::KeyMaterial`] if the MAC rejects the key; HMAC accepts
    /// any key length, so this does not occur for a 32-byte subkey.
    pub fn keyed_hash(&self, input: &[u8]) -> Result<[u8; 32]> {
        hmac_sha256(self.expose(), &[input])
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        self.bytes.expose_secret()
    }
}

impl ZeroizeOnDrop for SubKey {}

impl std::fmt::Debug for SubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubKey([REDACTED])")
    }
}

/// A subkey used for XChaCha20-Poly1305 sealing, tagged with the key id
/// written into each sealed header.
#[derive(Debug)]
pub struct SealingKey {
    id: KeyId,
    key: SubKey,
}

impl SealingKey {
    /// The key id written into sealed headers.
    #[must_use]
    pub const fn id(&self) -> KeyId {
        self.id
    }

    pub(crate) fn subkey(&self) -> &SubKey {
        &self.key
    }
}

/// The per-store HKDF salt, stored in plaintext in `meta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreSalt([u8; 32]);

impl StoreSalt {
    /// Draw a new salt from the operating system random source.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Entropy`] when the random source fails.
    pub fn generate() -> Result<Self> {
        Self::generate_with(&mut OsEntropy)
    }

    pub(crate) fn generate_with(entropy: &mut impl Entropy) -> Result<Self> {
        Ok(Self(random_array(entropy)?))
    }

    /// Rebuild a salt read back from `meta`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The salt bytes, for storing in `meta`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Store-level subkeys derived from the root key.
#[derive(Debug)]
pub struct StoreKeys {
    root_key_id: KeyId,
    blob: SealingKey,
    meta: SealingKey,
    audit: SealingKey,
    index: SubKey,
    kek: SubKey,
    check: SubKey,
}

impl StoreKeys {
    /// Derive store subkeys for a store being created. The caller persists
    /// [`StoreKeys::key_check`] with the salt and root key id.
    ///
    /// # Errors
    ///
    /// [`crate::Error::KeyMaterial`] if a derivation primitive rejects its input.
    pub fn derive(root: &RootKey, root_key_id: KeyId, salt: &StoreSalt) -> Result<Self> {
        let hk = hkdf_extract(Some(salt.as_bytes()), root.expose());
        let sealing = |info| -> Result<SealingKey> {
            Ok(SealingKey {
                id: root_key_id,
                key: SubKey::derive(&hk, info)?,
            })
        };
        Ok(Self {
            root_key_id,
            blob: sealing(label::BLOB)?,
            meta: sealing(label::META)?,
            audit: sealing(label::AUDIT)?,
            index: SubKey::derive(&hk, label::INDEX)?,
            kek: SubKey::derive(&hk, label::KEK)?,
            check: SubKey::derive(&hk, label::CHECK)?,
        })
    }

    /// Derive store subkeys for an existing store and verify them against
    /// the stored key-check value. The comparison is constant time.
    ///
    /// # Errors
    ///
    /// - [`crate::Error::StoreLocked`] when `stored_check` does not match; the
    ///   store must not be opened.
    /// - [`crate::Error::KeyMaterial`] if a derivation primitive rejects its input.
    pub fn unlock(
        root: &RootKey,
        root_key_id: KeyId,
        salt: &StoreSalt,
        stored_check: &[u8],
    ) -> Result<Self> {
        let keys = Self::derive(root, root_key_id, salt)?;
        let matches = hmac_sha256_verify(keys.check.expose(), KEY_CHECK_MESSAGE, stored_check)?;
        ensure!(matches, StoreLockedSnafu);
        Ok(keys)
    }

    /// The key-check value to persist in `meta`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::KeyMaterial`] if the MAC rejects the key.
    pub fn key_check(&self) -> Result<KeyCheck> {
        hmac_sha256(self.check.expose(), &[KEY_CHECK_MESSAGE]).map(KeyCheck)
    }

    /// The root key id these subkeys were derived under.
    #[must_use]
    pub const fn root_key_id(&self) -> KeyId {
        self.root_key_id
    }

    /// Sealing key for store-level blob records.
    #[must_use]
    pub const fn blob(&self) -> &SealingKey {
        &self.blob
    }

    /// Sealing key for store-level metadata records.
    #[must_use]
    pub const fn meta(&self) -> &SealingKey {
        &self.meta
    }

    /// Sealing key for store-level audit records.
    #[must_use]
    pub const fn audit(&self) -> &SealingKey {
        &self.audit
    }

    /// Subkey for keyed hashes of store-level index keys.
    #[must_use]
    pub const fn index(&self) -> &SubKey {
        &self.index
    }

    pub(crate) fn kek(&self) -> &SubKey {
        &self.kek
    }
}

/// A tenant's random data key, zeroed on drop. On disk it exists only
/// wrapped by the store's key-encryption subkey.
pub struct TenantDataKey {
    id: KeyId,
    bytes: SecretBox<[u8; KEY_LEN]>,
}

impl TenantDataKey {
    /// Draw a new tenant data key from the operating system random source.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Entropy`] when the random source fails.
    pub fn generate(id: KeyId) -> Result<Self> {
        Self::generate_with(id, &mut OsEntropy)
    }

    pub(crate) fn generate_with(id: KeyId, entropy: &mut impl Entropy) -> Result<Self> {
        let bytes = SecretBox::new(Box::new(random_array::<KEY_LEN>(entropy)?));
        Ok(Self { id, bytes })
    }

    pub(crate) fn from_secret(id: KeyId, bytes: SecretBox<[u8; KEY_LEN]>) -> Self {
        Self { id, bytes }
    }

    /// The data key's id.
    #[must_use]
    pub const fn id(&self) -> KeyId {
        self.id
    }

    /// Derive the tenant's subkeys.
    ///
    /// # Errors
    ///
    /// [`crate::Error::KeyMaterial`] if a derivation primitive rejects its input.
    pub fn derive(&self) -> Result<TenantKeys> {
        // WHY no salt: the data key is 32 uniformly random bytes, so HKDF's
        // extract step needs no salt to produce a uniform PRK (RFC 5869 3.1).
        let hk = hkdf_extract(None, self.expose());
        let sealing = |info| -> Result<SealingKey> {
            Ok(SealingKey {
                id: self.id,
                key: SubKey::derive(&hk, info)?,
            })
        };
        Ok(TenantKeys {
            key_id: self.id,
            blob: sealing(label::TENANT_BLOB)?,
            blob_addr: SubKey::derive(&hk, label::TENANT_BLOB_ADDR)?,
            meta: sealing(label::TENANT_META)?,
            audit: sealing(label::TENANT_AUDIT)?,
            index: SubKey::derive(&hk, label::TENANT_INDEX)?,
        })
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        self.bytes.expose_secret()
    }
}

impl ZeroizeOnDrop for TenantDataKey {}

impl std::fmt::Debug for TenantDataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantDataKey")
            .field("id", &self.id)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Subkeys derived from one tenant data key.
#[derive(Debug)]
pub struct TenantKeys {
    key_id: KeyId,
    blob: SealingKey,
    blob_addr: SubKey,
    meta: SealingKey,
    audit: SealingKey,
    index: SubKey,
}

impl TenantKeys {
    /// The data-key id these subkeys come from.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Sealing key for the tenant's blobs.
    #[must_use]
    pub const fn blob(&self) -> &SealingKey {
        &self.blob
    }

    /// Sealing key for the tenant's metadata records.
    #[must_use]
    pub const fn meta(&self) -> &SealingKey {
        &self.meta
    }

    /// Sealing key for the tenant's audit records.
    #[must_use]
    pub const fn audit(&self) -> &SealingKey {
        &self.audit
    }

    /// Subkey for keyed hashes of the tenant's index keys.
    #[must_use]
    pub const fn index(&self) -> &SubKey {
        &self.index
    }

    /// The tenant-scoped address of `plaintext`: HMAC-SHA256 under the
    /// tenant's blob-address key. Identical bytes held by two tenants get two
    /// unrelated addresses, so an address neither deduplicates across
    /// tenants nor lets one tenant test for another's content.
    ///
    /// # Errors
    ///
    /// [`crate::Error::KeyMaterial`] if the MAC rejects the key.
    pub fn blob_address(&self, plaintext: &[u8]) -> Result<BlobAddress> {
        hmac_sha256(self.blob_addr.expose(), &[plaintext]).map(BlobAddress)
    }
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
