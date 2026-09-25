//! Key hierarchy: store subkeys from the root key, tenant data keys, and
//! tenant subkeys.

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use snafu::ensure;
use zeroize::ZeroizeOnDrop;

use super::{
    BlobAddress, Entropy, KEY_LEN, KeyCheck, KeyId, OsEntropy, hkdf_expand, hkdf_extract,
    hmac_sha256, hmac_sha256_verify,
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

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
        }
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
        let mut salt = [0_u8; 32];
        entropy.fill(&mut salt)?;
        Ok(Self(salt))
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
        let mut bytes = SecretBox::new(Box::new([0_u8; KEY_LEN]));
        entropy.fill(bytes.expose_secret_mut())?;
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
pub(crate) mod tests {
    #![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

    use super::*;
    use crate::Error;
    use crate::crypto::test_support::FailingEntropy;

    pub(crate) const ROOT_BYTES: [u8; 32] = [0x11; 32];
    pub(crate) const ROOT_ID: KeyId = KeyId::new(1);

    pub(crate) fn store_keys() -> StoreKeys {
        let root = RootKey::from_bytes(ROOT_BYTES);
        StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([0x22; 32])).expect("derive")
    }

    pub(crate) fn tenant_key(id: u32, fill: u8) -> TenantDataKey {
        TenantDataKey::from_secret(KeyId::new(id), SecretBox::new(Box::new([fill; KEY_LEN])))
    }

    fn all_store_subkeys(keys: &StoreKeys) -> Vec<[u8; 32]> {
        vec![
            *keys.blob.key.expose(),
            *keys.meta.key.expose(),
            *keys.audit.key.expose(),
            *keys.index.expose(),
            *keys.kek.expose(),
            *keys.check.expose(),
        ]
    }

    #[test]
    fn store_subkeys_are_pairwise_distinct_and_differ_from_root() {
        let keys = store_keys();
        let subkeys = all_store_subkeys(&keys);
        let unique: std::collections::HashSet<_> = subkeys.iter().collect();
        assert_eq!(unique.len(), 6, "six distinct subkeys");
        assert!(
            !subkeys.contains(&ROOT_BYTES),
            "no subkey equals the root key"
        );
    }

    // WHY: expected values computed outside this crate with Python's
    // `hmac`/`hashlib` (HKDF per RFC 5869 over the documented labels), so
    // the test checks label, salt, and message wiring, not the code against
    // itself.
    const KAT_BLOB_SUBKEY: &str =
        "d3e5b2d5529c88ead9447f5944c9e16c4b14c22f32798af461127b57b98db2b0";
    const KAT_KEY_CHECK: &str = "d958239cb0a00284e9f9668ee7b517775c68440f96ea9fc6aa2fc6fc451c1c42";
    const KAT_BLOB_ADDRESS_ABC: &str =
        "8f363b9c1ee46a604a4666c77b8fec5704a82a63290fbcd2f3acab14a13aede2";

    #[test]
    fn store_blob_subkey_matches_known_answer() {
        let hex = crate::crypto::test_support::hex(store_keys().blob.key.expose());
        assert_eq!(
            hex, KAT_BLOB_SUBKEY,
            "HKDF(salt, root, \"dioptron/v1/blob\")"
        );
    }

    #[test]
    fn key_check_matches_known_answer() {
        let check = store_keys().key_check().expect("check");
        let hex = crate::crypto::test_support::hex(check.as_bytes());
        assert_eq!(hex, KAT_KEY_CHECK, "HMAC(k_check, \"dioptron-key-check\")");
    }

    #[test]
    fn blob_address_matches_known_answer() {
        let tenant = tenant_key(1, 0xa1).derive().expect("derive");
        let address = tenant.blob_address(b"abc").expect("address");
        let hex = crate::crypto::test_support::hex(address.as_bytes());
        assert_eq!(hex, KAT_BLOB_ADDRESS_ABC, "HMAC(k_blob_addr, \"abc\")");
    }

    #[test]
    fn derive_is_deterministic_and_salt_sensitive() {
        let root = RootKey::from_bytes(ROOT_BYTES);
        let a = StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([1; 32])).expect("a");
        let b = StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([1; 32])).expect("b");
        let c = StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([2; 32])).expect("c");
        assert_eq!(all_store_subkeys(&a), all_store_subkeys(&b), "same inputs");
        assert_ne!(
            all_store_subkeys(&a),
            all_store_subkeys(&c),
            "salt changes keys"
        );
    }

    #[test]
    fn unlock_accepts_matching_key_check() {
        let root = RootKey::from_bytes(ROOT_BYTES);
        let salt = StoreSalt::from_bytes([3; 32]);
        let check = StoreKeys::derive(&root, ROOT_ID, &salt)
            .and_then(|k| k.key_check())
            .expect("check");
        let keys = StoreKeys::unlock(&root, ROOT_ID, &salt, check.as_bytes()).expect("unlock");
        assert_eq!(keys.root_key_id(), ROOT_ID, "unlocked under the root id");
    }

    #[test]
    fn unlock_with_wrong_root_key_is_locked() {
        let salt = StoreSalt::from_bytes([3; 32]);
        let check = StoreKeys::derive(&RootKey::from_bytes(ROOT_BYTES), ROOT_ID, &salt)
            .and_then(|k| k.key_check())
            .expect("check");
        let wrong = RootKey::from_bytes([0x12; 32]);
        let err = StoreKeys::unlock(&wrong, ROOT_ID, &salt, check.as_bytes()).expect_err("locked");
        assert!(matches!(err, Error::StoreLocked { .. }), "got {err:?}");
        let shown = err.to_string();
        assert!(
            !shown.contains("18") && !shown.contains("0x12"),
            "no key bytes: {shown}"
        );
    }

    #[test]
    fn unlock_with_wrong_salt_or_short_check_is_locked() {
        let root = RootKey::from_bytes(ROOT_BYTES);
        let check = StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([3; 32]))
            .and_then(|k| k.key_check())
            .expect("check");
        let other_salt = StoreSalt::from_bytes([4; 32]);
        let err = StoreKeys::unlock(&root, ROOT_ID, &other_salt, check.as_bytes());
        assert!(
            matches!(err, Err(Error::StoreLocked { .. })),
            "salt mismatch"
        );
        let salt = StoreSalt::from_bytes([3; 32]);
        let short = check.as_bytes().get(..16).expect("prefix");
        let err = StoreKeys::unlock(&root, ROOT_ID, &salt, short);
        assert!(matches!(err, Err(Error::StoreLocked { .. })), "short check");
        let err = StoreKeys::unlock(&root, ROOT_ID, &salt, &[]);
        assert!(matches!(err, Err(Error::StoreLocked { .. })), "empty check");
    }

    #[test]
    fn tenant_subkeys_are_distinct_and_key_specific() {
        let a = tenant_key(7, 0xa1).derive().expect("a");
        let b = tenant_key(7, 0xb2).derive().expect("b");
        let a_keys = [
            *a.blob.key.expose(),
            *a.blob_addr.expose(),
            *a.meta.key.expose(),
            *a.audit.key.expose(),
            *a.index.expose(),
        ];
        let unique: std::collections::HashSet<_> = a_keys.iter().collect();
        assert_eq!(unique.len(), 5, "five distinct tenant subkeys");
        assert_ne!(a.blob.key.expose(), b.blob.key.expose(), "per-tenant");
        assert_eq!(a.key_id(), KeyId::new(7), "key id carried");
        assert_eq!(
            a.blob().id(),
            KeyId::new(7),
            "sealing key id is the data key id"
        );
    }

    #[test]
    fn blob_address_is_tenant_scoped_and_stable() {
        let a = tenant_key(1, 0xa1).derive().expect("a");
        let b = tenant_key(1, 0xb2).derive().expect("b");
        let body = b"<html>identical capture from https://example.com/</html>";
        let a1 = a.blob_address(body).expect("a1");
        let a2 = a.blob_address(body).expect("a2");
        let b1 = b.blob_address(body).expect("b1");
        assert_eq!(a1, a2, "stable within a tenant");
        assert_ne!(a1, b1, "differs across tenants");
        assert_ne!(
            a1.as_bytes(),
            crate::crypto::provenance_digest(body).as_bytes(),
            "address is not the plain digest"
        );
    }

    #[test]
    fn generate_draws_distinct_keys_and_surfaces_entropy_failure() {
        let a = TenantDataKey::generate(KeyId::new(1)).expect("a");
        let b = TenantDataKey::generate(KeyId::new(1)).expect("b");
        assert_ne!(a.expose(), b.expose(), "independent draws");
        let s1 = StoreSalt::generate().expect("salt");
        let s2 = StoreSalt::generate().expect("salt");
        assert_ne!(s1, s2, "independent salts");
        let err = TenantDataKey::generate_with(KeyId::new(1), &mut FailingEntropy);
        assert!(
            matches!(err, Err(Error::Entropy { .. })),
            "data key entropy"
        );
        let err = StoreSalt::generate_with(&mut FailingEntropy);
        assert!(matches!(err, Err(Error::Entropy { .. })), "salt entropy");
    }

    fn assert_no_key_bytes(shown: &str, key: &[u8; 32]) {
        let hex = crate::crypto::test_support::hex(key);
        let decimal = format!("{key:?}");
        let decimal_inner = decimal.trim_start_matches('[').trim_end_matches(']');
        assert!(!shown.contains(&hex), "hex key bytes leaked: {shown}");
        assert!(
            !shown.contains(decimal_inner),
            "decimal key bytes leaked: {shown}"
        );
    }

    #[test]
    fn debug_output_contains_no_key_bytes() {
        let store = store_keys();
        let shown = format!("{store:?}");
        assert!(shown.contains("[REDACTED]"), "redaction marker present");
        for key in all_store_subkeys(&store) {
            assert_no_key_bytes(&shown, &key);
        }
        assert_no_key_bytes(&shown, &ROOT_BYTES);

        let data = tenant_key(9, 0xc3);
        let shown = format!("{data:?}");
        assert_no_key_bytes(&shown, data.expose());
        assert!(!shown.contains("195"), "no decimal 0xc3 byte: {shown}");

        let tenant = data.derive().expect("derive");
        let shown = format!("{tenant:?}");
        for key in [
            tenant.blob.key.expose(),
            tenant.blob_addr.expose(),
            tenant.meta.key.expose(),
            tenant.audit.key.expose(),
            tenant.index.expose(),
        ] {
            assert_no_key_bytes(&shown, key);
        }
    }

    #[test]
    fn keyed_hash_is_key_specific() {
        let store = store_keys();
        let tenant = tenant_key(1, 0xa1).derive().expect("derive");
        let s = store.index().keyed_hash(b"tenant-id").expect("store index");
        let t = tenant
            .index()
            .keyed_hash(b"tenant-id")
            .expect("tenant index");
        assert_ne!(s, t, "different index keys give different tags");
    }
}
