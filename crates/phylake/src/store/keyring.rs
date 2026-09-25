//! A tenant's keyring: the sealing keys of its active data key, the
//! sealing keys of the data key being retired while a rotation runs, and
//! the addressing subkeys that stay fixed across rotations.
//!
//! Writers seal under the active key only. Readers open under either key
//! id while a rotation is in progress, so a read never fails mid-rotation
//! (`docs/design/custody-store.md`, "Rekey protocol").
//!
//! The keyring is read from the reader it is used with: the tenant record
//! names the active key id and the rekey record names the retiring one.
//! The cache is keyed by those ids, so a cached keyring is used only when
//! it matches what the reader sees. A writer therefore always seals under
//! the key its own transaction names as active, and never under a key a
//! concurrent rotation has replaced.

use std::sync::{Arc, PoisonError};

use fjall::Readable;
use snafu::{OptionExt as _, ResultExt as _, ensure};
use syntheke::TenantId;

use super::records::{RekeyRecord, TombstoneRecord};
use super::{INITIAL_DATA_KEY_ID, Store, record_key, slot};
use crate::Result;
use crate::crypto::{
    AddressKeys, BlobAddress, KeyId, Keyspace, SealingKey, SubKey, TenantDataKey, TenantSealingKeys,
};
use crate::error::{DatabaseSnafu, InconsistentSnafu, TenantMissingSnafu, TenantShreddedSnafu};

/// The keys a store operation on one tenant's records uses.
#[derive(Debug)]
pub(crate) struct TenantKeyring {
    active: TenantSealingKeys,
    retiring: Option<TenantSealingKeys>,
    address: AddressKeys,
}

impl TenantKeyring {
    /// The active data-key id: new and re-sealed records use it.
    pub(crate) const fn key_id(&self) -> KeyId {
        self.active.key_id()
    }

    /// The data-key id being retired, while a rotation runs.
    pub(crate) fn retiring_id(&self) -> Option<KeyId> {
        self.retiring.as_ref().map(TenantSealingKeys::key_id)
    }

    /// The active sealing keys.
    pub(crate) const fn active(&self) -> &TenantSealingKeys {
        &self.active
    }

    /// The sealing keys being retired, while a rotation runs.
    pub(crate) const fn retiring(&self) -> Option<&TenantSealingKeys> {
        self.retiring.as_ref()
    }

    /// Sealing key for new blobs.
    pub(crate) const fn blob(&self) -> &SealingKey {
        self.active.blob()
    }

    /// Sealing key for new metadata records.
    pub(crate) const fn meta(&self) -> &SealingKey {
        self.active.meta()
    }

    /// Sealing key for new audit records.
    pub(crate) const fn audit(&self) -> &SealingKey {
        self.active.audit()
    }

    /// Keys that open a blob: the active one and, mid-rotation, the
    /// retiring one.
    pub(crate) fn blob_openers(&self) -> [&SealingKey; 2] {
        self.openers(TenantSealingKeys::blob)
    }

    /// Keys that open a metadata record.
    pub(crate) fn meta_openers(&self) -> [&SealingKey; 2] {
        self.openers(TenantSealingKeys::meta)
    }

    /// Keys that open an audit record.
    pub(crate) fn audit_openers(&self) -> [&SealingKey; 2] {
        self.openers(TenantSealingKeys::audit)
    }

    /// The active key and the retiring one, or the active key twice when
    /// no rotation runs; `open` picks the key whose id the header names.
    fn openers<'a>(
        &'a self,
        pick: fn(&'a TenantSealingKeys) -> &'a SealingKey,
    ) -> [&'a SealingKey; 2] {
        let active = pick(&self.active);
        [active, self.retiring.as_ref().map_or(active, pick)]
    }

    /// Subkey for keyed hashes of the tenant's record keys.
    pub(crate) const fn index(&self) -> &SubKey {
        self.address.index()
    }

    /// The tenant-scoped address of `plaintext`.
    pub(crate) fn blob_address(&self, plaintext: &[u8]) -> Result<BlobAddress> {
        self.address.blob_address(plaintext)
    }

    /// The addressing subkeys, for wrapping at a tenant's first rotation.
    pub(crate) const fn address(&self) -> &AddressKeys {
        &self.address
    }
}

impl Store {
    /// The keyring of `tenant` as `reader` sees it, unwrapping its data
    /// keys on first use.
    ///
    /// NOTE: a cached keyring is reused only when its key ids match the
    /// tenant and rekey records read through `reader`; rotation and
    /// crypto-shredding also evict the entry once they commit, so retired
    /// key material does not stay cached.
    pub(crate) fn tenant_keys<R: Readable>(
        &self,
        reader: &R,
        tenant: TenantId,
    ) -> Result<Arc<TenantKeyring>> {
        let Some(record) = self.tenant_record(reader, tenant)? else {
            return Err(self.absent_tenant(reader, tenant));
        };
        let active = KeyId::new(record.data_key_id);
        let retiring = self
            .rekey_record(reader, tenant)?
            .filter(|rekey| !rekey.done)
            .map(|rekey| KeyId::new(rekey.from_key_id));
        let cached = self
            .tenant_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&tenant)
            .filter(|keys| keys.key_id() == active && keys.retiring_id() == retiring)
            .cloned();
        if let Some(keys) = cached {
            return Ok(keys);
        }
        let keyring = Arc::new(self.load_keyring(reader, tenant, active, retiring)?);
        self.tenant_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tenant, Arc::clone(&keyring));
        Ok(keyring)
    }

    /// Like [`Store::tenant_keys`], but `None` for a shredded tenant, for
    /// reads that answer "not found" rather than fail.
    pub(crate) fn live_tenant_keys<R: Readable>(
        &self,
        reader: &R,
        tenant: TenantId,
    ) -> Result<Option<Arc<TenantKeyring>>> {
        match self.tenant_keys(reader, tenant) {
            Ok(keys) => Ok(Some(keys)),
            Err(crate::Error::TenantShredded { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Drops the cached keyring of `tenant`, so its key material is wiped
    /// once no operation still holds it.
    pub(crate) fn evict_tenant_keys(&self, tenant: TenantId) {
        self.tenant_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&tenant);
    }

    fn load_keyring<R: Readable>(
        &self,
        reader: &R,
        tenant: TenantId,
        active: KeyId,
        retiring: Option<KeyId>,
    ) -> Result<TenantKeyring> {
        let (active_keys, derived_address) = self
            .data_key(reader, tenant, active)?
            .context(InconsistentSnafu {
                what: "tenant data key is missing",
            })?
            .derive()?
            .split();
        let address = if let Some(address) = self.stored_address_keys(reader, tenant)? {
            address
        } else {
            // INVARIANT: the first rotation stores the addressing subkeys
            // of data key 1 in the transaction that makes another key
            // active, so only key 1 derives them.
            ensure!(
                active == INITIAL_DATA_KEY_ID,
                InconsistentSnafu {
                    what: "rotated tenant has no addressing subkeys",
                }
            );
            derived_address
        };
        let retiring = retiring
            .map(|id| -> Result<TenantSealingKeys> {
                Ok(self
                    .data_key(reader, tenant, id)?
                    .context(InconsistentSnafu {
                        what: "retiring tenant data key is missing",
                    })?
                    .derive()?
                    .split()
                    .0)
            })
            .transpose()?;
        Ok(TenantKeyring {
            active: active_keys,
            retiring,
            address,
        })
    }

    /// The error for a tenant with no record: shredded or never registered.
    pub(crate) fn absent_tenant<R: Readable>(&self, reader: &R, tenant: TenantId) -> crate::Error {
        match self.tombstone(reader, tenant) {
            Ok(Some(_)) => TenantShreddedSnafu { tenant }.build(),
            Ok(None) => TenantMissingSnafu { tenant }.build(),
            Err(error) => error,
        }
    }

    /// The unwrapped data key `key_id` of `tenant`, or `None`.
    pub(crate) fn data_key<R: Readable>(
        &self,
        reader: &R,
        tenant: TenantId,
        key_id: KeyId,
    ) -> Result<Option<TenantDataKey>> {
        let slot_key = record_key::store::data_key(self.keys.index(), tenant, key_id)?;
        reader
            .get(self.ks.get(Keyspace::Keys)?, slot_key)
            .context(DatabaseSnafu)?
            .map(|wrapped| self.keys.unwrap_tenant_key(&tenant.to_bytes(), &wrapped))
            .transpose()
    }

    /// The stored addressing subkeys of `tenant`, or `None` before its
    /// first rotation.
    pub(crate) fn stored_address_keys<R: Readable>(
        &self,
        reader: &R,
        tenant: TenantId,
    ) -> Result<Option<AddressKeys>> {
        let slot_key = record_key::store::address_keys(self.keys.index(), tenant)?;
        reader
            .get(self.ks.get(Keyspace::Keys)?, slot_key)
            .context(DatabaseSnafu)?
            .map(|wrapped| self.keys.unwrap_address_keys(&tenant.to_bytes(), &wrapped))
            .transpose()
    }

    /// The rekey record of `tenant`.
    pub(crate) fn rekey_record<R: Readable>(
        &self,
        reader: &R,
        tenant: TenantId,
    ) -> Result<Option<RekeyRecord>> {
        let key = record_key::store::rekey(self.keys.index(), tenant)?;
        self.get_global(reader, slot::REKEY, &key)
    }

    /// The tombstone of `tenant`, when it was shredded.
    pub(crate) fn tombstone<R: Readable>(
        &self,
        reader: &R,
        tenant: TenantId,
    ) -> Result<Option<TombstoneRecord>> {
        let key = record_key::store::tombstone(self.keys.index(), tenant)?;
        self.get_global(reader, slot::TOMBSTONE, &key)
    }
}
