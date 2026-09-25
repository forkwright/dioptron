//! Tenant data-key rotation (`docs/design/custody-store.md`, "Rekey
//! protocol").
//!
//! A rotation runs in three kinds of transaction:
//!
//! 1. Begin: draws the new data key, wraps it, makes it the tenant's
//!    active key, and writes the rekey record. At a tenant's first
//!    rotation it also stores the addressing subkeys of data key 1,
//!    because record keys and blob addresses are computed under them and
//!    do not rotate.
//! 2. Batch: walks the tenant-sealed keyspaces in a fixed order, a bounded
//!    number of records per transaction, re-sealing each record of this
//!    tenant still sealed under the old key. The cursor (keyspace and last
//!    record key) advances in the same transaction as the re-sealed
//!    records, so a crash before or after the commit resumes from the last
//!    committed cursor and repeats no work that committed.
//! 3. Retire: once the walk has passed every keyspace, deletes the old
//!    wrapped key and marks the record done.
//!
//! No record is ever sealed under a retired key. From the begin commit on,
//! every writer's transaction reads the new key as active and seals under
//! it (the keyring is read through the writer's own transaction), so the
//! set of records under the old key only shrinks. Records are re-sealed
//! in place at the same record key, so the walk's order is stable and it
//! visits each old record once. Readers open under either key id until
//! the retire commit.
//!
//! The walk finds the tenant's records by header and trial: a record whose
//! header names the old key id is opened under the old key with each
//! record kind its keyspace holds; one that opens is this tenant's. Key
//! ids are per tenant, so another tenant's record can carry the same id;
//! it fails authentication and is left alone.
//!
//! PERF: the walk reads every record of the tenant-sealed keyspaces,
//! other tenants' included, and trial-opens those whose header names the
//! old key id. A per-tenant record index would bound it by the tenant's
//! own records; Phase 01 volumes do not need one.

use std::num::NonZeroUsize;
use std::ops::Bound;
use std::sync::PoisonError;

use fjall::Readable;
use snafu::{OptionExt as _, ResultExt as _, ensure};
use syntheke::TenantId;

use super::codec::StoredRecord as _;
use super::keyring::TenantKeyring;
use super::record_key::store as keys;
use super::records::RekeyRecord;
use super::{Boundary, Slot, Store, WriteTx, slot};
use crate::crypto::{KeyId, Keyspace, SealingKey, TenantDataKey, TenantSealingKeys, sealed_key_id};
use crate::error::{
    DatabaseSnafu, InconsistentSnafu, RekeyInProgressSnafu, RekeyNotInProgressSnafu,
};
use crate::{Error, Result};

/// One keyspace of the walk: the tenant-sealed record kinds it holds and
/// the sealing key each kind uses.
struct WalkStep {
    keyspace: Keyspace,
    slots: &'static [Slot],
    sealer: fn(&TenantSealingKeys) -> &SealingKey,
}

/// The walk, in order. Every tenant-sealed record lives in one of these.
const WALK: [WalkStep; 5] = [
    WalkStep {
        keyspace: Keyspace::Idem,
        slots: &[slot::IDEM],
        sealer: TenantSealingKeys::meta,
    },
    WalkStep {
        keyspace: Keyspace::Artifacts,
        slots: &[slot::ARTIFACT, slot::PENDING_ARTIFACT],
        sealer: TenantSealingKeys::meta,
    },
    WalkStep {
        keyspace: Keyspace::Blobs,
        slots: &[slot::BLOB],
        sealer: TenantSealingKeys::blob,
    },
    WalkStep {
        keyspace: Keyspace::SessionIndex,
        slots: &[slot::SESSION_INDEX],
        sealer: TenantSealingKeys::meta,
    },
    WalkStep {
        keyspace: Keyspace::Audit,
        slots: &[slot::AUDIT],
        sealer: TenantSealingKeys::audit,
    },
];

/// Progress of a tenant data-key rotation, read from its rekey record.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RekeyStatus {
    /// The tenant.
    pub tenant: TenantId,
    /// The data key being retired.
    pub from_key_id: KeyId,
    /// The data key new and re-sealed records use.
    pub to_key_id: KeyId,
    /// The keyspace the walk is in; `None` once it has passed every
    /// keyspace.
    pub keyspace: Option<Keyspace>,
    /// Records examined so far.
    pub visited: u64,
    /// Records re-sealed under the new key so far.
    pub resealed: u64,
    /// Records in the walked keyspaces when the rotation began, every
    /// tenant's included. Records written during the rotation can make
    /// `visited` exceed it.
    pub total: u64,
    /// Whether the old key is retired.
    pub done: bool,
}

impl From<&RekeyRecord> for RekeyStatus {
    fn from(record: &RekeyRecord) -> Self {
        Self {
            tenant: record.tenant,
            from_key_id: KeyId::new(record.from_key_id),
            to_key_id: KeyId::new(record.to_key_id),
            keyspace: WALK
                .get(usize::from(record.keyspace))
                .map(|step| step.keyspace),
            visited: record.visited,
            resealed: record.resealed,
            total: record.total,
            done: record.done,
        }
    }
}

impl Store {
    /// Rotates `tenant`'s data key to completion, `batch` records per
    /// transaction. A rotation already in progress (for example one a
    /// crash interrupted) is resumed from its cursor, not restarted.
    ///
    /// # Errors
    ///
    /// As [`Store::begin_rekey`] and [`Store::rekey_batch`].
    pub fn rekey_tenant(&self, tenant: TenantId, batch: NonZeroUsize) -> Result<RekeyStatus> {
        let mut status = match self.rekey_status(tenant)? {
            Some(status) if !status.done => status,
            _ => self.begin_rekey(tenant)?,
        };
        while !status.done {
            status = self.rekey_batch(tenant, batch)?;
        }
        Ok(status)
    }

    /// Begins rotating `tenant`'s data key: one transaction that stores
    /// the new wrapped key, makes it active, and writes the rekey record.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TenantMissing`] or [`crate::Error::TenantShredded`]
    /// for a tenant with no record, [`crate::Error::RekeyInProgress`] when
    /// a rotation has not finished, [`crate::Error::Entropy`] when the key
    /// cannot be drawn, [`crate::Error::InjectedCrash`], or a storage
    /// failure.
    pub fn begin_rekey(&self, tenant: TenantId) -> Result<RekeyStatus> {
        let mut tx = self.write_tx();
        let Some(mut record) = self.tenant_record(&tx, tenant)? else {
            return Err(self.absent_tenant(&tx, tenant));
        };
        if let Some(existing) = self.rekey_record(&tx, tenant)? {
            ensure!(existing.done, RekeyInProgressSnafu { tenant });
        }
        let current = self.tenant_keys(&tx, tenant)?;
        let from = current.key_id();
        let to = from
            .get()
            .checked_add(1)
            .map(KeyId::new)
            .context(InconsistentSnafu {
                what: "tenant data key ids are exhausted",
            })?;
        self.stage_new_key(&mut tx, tenant, to, &current)?;
        record.data_key_id = to.get();
        self.put_global(
            &mut tx,
            slot::TENANT,
            &keys::tenant(self.keys.index(), tenant)?,
            &record,
        )?;
        let rekey = RekeyRecord {
            tenant,
            from_key_id: from.get(),
            to_key_id: to.get(),
            keyspace: 0,
            cursor: None,
            visited: 0,
            resealed: 0,
            total: self.walk_total(&tx)?,
            done: false,
            started_at: self.now(),
            finished_at: None,
        };
        self.put_rekey(&mut tx, &rekey)?;
        self.commit(tx, Some(Boundary::RekeyBegin))?;
        self.evict_tenant_keys(tenant);
        Ok(RekeyStatus::from(&rekey))
    }

    /// Stages the wrapped data key `to` and, at the tenant's first
    /// rotation, its wrapped addressing subkeys.
    fn stage_new_key(
        &self,
        tx: &mut WriteTx<'_>,
        tenant: TenantId,
        to: KeyId,
        current: &TenantKeyring,
    ) -> Result<()> {
        let first_rotation = self.stored_address_keys(&*tx, tenant)?.is_none();
        let (wrapped_key, wrapped_address) = {
            let mut entropy = self.entropy.lock().unwrap_or_else(PoisonError::into_inner);
            let data_key = TenantDataKey::generate_with(to, &mut *entropy)?;
            let wrapped_key =
                self.keys
                    .wrap_tenant_key_with(&tenant.to_bytes(), &data_key, &mut *entropy)?;
            let wrapped_address = if first_rotation {
                Some(self.keys.wrap_address_keys_with(
                    &tenant.to_bytes(),
                    current.address(),
                    &mut *entropy,
                )?)
            } else {
                None
            };
            (wrapped_key, wrapped_address)
        };
        let handle = self.ks.get(Keyspace::Keys)?;
        tx.insert(
            handle,
            keys::data_key(self.keys.index(), tenant, to)?,
            wrapped_key,
        );
        if let Some(wrapped) = wrapped_address {
            tx.insert(
                handle,
                keys::address_keys(self.keys.index(), tenant)?,
                wrapped,
            );
        }
        Ok(())
    }

    /// Runs one step of `tenant`'s rotation: a batch of at most `batch`
    /// records, or, once the walk has passed every keyspace, the retire
    /// transaction. Each is one transaction.
    ///
    /// # Errors
    ///
    /// [`crate::Error::RekeyNotInProgress`] when no rotation runs,
    /// [`crate::Error::InjectedCrash`], or a storage, decryption, or
    /// decoding failure.
    pub fn rekey_batch(&self, tenant: TenantId, batch: NonZeroUsize) -> Result<RekeyStatus> {
        let mut tx = self.write_tx();
        let mut record = self
            .rekey_record(&tx, tenant)?
            .filter(|record| !record.done)
            .context(RekeyNotInProgressSnafu { tenant })?;
        let Some(step) = WALK.get(usize::from(record.keyspace)) else {
            return self.retire(tx, record);
        };
        let keys = self.tenant_keys(&tx, tenant)?;
        let retiring = keys.retiring().context(InconsistentSnafu {
            what: "rotation in progress without a retiring key",
        })?;
        let entries = walk_entries(
            &tx,
            self.ks.get(step.keyspace)?,
            record.cursor.as_deref(),
            batch,
        )?;
        for (key, sealed) in &entries {
            if let Some(fresh) = self.reseal(step, retiring, keys.active(), key, sealed)? {
                tx.insert(self.ks.get(step.keyspace)?, key.as_slice(), fresh);
                record.resealed = record.resealed.saturating_add(1);
            }
        }
        let seen = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        record.visited = record.visited.saturating_add(seen);
        if entries.len() < batch.get() {
            record.keyspace = record.keyspace.saturating_add(1);
            record.cursor = None;
        } else {
            record.cursor = entries.last().map(|(key, _)| key.clone());
        }
        self.put_rekey(&mut tx, &record)?;
        self.commit(tx, Some(Boundary::RekeyBatch))?;
        Ok(RekeyStatus::from(&record))
    }

    /// The value re-sealed under `active` when `sealed` is one of this
    /// tenant's records under `retiring`; `None` for any other record.
    fn reseal(
        &self,
        step: &WalkStep,
        retiring: &TenantSealingKeys,
        active: &TenantSealingKeys,
        key: &[u8],
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if sealed_key_id(sealed) != Some(retiring.key_id()) {
            return Ok(None);
        }
        for &slot in step.slots {
            match Self::open_bytes(&[(step.sealer)(retiring)], slot, key, sealed) {
                Ok(plain) => {
                    return self
                        .seal_bytes((step.sealer)(active), slot, key, &plain)
                        .map(Some);
                }
                // WHY: another tenant's record, or another kind in a shared
                // keyspace, fails authentication under this key.
                Err(Error::Open { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// The retire transaction: deletes the old wrapped key and marks the
    /// rotation done.
    fn retire(&self, mut tx: WriteTx<'_>, mut record: RekeyRecord) -> Result<RekeyStatus> {
        let tenant = record.tenant;
        let from = KeyId::new(record.from_key_id);
        tx.remove(
            self.ks.get(Keyspace::Keys)?,
            keys::data_key(self.keys.index(), tenant, from)?,
        );
        record.done = true;
        record.cursor = None;
        record.finished_at = Some(self.now());
        self.put_rekey(&mut tx, &record)?;
        self.commit(tx, Some(Boundary::RekeyRetire))?;
        self.evict_tenant_keys(tenant);
        Ok(RekeyStatus::from(&record))
    }

    /// The progress of `tenant`'s current or last rotation, or `None` when
    /// its data key never rotated.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure.
    pub fn rekey_status(&self, tenant: TenantId) -> Result<Option<RekeyStatus>> {
        let snapshot = self.db.read_tx();
        Ok(self
            .rekey_record(&snapshot, tenant)?
            .as_ref()
            .map(RekeyStatus::from))
    }

    /// Every rotation that has not finished, for resuming after a restart.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure.
    pub fn rekeys_in_progress(&self) -> Result<Vec<RekeyStatus>> {
        let snapshot = self.db.read_tx();
        let mut open = Vec::new();
        for guard in snapshot.iter(self.ks.get(Keyspace::Rekey)?) {
            let (key, sealed) = guard.into_inner().context(DatabaseSnafu)?;
            let plain = Self::open_bytes(&[self.keys.meta()], slot::REKEY, &key, &sealed)?;
            let record = RekeyRecord::decode(&plain, Keyspace::Rekey.name())?;
            if !record.done {
                open.push(RekeyStatus::from(&record));
            }
        }
        Ok(open)
    }

    /// Stages `record` at its tenant's rekey key.
    pub(crate) fn put_rekey(&self, tx: &mut WriteTx<'_>, record: &RekeyRecord) -> Result<()> {
        let key = keys::rekey(self.keys.index(), record.tenant)?;
        self.put_global(tx, slot::REKEY, &key, record)
    }

    /// Records in the walked keyspaces.
    fn walk_total<R: Readable>(&self, reader: &R) -> Result<u64> {
        let mut total: u64 = 0;
        for step in &WALK {
            let count = reader.iter(self.ks.get(step.keyspace)?).count();
            total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        }
        Ok(total)
    }
}

/// At most `batch` entries of `keyspace` after `cursor`.
fn walk_entries<R: Readable>(
    reader: &R,
    keyspace: &fjall::SingleWriterTxKeyspace,
    cursor: Option<&[u8]>,
    batch: NonZeroUsize,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let start = cursor.map_or(Bound::Unbounded, |key| Bound::Excluded(key.to_vec()));
    reader
        .range(keyspace, (start, Bound::Unbounded))
        .take(batch.get())
        .map(|guard| {
            let (key, value) = guard.into_inner().context(DatabaseSnafu)?;
            Ok((key.to_vec(), value.to_vec()))
        })
        .collect()
}
