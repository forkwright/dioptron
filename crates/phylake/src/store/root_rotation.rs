//! Root key rotation (`docs/design/custody-store.md`, "Rekey protocol").
//!
//! One transaction moves the whole store-sealed scope to keys derived from
//! the new root key and a fresh salt: every tenant data key and every
//! tenant's addressing subkeys are rewrapped under the new key-encryption
//! subkey, every store-sealed record is re-sealed under the new metadata
//! subkey, and every record keyed under the store index subkey moves to
//! its key under the new index subkey. The new root key id, salt, and key
//! check are written to `meta` in the same transaction, so a crash leaves
//! either the old root key or the new one able to open the store, never
//! neither. Tenant-sealed records do not change: their keys are tenant
//! keys and their record keys hash under the tenant's addressing subkey.
//!
//! WHY one transaction and not the batch cursor: the store-sealed scope
//! holds identifiers and amounts, not acquired content, and at Phase 01
//! volumes it fits one in-memory write transaction. A batched rotation
//! would need readers that try two root keys and two index subkeys at
//! once; that lands if the store-sealed scope outgrows one transaction.
//!
//! The old root key's derived subkeys are wiped when the store drops them
//! after the commit. Values the old root key sealed or wrapped can stay in
//! the database's journal and table files until [`Store::compact`]
//! rewrites them away; until then the old root key file still opens them
//! and must stay in custody or be destroyed.

use std::collections::{HashMap, HashSet};
use std::sync::PoisonError;

use fjall::Readable;
use snafu::{OptionExt as _, ResultExt as _, ensure};
use syntheke::TenantId;

use super::codec::StoredRecord;
use super::meta::{self, Meta};
use super::record_key::store as keys;
use super::records::{
    AuditStubRecord, GrantRecord, InvocationRecord, LedgerRef, LocatorRecord, RekeyRecord,
    RevocationRecord, SessionRecord, TenantRecord, TombstoneRecord,
};
use super::{Boundary, Keyspaces, Slot, Store, WriteTx, slot};
use crate::crypto::{KeyId, Keyspace, StoreKeys, StoreSalt, SubKey};
use crate::error::{DatabaseSnafu, InconsistentSnafu};
use crate::keyfile::RootKey;
use crate::{Error, Result};

/// A raw keyspace entry.
type Entry = (Vec<u8>, Vec<u8>);

/// The staged changes: old record keys to remove, then new entries.
#[derive(Default)]
struct Moves {
    removes: Vec<(Keyspace, Vec<u8>)>,
    inserts: Vec<(Keyspace, Vec<u8>, Vec<u8>)>,
}

impl Moves {
    fn push(&mut self, keyspace: Keyspace, old: Vec<u8>, new: Vec<u8>, value: Vec<u8>) {
        self.removes.push((keyspace, old));
        self.inserts.push((keyspace, new, value));
    }

    /// Stages every removal, then every insertion, so a new key equal to
    /// an old one is kept.
    fn apply(self, tx: &mut WriteTx<'_>, ks: &Keyspaces) -> Result<()> {
        for (keyspace, key) in self.removes {
            tx.remove(ks.get(keyspace)?, key);
        }
        for (keyspace, key, value) in self.inserts {
            tx.insert(ks.get(keyspace)?, key, value);
        }
        Ok(())
    }
}

/// Identifiers the moved records name, for the records keyed by them.
#[derive(Default)]
struct Owners {
    tenants: Vec<TenantRecord>,
    shredded: Vec<TenantId>,
    rekeys: Vec<RekeyRecord>,
    ledgers: HashSet<LedgerRef>,
}

impl Store {
    /// Rotates the root key from `current` to `next` in one transaction
    /// and returns the new root key id. Afterwards the store opens with
    /// `next` only; `current` gets [`crate::Error::StoreLocked`].
    ///
    /// WARNING: an injected crash after the commit returns before this
    /// handle switches to the new keys; the handle must be dropped, as the
    /// failpoint contract requires, and the store reopened with `next`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::StoreLocked`] when `current` is not the store's root
    /// key, [`crate::Error::Entropy`] when the salt or a nonce cannot be
    /// drawn, [`crate::Error::Inconsistent`] when a store-sealed record or
    /// a wrapped key has no owner to rekey it under,
    /// [`crate::Error::InjectedCrash`], or a storage, decryption, or
    /// decoding failure. On any error before the commit nothing changes.
    pub fn rotate_root(&mut self, current: &RootKey, next: &RootKey) -> Result<KeyId> {
        let next_keys = {
            let mut tx = self.write_tx();
            let stored = meta::read(&tx, self.ks.get(Keyspace::Meta)?, &self.path)?;
            StoreKeys::unlock(current, stored.root_key_id(), stored.salt(), stored.check())?;
            let next_id = stored
                .root_key_id()
                .get()
                .checked_add(1)
                .map(KeyId::new)
                .context(InconsistentSnafu {
                    what: "root key ids are exhausted",
                })?;
            let salt = {
                let mut entropy = self.entropy.lock().unwrap_or_else(PoisonError::into_inner);
                StoreSalt::generate_with(&mut *entropy)?
            };
            let next_keys = StoreKeys::derive(next, next_id, &salt)?;
            let check = next_keys.key_check()?;
            let mut moves = Moves::default();
            self.stage_root_moves(&tx, &next_keys, &mut moves)?;
            moves.apply(&mut tx, &self.ks)?;
            meta::write(
                &mut tx,
                self.ks.get(Keyspace::Meta)?,
                &Meta::new(next_id, salt, *check.as_bytes()),
            );
            self.commit(tx, Some(Boundary::RootRotation))?;
            next_keys
        };
        let next_id = next_keys.root_key_id();
        self.keys = next_keys;
        Ok(next_id)
    }

    /// Stages the move of every store-keyed record and wrapped key.
    fn stage_root_moves(
        &self,
        tx: &WriteTx<'_>,
        next: &StoreKeys,
        moves: &mut Moves,
    ) -> Result<()> {
        let mut owners = Owners::default();
        self.move_tenants(tx, next, moves, &mut owners)?;
        for grant in self.move_all(tx, next, slot::GRANT, moves, |r: &GrantRecord, i| {
            keys::grant(i, r.id)
        })? {
            owners.ledgers.insert(LedgerRef::Grant(grant.id));
        }
        self.move_all(
            tx,
            next,
            slot::REVOCATION,
            moves,
            |r: &RevocationRecord, i| keys::revocation(i, r.grant),
        )?;
        for session in self.move_all(tx, next, slot::SESSION, moves, |r: &SessionRecord, i| {
            keys::session(i, r.id)
        })? {
            owners.ledgers.insert(LedgerRef::Session(session.id));
        }
        self.move_all(
            tx,
            next,
            slot::INVOCATION,
            moves,
            |r: &InvocationRecord, i| keys::invocation(i, r.id),
        )?;
        self.move_all(
            tx,
            next,
            slot::AUDIT_STUB,
            moves,
            |r: &AuditStubRecord, _| Ok(r.seq.get().to_be_bytes()),
        )?;
        owners.rekeys = self.move_all(tx, next, slot::REKEY, moves, |r: &RekeyRecord, i| {
            keys::rekey(i, r.tenant)
        })?;
        self.move_locators(tx, next, moves)?;
        self.move_ledgers(tx, next, moves, &owners.ledgers)?;
        self.move_wrapped_keys(tx, next, moves, &owners)
    }

    /// Moves tenant records and tombstones, which share `tenants`.
    fn move_tenants(
        &self,
        tx: &WriteTx<'_>,
        next: &StoreKeys,
        moves: &mut Moves,
        owners: &mut Owners,
    ) -> Result<()> {
        for (key, sealed) in self.entries(tx, Keyspace::Tenants)? {
            if let Some(plain) = self.try_open(slot::TENANT, &key, &sealed)? {
                let record = TenantRecord::decode(&plain, Keyspace::Tenants.name())?;
                let new = keys::tenant(next.index(), record.id)?;
                self.stage_move(moves, next, slot::TENANT, (key, new.to_vec()), &plain)?;
                owners.ledgers.insert(LedgerRef::Tenant(record.id));
                owners.tenants.push(record);
            } else {
                let plain =
                    self.try_open(slot::TOMBSTONE, &key, &sealed)?
                        .context(InconsistentSnafu {
                            what: "a tenants record opens as no known kind",
                        })?;
                let record = TombstoneRecord::decode(&plain, Keyspace::Tenants.name())?;
                let new = keys::tombstone(next.index(), record.tenant)?;
                self.stage_move(moves, next, slot::TOMBSTONE, (key, new.to_vec()), &plain)?;
                owners.ledgers.insert(LedgerRef::Tenant(record.tenant));
                owners.shredded.push(record.tenant);
            }
        }
        Ok(())
    }

    /// Moves every record of `slot`, whose keyspace holds only that kind,
    /// to the key `new_key` computes under the new index subkey, and
    /// returns the records.
    fn move_all<T, K, F>(
        &self,
        tx: &WriteTx<'_>,
        next: &StoreKeys,
        slot: Slot,
        moves: &mut Moves,
        new_key: F,
    ) -> Result<Vec<T>>
    where
        T: StoredRecord,
        K: AsRef<[u8]>,
        F: Fn(&T, &SubKey) -> Result<K>,
    {
        let mut records = Vec::new();
        for (key, sealed) in self.entries(tx, slot.keyspace)? {
            let plain = self
                .try_open(slot, &key, &sealed)?
                .context(InconsistentSnafu {
                    what: "a store-sealed record does not open under the root key",
                })?;
            let record = T::decode(&plain, slot.keyspace.name())?;
            let new = new_key(&record, next.index())?.as_ref().to_vec();
            self.stage_move(moves, next, slot, (key, new), &plain)?;
            records.push(record);
        }
        Ok(records)
    }

    /// Moves artifact locators. The other records in `artifacts` are
    /// tenant-sealed: they do not open under the store key and stay put.
    fn move_locators(&self, tx: &WriteTx<'_>, next: &StoreKeys, moves: &mut Moves) -> Result<()> {
        for (key, sealed) in self.entries(tx, Keyspace::Artifacts)? {
            if let Some(plain) = self.try_open(slot::LOCATOR, &key, &sealed)? {
                let record = LocatorRecord::decode(&plain, Keyspace::Artifacts.name())?;
                let new = keys::locator(next.index(), record.artifact)?;
                self.stage_move(moves, next, slot::LOCATOR, (key, new.to_vec()), &plain)?;
            }
        }
        Ok(())
    }

    /// Moves ledgers. A ledger record does not name its owner, so each is
    /// found from the grants, sessions, and tenants that can own one; a
    /// ledger none of them owns fails the rotation rather than be lost.
    fn move_ledgers(
        &self,
        tx: &WriteTx<'_>,
        next: &StoreKeys,
        moves: &mut Moves,
        owners: &HashSet<LedgerRef>,
    ) -> Result<()> {
        let mut ledgers: HashMap<Vec<u8>, Vec<u8>> =
            self.entries(tx, Keyspace::Ledgers)?.into_iter().collect();
        for &ledger in owners {
            let old = keys::ledger(self.keys.index(), ledger)?;
            let Some(sealed) = ledgers.remove(&old[..]) else {
                continue;
            };
            let plain = self
                .try_open(slot::LEDGER, &old, &sealed)?
                .context(InconsistentSnafu {
                    what: "a ledger does not open under the root key",
                })?;
            let new = keys::ledger(next.index(), ledger)?;
            self.stage_move(
                moves,
                next,
                slot::LEDGER,
                (old.to_vec(), new.to_vec()),
                &plain,
            )?;
        }
        ensure!(
            ledgers.is_empty(),
            InconsistentSnafu {
                what: "a ledger has no grant, session, or tenant",
            }
        );
        Ok(())
    }

    /// Rewraps every tenant data key (the active one and, mid-rotation,
    /// the retiring one) and every tenant's addressing subkeys. A wrapped
    /// key no live tenant names fails the rotation.
    fn move_wrapped_keys(
        &self,
        tx: &WriteTx<'_>,
        next: &StoreKeys,
        moves: &mut Moves,
        owners: &Owners,
    ) -> Result<()> {
        let mut wrapped: HashMap<Vec<u8>, Vec<u8>> =
            self.entries(tx, Keyspace::Keys)?.into_iter().collect();
        for tenant in &owners.tenants {
            let id = tenant.id;
            let retiring = owners
                .rekeys
                .iter()
                .filter(|rekey| rekey.tenant == id && !rekey.done)
                .map(|rekey| KeyId::new(rekey.from_key_id));
            for key_id in std::iter::once(KeyId::new(tenant.data_key_id)).chain(retiring) {
                let old = keys::data_key(self.keys.index(), id, key_id)?;
                let sealed = wrapped.remove(&old[..]).context(InconsistentSnafu {
                    what: "tenant data key is missing",
                })?;
                let data_key = self.keys.unwrap_tenant_key(&id.to_bytes(), &sealed)?;
                let rewrapped = {
                    let mut entropy = self.entropy.lock().unwrap_or_else(PoisonError::into_inner);
                    next.wrap_tenant_key_with(&id.to_bytes(), &data_key, &mut *entropy)?
                };
                let new = keys::data_key(next.index(), id, key_id)?;
                moves.push(Keyspace::Keys, old.to_vec(), new.to_vec(), rewrapped);
            }
            let old = keys::address_keys(self.keys.index(), id)?;
            if let Some(sealed) = wrapped.remove(&old[..]) {
                let address = self.keys.unwrap_address_keys(&id.to_bytes(), &sealed)?;
                let rewrapped = {
                    let mut entropy = self.entropy.lock().unwrap_or_else(PoisonError::into_inner);
                    next.wrap_address_keys_with(&id.to_bytes(), &address, &mut *entropy)?
                };
                let new = keys::address_keys(next.index(), id)?;
                moves.push(Keyspace::Keys, old.to_vec(), new.to_vec(), rewrapped);
            }
        }
        ensure!(
            wrapped.is_empty(),
            InconsistentSnafu {
                what: "a wrapped key names no live tenant",
            }
        );
        Ok(())
    }

    /// Re-seals `plain` under the new store key at `new` and stages the
    /// move from `old`.
    fn stage_move(
        &self,
        moves: &mut Moves,
        next: &StoreKeys,
        slot: Slot,
        (old, new): (Vec<u8>, Vec<u8>),
        plain: &[u8],
    ) -> Result<()> {
        let sealed = self.seal_bytes(next.meta(), slot, &new, plain)?;
        moves.push(slot.keyspace, old, new, sealed);
        Ok(())
    }

    /// Opens `sealed` as `slot` under the current store key; `None` when
    /// it does not authenticate as that kind.
    fn try_open(
        &self,
        slot: Slot,
        key: &[u8],
        sealed: &[u8],
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
        match Self::open_bytes(&[self.keys.meta()], slot, key, sealed) {
            Ok(plain) => Ok(Some(plain)),
            Err(Error::Open { .. } | Error::UnknownKeyId { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Every entry of `keyspace` as `reader` sees it.
    pub(crate) fn entries<R: Readable>(
        &self,
        reader: &R,
        keyspace: Keyspace,
    ) -> Result<Vec<Entry>> {
        reader
            .iter(self.ks.get(keyspace)?)
            .map(|guard| {
                let (key, value) = guard.into_inner().context(DatabaseSnafu)?;
                Ok((key.to_vec(), value.to_vec()))
            })
            .collect()
    }
}
