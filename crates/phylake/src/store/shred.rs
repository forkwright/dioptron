//! Crypto-shredding (`docs/design/custody-store.md`, "Crypto-shredding").
//!
//! One transaction deletes every wrapped key of the tenant (the active data
//! key, a retiring one mid-rotation, and the addressing subkeys), deletes
//! its rekey record, and replaces its tenant record with a tombstone. The
//! tenant's plaintext data keys existed only wrapped, so every record
//! sealed under them is unrecoverable from then on. The tombstone keeps
//! the id reserved: the id cannot be registered again, and operations on
//! it fail with [`crate::Error::TenantShredded`] rather than as a missing
//! tenant. Global audit stubs carry no tenant and survive.
//!
//! The deletion is a tombstone in the database, so the wrapped key bytes
//! stay in its journal and table files until [`Store::compact`] rewrites
//! the store without them; the shred is complete only then.

use std::collections::HashSet;

use fjall::Readable;
use snafu::{OptionExt as _, ensure};
use syntheke::{SessionId, TenantId};

use super::codec::StoredRecord as _;
use super::record_key::store as keys;
use super::records::{InvocationRecord, SessionRecord, TombstoneRecord};
use super::view::View;
use super::{Store, slot};
use crate::Result;
use crate::crypto::{KeyId, Keyspace};
use crate::error::{TenantBusySnafu, TenantMissingSnafu};

impl Store {
    /// Crypto-shreds `tenant`. A second shred of the same tenant does
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TenantMissing`] for a tenant never registered,
    /// [`crate::Error::TenantBusy`] while an invocation of the tenant, or
    /// in a session it owns, is not terminal (recovery would need the
    /// tenant's keys to settle it), or a storage, decryption, or decoding
    /// failure.
    pub fn shred_tenant(&self, tenant: TenantId) -> Result<()> {
        let mut tx = self.write_tx();
        if self.tombstone(&tx, tenant)?.is_some() {
            return Ok(());
        }
        let record = self
            .tenant_record(&tx, tenant)?
            .context(TenantMissingSnafu { tenant })?;
        ensure!(
            !self.has_open_invocations(&tx, tenant)?,
            TenantBusySnafu { tenant }
        );
        let index = self.keys.index();
        let wrapped = self.ks.get(Keyspace::Keys)?;
        tx.remove(
            wrapped,
            keys::data_key(index, tenant, KeyId::new(record.data_key_id))?,
        );
        if let Some(rekey) = self.rekey_record(&tx, tenant)? {
            if !rekey.done {
                tx.remove(
                    wrapped,
                    keys::data_key(index, tenant, KeyId::new(rekey.from_key_id))?,
                );
            }
            tx.remove(self.ks.get(Keyspace::Rekey)?, keys::rekey(index, tenant)?);
        }
        tx.remove(wrapped, keys::address_keys(index, tenant)?);
        tx.remove(
            self.ks.get(Keyspace::Tenants)?,
            keys::tenant(index, tenant)?,
        );
        let tombstone = TombstoneRecord {
            tenant,
            shredded_at: self.now(),
        };
        self.put_global(
            &mut tx,
            slot::TOMBSTONE,
            &keys::tombstone(index, tenant)?,
            &tombstone,
        )?;
        self.commit(tx, None)?;
        self.evict_tenant_keys(tenant);
        Ok(())
    }

    /// Whether `session` exists and its owner was shredded.
    pub(crate) fn session_owner_shredded<R: Readable>(
        &self,
        reader: &R,
        session: Option<SessionId>,
    ) -> Result<bool> {
        let Some(session) = session else {
            return Ok(false);
        };
        let view = View {
            store: self,
            reader,
        };
        match view.session_record(session)? {
            Some(record) => Ok(self.tombstone(reader, record.owner)?.is_some()),
            None => Ok(false),
        }
    }

    /// Whether an invocation of `tenant`, or in a session it owns, is not
    /// terminal.
    ///
    /// PERF: scans every session and invocation record, as recovery does.
    fn has_open_invocations<R: Readable>(&self, reader: &R, tenant: TenantId) -> Result<bool> {
        let mut owned = HashSet::new();
        for (key, sealed) in self.entries(reader, Keyspace::Sessions)? {
            let plain = Self::open_bytes(&[self.keys.meta()], slot::SESSION, &key, &sealed)?;
            let session = SessionRecord::decode(&plain, Keyspace::Sessions.name())?;
            if session.owner == tenant {
                owned.insert(session.id);
            }
        }
        for (key, sealed) in self.entries(reader, Keyspace::Invocations)? {
            let plain = Self::open_bytes(&[self.keys.meta()], slot::INVOCATION, &key, &sealed)?;
            let record = InvocationRecord::decode(&plain, Keyspace::Invocations.name())?;
            let involved =
                record.tenant == tenant || record.session.is_some_and(|s| owned.contains(&s));
            if involved && !record.state.is_terminal() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
