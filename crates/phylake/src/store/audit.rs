//! Audit: a per-tenant sequenced entry plus a global stub, written in the
//! same transaction as the state they record.
//!
//! The sequence is global: the next value is one past the last key in
//! `audit_stub`, read inside the writing transaction, so writers (which
//! serialize on the database's single-writer lock) never reuse one. A
//! tenant's entries sit under a keyed prefix of that tenant followed by
//! the big-endian sequence, so they sort in sequence order.

use std::collections::HashMap;

use fjall::{Readable, Snapshot};
use snafu::{OptionExt as _, ResultExt as _};
use syntheke::{
    AuditRecord, AuditScope, AuditSeq, Capability, InvocationId, InvocationState, OutcomeKind,
    ReleaseReason, SessionId, TenantId,
};

use super::codec::StoredRecord as _;
use super::record_key::{self, HashedKey, SEQ_LEN};
use super::records::{AuditEntryRecord, AuditStubRecord, TenantRecord, Terminal};
use super::view::View;
use super::{Store, WriteTx, slot};
use crate::Result;
use crate::crypto::Keyspace;
use crate::error::{DatabaseSnafu, InconsistentSnafu};

/// One audit entry to append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuditEntry {
    tenant: TenantId,
    session: Option<SessionId>,
    invocation: InvocationId,
    capability: Capability,
    state: InvocationState,
    outcome: OutcomeKind,
    release_reason: Option<ReleaseReason>,
}

impl AuditEntry {
    /// An entry for a non-release state of `invocation` by `tenant`.
    pub(crate) const fn new(
        tenant: TenantId,
        invocation: InvocationId,
        capability: Capability,
        state: InvocationState,
        outcome: OutcomeKind,
    ) -> Self {
        Self {
            tenant,
            session: None,
            invocation,
            capability,
            state,
            outcome,
            release_reason: None,
        }
    }

    /// The entry recording `terminal`, with its release reason when it has
    /// one.
    pub(crate) const fn terminal(
        tenant: TenantId,
        invocation: InvocationId,
        capability: Capability,
        terminal: Terminal,
    ) -> Self {
        Self {
            release_reason: terminal.release_reason(),
            ..Self::new(
                tenant,
                invocation,
                capability,
                terminal.state(),
                terminal.outcome(),
            )
        }
    }

    /// The same entry, acting in `session`.
    pub(crate) const fn in_session(mut self, session: Option<SessionId>) -> Self {
        self.session = session;
        self
    }
}

/// An audit record as stored: the contract's record plus the release
/// reason, which the contract's record has no field for.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditEvent {
    /// The record the contract's `AuditQuery` returns.
    pub record: AuditRecord,
    /// Why the reservation was released; present exactly when
    /// `record.state` is `Released`.
    pub release_reason: Option<ReleaseReason>,
}

/// An audit read across tenants, as an `AuditQuery` needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditQuery {
    /// The reading tenant.
    pub actor: TenantId,
    /// The scope the lifecycle applied (contract § Read scopes, D17.7).
    pub scope: AuditScope,
    /// Narrows the scope to one session.
    pub session: Option<SessionId>,
    /// Only records after this sequence.
    pub after: Option<AuditSeq>,
    /// At most this many records.
    pub limit: u32,
}

impl AuditQuery {
    /// A query by `actor` under `scope`, from the start, unnarrowed.
    #[must_use]
    pub const fn new(actor: TenantId, scope: AuditScope, limit: u32) -> Self {
        Self {
            actor,
            scope,
            session: None,
            after: None,
            limit,
        }
    }
}

impl Store {
    /// Stages `entry` and its stub in `tx` and returns its sequence.
    pub(crate) fn append_audit(&self, tx: &mut WriteTx<'_>, entry: AuditEntry) -> Result<AuditSeq> {
        let seq = self.next_audit_seq(tx)?;
        let time = self.now();
        let seq_key = seq.get().to_be_bytes();
        self.put_global(
            tx,
            slot::AUDIT_STUB,
            &seq_key,
            &AuditStubRecord {
                seq,
                invocation: entry.invocation,
                capability: entry.capability,
                outcome: entry.outcome,
                time,
            },
        )?;
        let tenant_keys = self.tenant_keys(&*tx, entry.tenant)?;
        let prefix = record_key::tenant::audit(tenant_keys.index(), entry.tenant)?;
        let key = record_key::join(&prefix, &seq_key);
        self.put(
            tx,
            slot::AUDIT,
            &key,
            tenant_keys.audit(),
            &AuditEntryRecord {
                seq,
                time,
                tenant: entry.tenant,
                session: entry.session,
                invocation: entry.invocation,
                capability: entry.capability,
                state: entry.state,
                outcome: entry.outcome,
                release_reason: entry.release_reason,
            },
        )?;
        Ok(seq)
    }

    /// One past the last sequence in `audit_stub`; 1 for an empty log.
    fn next_audit_seq(&self, tx: &WriteTx<'_>) -> Result<AuditSeq> {
        let last = match tx.last_key_value(self.ks.get(Keyspace::AuditStub)?) {
            Some(guard) => {
                let key = guard.key().context(DatabaseSnafu)?;
                let bytes = <[u8; SEQ_LEN]>::try_from(&*key)
                    .ok()
                    .context(InconsistentSnafu {
                        what: "audit stub key is not a sequence",
                    })?;
                u64::from_be_bytes(bytes)
            }
            None => 0,
        };
        let next = last.checked_add(1).context(InconsistentSnafu {
            what: "audit sequence is exhausted",
        })?;
        Ok(AuditSeq::new(next))
    }

    /// `tenant`'s own audit records after `after`, at most `limit`, in
    /// sequence order: one partition, with no scope applied.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure; an unknown tenant is
    /// [`crate::Error::TenantMissing`].
    pub fn audit_records(
        &self,
        tenant: TenantId,
        after: Option<AuditSeq>,
        limit: u32,
    ) -> Result<Vec<AuditEvent>> {
        let snapshot = self.db.read_tx();
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        self.partition(&snapshot, tenant, after, limit, |_| Ok(true))
    }

    /// The audit records `query` selects, from every tenant's partition, in
    /// global sequence order.
    ///
    /// `All` selects every record. `OwnAndOwnedSessions` selects the
    /// actor's own records plus records any tenant wrote in a session the
    /// actor owns. `session` then narrows either scope to one session. The
    /// store applies the scope it is given; deciding which scope the
    /// actor's grant allows is the lifecycle's (epitrope's
    /// `applied_audit_scope`). A scope a later contract adds selects
    /// nothing until the store learns it.
    ///
    /// PERF: every partition is scanned from `after`, keeping at most
    /// `limit` matches each, then merged. Phase 01 volumes do not need an
    /// index by session.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure.
    pub fn audit_query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        let snapshot = self.db.read_tx();
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        let view = View {
            store: self,
            reader: &snapshot,
        };
        let mut owners: HashMap<SessionId, Option<TenantId>> = HashMap::new();
        let mut selected = |entry: &AuditEntryRecord| -> Result<bool> {
            if query.session.is_some() && entry.session != query.session {
                return Ok(false);
            }
            match query.scope {
                AuditScope::All => Ok(true),
                AuditScope::OwnAndOwnedSessions => {
                    if entry.tenant == query.actor {
                        return Ok(true);
                    }
                    let Some(session) = entry.session else {
                        return Ok(false);
                    };
                    let owner = if let Some(owner) = owners.get(&session) {
                        *owner
                    } else {
                        let owner = view.session_record(session)?.map(|record| record.owner);
                        owners.insert(session, owner);
                        owner
                    };
                    Ok(owner == Some(query.actor))
                }
                _ => Ok(false),
            }
        };
        let mut events = Vec::new();
        for tenant in self.tenant_ids(&snapshot)? {
            events.extend(self.partition(&snapshot, tenant, query.after, limit, &mut selected)?);
        }
        events.sort_by_key(|event| event.record.seq);
        events.truncate(limit);
        Ok(events)
    }

    /// Every registered tenant.
    ///
    /// NOTE: a crypto-shred must remove or tombstone the tenant record in
    /// the transaction that deletes its data key, or this scan fails on
    /// the shredded tenant's partition.
    fn tenant_ids(&self, snapshot: &Snapshot) -> Result<Vec<TenantId>> {
        let mut ids = Vec::new();
        for guard in snapshot.iter(self.ks.get(slot::TENANT.keyspace)?) {
            let (key, sealed) = guard.into_inner().context(DatabaseSnafu)?;
            let plain = Self::open_bytes(&[self.keys.meta()], slot::TENANT, &key, &sealed)?;
            ids.push(TenantRecord::decode(&plain, slot::TENANT.keyspace.name())?.id);
        }
        Ok(ids)
    }

    /// Up to `limit` records of `tenant`'s partition after `after` that
    /// `keep` selects, in sequence order.
    fn partition<R: Readable>(
        &self,
        reader: &R,
        tenant: TenantId,
        after: Option<AuditSeq>,
        limit: usize,
        mut keep: impl FnMut(&AuditEntryRecord) -> Result<bool>,
    ) -> Result<Vec<AuditEvent>> {
        let tenant_keys = self.tenant_keys(reader, tenant)?;
        let prefix: HashedKey = record_key::tenant::audit(tenant_keys.index(), tenant)?;
        let Some(start) = after.map_or(Some(0), |seq| seq.get().checked_add(1)) else {
            return Ok(Vec::new());
        };
        let from = record_key::join(&prefix, &start.to_be_bytes());
        let to = record_key::join(&prefix, &u64::MAX.to_be_bytes());
        let mut events = Vec::new();
        for guard in reader.range(self.ks.get(Keyspace::Audit)?, from..=to) {
            if events.len() >= limit {
                break;
            }
            let (key, sealed) = guard.into_inner().context(DatabaseSnafu)?;
            let plain = Self::open_bytes(&[tenant_keys.audit()], slot::AUDIT, &key, &sealed)?;
            let entry = AuditEntryRecord::decode(&plain, Keyspace::Audit.name())?;
            if keep(&entry)? {
                events.push(AuditEvent {
                    record: AuditRecord {
                        seq: entry.seq,
                        time: entry.time,
                        tenant: entry.tenant,
                        session: entry.session,
                        invocation: entry.invocation,
                        capability: entry.capability,
                        state: entry.state,
                        outcome: entry.outcome,
                    },
                    release_reason: entry.release_reason,
                });
            }
        }
        Ok(events)
    }
}
