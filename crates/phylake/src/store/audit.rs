//! Audit: a per-tenant sequenced entry plus a global stub, written in the
//! same transaction as the state they record.
//!
//! The sequence is global: the next value is one past the last key in
//! `audit_stub`, read inside the writing transaction, so writers (which
//! serialize on the database's single-writer lock) never reuse one. A
//! tenant's entries sit under a keyed prefix of that tenant followed by
//! the big-endian sequence, so they sort in sequence order.

use fjall::Readable as _;
use snafu::{OptionExt as _, ResultExt as _};
use syntheke::{
    AuditRecord, AuditSeq, Capability, InvocationId, InvocationState, OutcomeKind, SessionId,
    TenantId,
};

use super::record_key::{self, HashedKey, SEQ_LEN};
use super::records::{AuditEntryRecord, AuditStubRecord};
use super::{Store, WriteTx, slot};
use crate::Result;
use crate::crypto::Keyspace;
use crate::error::{DatabaseSnafu, InconsistentSnafu};

/// One audit entry to append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditEntry {
    /// The acting tenant.
    pub tenant: TenantId,
    /// The session the call acted in, if any.
    pub session: Option<SessionId>,
    /// The invocation.
    pub invocation: InvocationId,
    /// The capability invoked.
    pub capability: Capability,
    /// The state committed with this entry.
    pub state: InvocationState,
    /// The outcome kind at that state.
    pub outcome: OutcomeKind,
}

impl AuditEntry {
    /// An entry for `invocation` by `tenant`.
    #[must_use]
    pub const fn new(
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
        }
    }

    /// The same entry, acting in `session`.
    #[must_use]
    pub const fn in_session(mut self, session: Option<SessionId>) -> Self {
        self.session = session;
        self
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
    /// sequence order.
    ///
    /// NOTE: this reads the acting tenant's partition only. The contract's
    /// `OwnAndOwnedSessions` and `All` scopes, which add records other
    /// tenants wrote in sessions this tenant owns, land with the lifecycle
    /// slice that serves `AuditQuery`.
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
    ) -> Result<Vec<AuditRecord>> {
        let snapshot = self.db.read_tx();
        let tenant_keys = self.tenant_keys(&snapshot, tenant)?;
        let prefix: HashedKey = record_key::tenant::audit(tenant_keys.index(), tenant)?;
        let start = after.map_or(0, |seq| seq.get().saturating_add(1));
        let from = record_key::join(&prefix, &start.to_be_bytes());
        let to = record_key::join(&prefix, &u64::MAX.to_be_bytes());
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut records = Vec::new();
        for guard in snapshot.range(self.ks.get(Keyspace::Audit)?, from..=to) {
            if records.len() >= limit {
                break;
            }
            let (key, sealed) = guard.into_inner().context(DatabaseSnafu)?;
            let plain = Self::open_bytes(&tenant_keys.audit_openers(), slot::AUDIT, &key, &sealed)?;
            let entry = <AuditEntryRecord as super::codec::StoredRecord>::decode(
                &plain,
                Keyspace::Audit.name(),
            )?;
            records.push(AuditRecord {
                seq: entry.seq,
                time: entry.time,
                tenant: entry.tenant,
                session: entry.session,
                invocation: entry.invocation,
                capability: entry.capability,
                state: entry.state,
                outcome: entry.outcome,
            });
        }
        Ok(records)
    }
}
