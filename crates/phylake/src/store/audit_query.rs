//! Audit reads within an audit scope (contract § Audit partitions, D17.7).
//!
//! Each tenant's audit entries sit in its own sealed partition. A scope of
//! `All` reads every partition; `OwnAndOwnedSessions` reads the acting
//! tenant's partition whole, plus the entries other tenants wrote in
//! sessions the acting tenant owns. The caller authorizes the scope first
//! (epitrope's `applied_audit_scope`); this module only filters.

use std::collections::HashMap;

use fjall::Readable as _;
use snafu::ResultExt as _;
use syntheke::{AuditRecord, AuditScope, AuditSeq, SessionId, TenantId};

use super::codec::StoredRecord as _;
use super::record_key;
use super::records::{AuditEntryRecord, TenantRecord};
use super::view::View;
use super::{Store, slot};
use crate::Result;
use crate::crypto::Keyspace;
use crate::error::DatabaseSnafu;

/// One audit read; see [`Store::audit_query`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditQuery {
    /// The acting tenant.
    pub tenant: TenantId,
    /// The scope to answer with, already bounded by the caller's grant.
    pub scope: AuditScope,
    /// Restrict to entries in this session.
    pub session: Option<SessionId>,
    /// Return entries after this sequence.
    pub after: Option<AuditSeq>,
    /// Maximum number of entries.
    pub limit: u32,
}

impl AuditQuery {
    /// A query of `scope` for `tenant`, with no session filter, from the
    /// start, returning at most `limit` entries.
    #[must_use]
    pub const fn new(tenant: TenantId, scope: AuditScope, limit: u32) -> Self {
        Self {
            tenant,
            scope,
            session: None,
            after: None,
            limit,
        }
    }
}

/// The entries of one audit read, and whether more remain.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditRead {
    /// Entries in sequence order.
    pub records: Vec<AuditRecord>,
    /// Whether entries beyond the limit match.
    pub more: bool,
}

impl Store {
    /// The audit entries `query` selects, in sequence order.
    ///
    /// PERF: every partition in scope is read in full and merged in
    /// memory. Phase 01 volumes do not need a global audit index.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure;
    /// [`crate::Error::TenantMissing`] for an unregistered acting tenant.
    pub fn audit_query(&self, query: &AuditQuery) -> Result<AuditRead> {
        let snapshot = self.db.read_tx();
        let after = query.after.map_or(0, AuditSeq::get);
        let mut matched = self.partition(&snapshot, query.tenant, after)?;
        let others = self.tenant_ids(&snapshot)?;
        let mut owners: HashMap<SessionId, Option<TenantId>> = HashMap::new();
        for tenant in others.into_iter().filter(|id| *id != query.tenant) {
            for record in self.partition(&snapshot, tenant, after)? {
                let visible = match query.scope {
                    AuditScope::All => true,
                    _ => match record.session {
                        Some(session) => {
                            self.session_owner(&snapshot, &mut owners, session)?
                                == Some(query.tenant)
                        }
                        None => false,
                    },
                };
                if visible {
                    matched.push(record);
                }
            }
        }
        if let Some(session) = query.session {
            matched.retain(|record| record.session == Some(session));
        }
        matched.sort_by_key(|record| record.seq);
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        let more = matched.len() > limit;
        matched.truncate(limit);
        Ok(AuditRead {
            records: matched,
            more,
        })
    }

    /// Every entry in `tenant`'s partition with a sequence above `after`.
    fn partition(
        &self,
        snapshot: &fjall::Snapshot,
        tenant: TenantId,
        after: u64,
    ) -> Result<Vec<AuditRecord>> {
        let keys = self.tenant_keys(snapshot, tenant)?;
        let prefix = record_key::tenant::audit(keys.index(), tenant)?;
        let from = record_key::join(&prefix, &after.saturating_add(1).to_be_bytes());
        let to = record_key::join(&prefix, &u64::MAX.to_be_bytes());
        let mut records = Vec::new();
        for guard in snapshot.range(self.ks.get(Keyspace::Audit)?, from..=to) {
            let (key, sealed) = guard.into_inner().context(DatabaseSnafu)?;
            let plain = Self::open_bytes(&[keys.audit()], slot::AUDIT, &key, &sealed)?;
            let entry = AuditEntryRecord::decode(&plain, Keyspace::Audit.name())?;
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

    /// The id of every registered tenant.
    fn tenant_ids(&self, snapshot: &fjall::Snapshot) -> Result<Vec<TenantId>> {
        let mut ids = Vec::new();
        for guard in snapshot.iter(self.ks.get(slot::TENANT.keyspace)?) {
            let (key, sealed) = guard.into_inner().context(DatabaseSnafu)?;
            let plain = Self::open_bytes(&[self.keys.meta()], slot::TENANT, &key, &sealed)?;
            ids.push(TenantRecord::decode(&plain, slot::TENANT.keyspace.name())?.id);
        }
        Ok(ids)
    }

    /// The owner of `session`, memoized in `owners`.
    fn session_owner(
        &self,
        snapshot: &fjall::Snapshot,
        owners: &mut HashMap<SessionId, Option<TenantId>>,
        session: SessionId,
    ) -> Result<Option<TenantId>> {
        if let Some(owner) = owners.get(&session) {
            return Ok(*owner);
        }
        let owner = View {
            store: self,
            reader: snapshot,
        }
        .session_record(session)?
        .map(|record| record.owner);
        owners.insert(session, owner);
        Ok(owner)
    }
}
