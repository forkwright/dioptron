//! Storage-side record types.
//!
//! WHY separate types: the store's schema changes only by migration, while
//! the contract and authorization types change with their own versions.
//! Contract types are embedded where their shape already is the stored
//! shape (identifiers, `Cost`, `Ceilings`, `SourceRef`, vocabulary enums);
//! everything else is converted at the boundary. Every record is encoded
//! with rkyv and read back only through validated access.

use epitrope::{Grant, LedgerId, Revocation, TargetScope};
use snafu::ResultExt as _;
use syntheke::{
    ArtifactRef, AuditScope, AuditSeq, Capability, Ceilings, Cost, DenyCode, Failure, GrantId,
    InvocationId, InvocationState, OutcomeKind, ReleaseReason, SessionId, SessionScope, SourceRef,
    TenantClass, TenantId, Timestamp,
};

use crate::error::AuthzSnafu;

/// Record kinds bound into every sealed value's additional data.
pub(crate) mod kind {
    use crate::crypto::RecordKind;

    /// A tenant record in `tenants`.
    pub(crate) const TENANT: RecordKind = RecordKind::new(1);
    /// A grant record in `grants`.
    pub(crate) const GRANT: RecordKind = RecordKind::new(3);
    /// A revocation record in `revocations`.
    pub(crate) const REVOCATION: RecordKind = RecordKind::new(4);
    /// A session record in `sessions`.
    pub(crate) const SESSION: RecordKind = RecordKind::new(5);
    /// An invocation record in `invocations`.
    pub(crate) const INVOCATION: RecordKind = RecordKind::new(6);
    /// An idempotency entry in `idem`.
    pub(crate) const IDEM: RecordKind = RecordKind::new(7);
    /// A ledger in `ledgers`.
    pub(crate) const LEDGER: RecordKind = RecordKind::new(8);
    /// A published artifact side record in `artifacts`.
    pub(crate) const ARTIFACT: RecordKind = RecordKind::new(9);
    /// A pending (B3, not visible) side record in `artifacts`.
    pub(crate) const PENDING_ARTIFACT: RecordKind = RecordKind::new(10);
    /// An artifact locator in `artifacts`.
    pub(crate) const LOCATOR: RecordKind = RecordKind::new(11);
    /// A verbatim envelope in `blobs`.
    pub(crate) const BLOB: RecordKind = RecordKind::new(12);
    /// A session index entry in `session_index`.
    pub(crate) const SESSION_INDEX: RecordKind = RecordKind::new(13);
    /// A per-tenant audit entry in `audit`.
    pub(crate) const AUDIT: RecordKind = RecordKind::new(14);
    /// A global audit stub in `audit_stub`.
    pub(crate) const AUDIT_STUB: RecordKind = RecordKind::new(15);
    /// A tenant data-key rotation in `rekey`.
    pub(crate) const REKEY: RecordKind = RecordKind::new(16);
    /// A crypto-shredded tenant's tombstone in `tenants`.
    pub(crate) const TOMBSTONE: RecordKind = RecordKind::new(17);
}

/// How an invocation ended. Each variant records only what its terminal
/// state means (contract § Invocation lifecycle): a settled call the reply
/// the caller observed, a released call the reason it released, and an
/// unknown effect nothing more. A release reason is never stored as a
/// failure, so `Released(Abandoned)` and `Released(Cancelled)` stay
/// distinct in every record.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[non_exhaustive]
pub enum Terminal {
    /// `Settled`: the actual consumption kept, the remainder released.
    Settled {
        /// The failure the caller observed; `None` for a success.
        failure: Option<Failure>,
    },
    /// `Released`: the whole reservation returned.
    Released {
        /// Why it was released.
        reason: ReleaseReason,
    },
    /// `UnknownEffect`: the whole reservation charged.
    UnknownEffect,
}

impl Terminal {
    /// The terminal state this ending records.
    #[must_use]
    pub const fn state(self) -> InvocationState {
        match self {
            Self::Settled { .. } => InvocationState::Settled,
            Self::Released { .. } => InvocationState::Released,
            Self::UnknownEffect => InvocationState::UnknownEffect,
        }
    }

    /// The release reason, for `Released` only.
    #[must_use]
    pub const fn release_reason(self) -> Option<ReleaseReason> {
        match self {
            Self::Released { reason } => Some(reason),
            Self::Settled { .. } | Self::UnknownEffect => None,
        }
    }

    /// The failure an idempotent replay of this invocation reports, or
    /// `None` for a success.
    ///
    /// For `Released` this is a reply mapping, not the record: `Revoked`
    /// reads as `Denied{GrantRevoked}`; `ProducerUnavailable`,
    /// `DeadlineExceeded`, and `Cancelled` as themselves; `Abandoned`,
    /// which no caller ever received a reply for, as `Cancelled`, the
    /// contract's outcome for a call that ended before any effect. The
    /// reason itself stays in [`Terminal::release_reason`].
    #[must_use]
    pub const fn reply_failure(self) -> Option<Failure> {
        match self {
            Self::Settled { failure } => failure,
            Self::UnknownEffect => Some(Failure::UnknownEffect),
            Self::Released { reason } => Some(match reason {
                ReleaseReason::Revoked => Failure::denied(DenyCode::GrantRevoked),
                ReleaseReason::ProducerUnavailable => Failure::ProducerUnavailable,
                ReleaseReason::DeadlineExceeded => Failure::DeadlineExceeded,
                // WHY a wildcard: `ReleaseReason` is non-exhaustive; a
                // reason a later contract adds reads as a call that ended
                // before any effect until it states otherwise.
                _ => Failure::Cancelled,
            }),
        }
    }

    /// The reply kind of [`Terminal::reply_failure`]: `Success` when it is
    /// `None`.
    #[must_use]
    pub const fn outcome(self) -> OutcomeKind {
        match self.reply_failure() {
            Some(failure) => failure.kind(),
            None => OutcomeKind::Success,
        }
    }
}

/// Derive list shared by every stored record.
macro_rules! record {
    ($(#[$meta:meta])* pub(crate) struct $name:ident { $($body:tt)* }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
        pub(crate) struct $name { $($body)* }
    };
}

record! {
    /// A registered tenant.
    pub(crate) struct TenantRecord {
        pub(crate) id: TenantId,
        pub(crate) class: TenantClass,
        pub(crate) verifying_key: [u8; 32],
        pub(crate) bound_uids: Vec<u32>,
        pub(crate) parent: Option<TenantId>,
        pub(crate) ceilings: Ceilings,
        /// The id of the tenant's active data key.
        pub(crate) data_key_id: u32,
        pub(crate) registered_at: Timestamp,
    }
}

record! {
    /// A grant. Target patterns are kept as their text so the record
    /// round-trips without a pattern printer.
    pub(crate) struct GrantRecord {
        pub(crate) id: GrantId,
        pub(crate) issuer: TenantId,
        pub(crate) holder: TenantId,
        pub(crate) capabilities: Vec<Capability>,
        pub(crate) session_scope: SessionScope,
        pub(crate) target_patterns: Vec<String>,
        pub(crate) audit_scope: AuditScope,
        pub(crate) ceilings: Ceilings,
        pub(crate) not_before: Timestamp,
        pub(crate) expires_at: Timestamp,
        pub(crate) parent: Option<GrantId>,
        pub(crate) depth: u8,
        pub(crate) max_depth: u8,
    }
}

impl GrantRecord {
    /// The stored form of `grant`, whose target scope parsed from
    /// `target_patterns`.
    pub(crate) fn from_grant(grant: &Grant, target_patterns: Vec<String>) -> Self {
        Self {
            id: grant.id,
            issuer: grant.issuer,
            holder: grant.holder,
            capabilities: grant.capabilities.iter().copied().collect(),
            session_scope: grant.session_scope.clone(),
            target_patterns,
            audit_scope: grant.audit_scope,
            ceilings: grant.ceilings,
            not_before: grant.not_before,
            expires_at: grant.expires_at,
            parent: grant.parent,
            depth: grant.depth,
            max_depth: grant.max_depth,
        }
    }

    /// The authorization form of this record.
    pub(crate) fn to_grant(&self) -> crate::Result<Grant> {
        Ok(Grant {
            id: self.id,
            issuer: self.issuer,
            holder: self.holder,
            capabilities: self.capabilities.iter().copied().collect(),
            session_scope: self.session_scope.clone(),
            target_scope: TargetScope::parse(&self.target_patterns).context(AuthzSnafu)?,
            audit_scope: self.audit_scope,
            ceilings: self.ceilings,
            not_before: self.not_before,
            expires_at: self.expires_at,
            parent: self.parent,
            depth: self.depth,
            max_depth: self.max_depth,
        })
    }
}

record! {
    /// A revocation record.
    pub(crate) struct RevocationRecord {
        pub(crate) grant: GrantId,
        pub(crate) at_seq: AuditSeq,
        pub(crate) at_time: Timestamp,
        pub(crate) by: TenantId,
    }
}

impl RevocationRecord {
    /// The authorization form of this record.
    pub(crate) const fn to_revocation(&self) -> Revocation {
        Revocation {
            grant: self.grant,
            at_seq: self.at_seq,
            at_time: self.at_time,
        }
    }
}

record! {
    /// A session.
    pub(crate) struct SessionRecord {
        pub(crate) id: SessionId,
        pub(crate) owner: TenantId,
        /// The session this one was forked from.
        pub(crate) parent: Option<SessionId>,
        pub(crate) ceilings: Ceilings,
        pub(crate) created_at: Timestamp,
    }
}

/// Identifies a ledger in storage.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub(crate) enum LedgerRef {
    /// A grant's ledger.
    Grant(GrantId),
    /// A session's ledger.
    Session(SessionId),
    /// A tenant's ledger.
    Tenant(TenantId),
}

impl LedgerRef {
    /// The stored form of an authorization ledger id, or `None` for a
    /// ledger kind this schema does not store.
    pub(crate) const fn from_ledger_id(id: LedgerId) -> Option<Self> {
        match id {
            LedgerId::Grant(grant) => Some(Self::Grant(grant)),
            LedgerId::Session(session) => Some(Self::Session(session)),
            LedgerId::Tenant(tenant) => Some(Self::Tenant(tenant)),
            _ => None,
        }
    }
}

record! {
    /// A budget ledger: settled consumption plus unsettled reservations.
    pub(crate) struct LedgerRecord {
        pub(crate) used: Cost,
    }
}

record! {
    /// An invocation's intent and lifecycle state.
    pub(crate) struct InvocationRecord {
        pub(crate) id: InvocationId,
        pub(crate) tenant: TenantId,
        pub(crate) capability: Capability,
        pub(crate) session: Option<SessionId>,
        /// The authorizing chain, leaf first.
        pub(crate) grant_chain: Vec<GrantId>,
        /// Every ledger the reservation debited.
        pub(crate) ledgers: Vec<LedgerRef>,
        /// The declared maximum debited from each ledger.
        pub(crate) reserved: Cost,
        pub(crate) state: InvocationState,
        /// How the invocation ended; `None` until a terminal state.
        pub(crate) terminal: Option<Terminal>,
        /// Actual consumption, recorded at B3 or at a B2 settlement.
        pub(crate) actual: Option<Cost>,
        /// Amount kept as spent at B5.
        pub(crate) debited: Option<Cost>,
        /// The artifact written at B3 and published at B4.
        pub(crate) artifact: Option<ArtifactRef>,
        pub(crate) revoked_after_effect: bool,
        pub(crate) created_at: Timestamp,
        pub(crate) updated_at: Timestamp,
    }
}

record! {
    /// An idempotency index entry. It lives only in the tenant-sealed
    /// `idem` keyspace, so the request binding is shredded with the
    /// tenant.
    pub(crate) struct IdemRecord {
        pub(crate) invocation: InvocationId,
        /// The store's binding of the caller's request digest to the
        /// designated grant, capability, session, target, and declared
        /// cost ([`crate::store::invocation`]).
        pub(crate) request_binding: [u8; 32],
    }
}

record! {
    /// An artifact side record, pending (B3) or published (B4).
    pub(crate) struct ArtifactRecord {
        pub(crate) artifact: ArtifactRef,
        pub(crate) invocation: InvocationId,
        pub(crate) tenant: TenantId,
        pub(crate) session: Option<SessionId>,
        pub(crate) grant_chain: Vec<GrantId>,
        /// The reservation the capture ran under (the invocation's).
        pub(crate) reservation: InvocationId,
        /// No classifier exists in Phase 01; always `None` until D7 lands.
        pub(crate) classification: Option<String>,
        /// The artifact this one corrects, if any.
        pub(crate) lineage: Option<ArtifactRef>,
        /// SHA-256 of the envelope, kept only inside this sealed record.
        pub(crate) provenance_digest: [u8; 32],
        /// Tenant-keyed address of the envelope.
        pub(crate) blob_address: [u8; 32],
        pub(crate) blob_len: u64,
        pub(crate) source: SourceRef,
        pub(crate) text_view: Option<String>,
        pub(crate) truncated: bool,
        pub(crate) output_bytes: u64,
        pub(crate) revoked_after_effect: bool,
        /// `None` while pending.
        pub(crate) published_at: Option<Timestamp>,
    }
}

record! {
    /// Where a published artifact lives: its owner and session. Readable
    /// with the store key alone, so a reader can find the owner's keys.
    pub(crate) struct LocatorRecord {
        pub(crate) artifact: ArtifactRef,
        pub(crate) owner: TenantId,
        pub(crate) session: Option<SessionId>,
    }
}

record! {
    /// One artifact in a session's index.
    pub(crate) struct SessionIndexRecord {
        pub(crate) artifact: ArtifactRef,
        pub(crate) captured_by: TenantId,
        pub(crate) published_at: Timestamp,
    }
}

record! {
    /// A per-tenant audit entry.
    pub(crate) struct AuditEntryRecord {
        pub(crate) seq: AuditSeq,
        pub(crate) time: Timestamp,
        pub(crate) tenant: TenantId,
        pub(crate) session: Option<SessionId>,
        pub(crate) invocation: InvocationId,
        pub(crate) capability: Capability,
        pub(crate) state: InvocationState,
        /// The reply kind at that state; for `Released`, the reply a
        /// replay observes ([`Terminal::outcome`]).
        pub(crate) outcome: OutcomeKind,
        /// Why the reservation was released; present exactly when `state`
        /// is `Released`.
        pub(crate) release_reason: Option<ReleaseReason>,
    }
}

record! {
    /// A global audit stub. Carries no tenant and no content, so it
    /// survives a crypto-shred of the tenant.
    pub(crate) struct AuditStubRecord {
        pub(crate) seq: AuditSeq,
        pub(crate) invocation: InvocationId,
        pub(crate) capability: Capability,
        pub(crate) outcome: OutcomeKind,
        pub(crate) time: Timestamp,
    }
}

record! {
    /// A tenant data-key rotation: in progress until `done`, then kept as
    /// the record of the last rotation until the next one replaces it.
    pub(crate) struct RekeyRecord {
        pub(crate) tenant: TenantId,
        /// The data key being retired.
        pub(crate) from_key_id: u32,
        /// The data key new and re-sealed records use.
        pub(crate) to_key_id: u32,
        /// Position in the rotation's keyspace walk; the walk's length
        /// once every keyspace has been visited.
        pub(crate) keyspace: u8,
        /// The last record key visited in `keyspace`; `None` at its start.
        pub(crate) cursor: Option<Vec<u8>>,
        /// Records examined so far.
        pub(crate) visited: u64,
        /// Records re-sealed under the new data key so far.
        pub(crate) resealed: u64,
        /// Records in the walked keyspaces when the rotation began.
        pub(crate) total: u64,
        /// Whether the old data key is retired.
        pub(crate) done: bool,
        pub(crate) started_at: Timestamp,
        pub(crate) finished_at: Option<Timestamp>,
    }
}

record! {
    /// A crypto-shredded tenant. It replaces the tenant record, so the id
    /// stays reserved and reads report the tenant as shredded.
    pub(crate) struct TombstoneRecord {
        pub(crate) tenant: TenantId,
        pub(crate) shredded_at: Timestamp,
    }
}
