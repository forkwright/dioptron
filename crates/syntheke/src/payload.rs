//! Request and response payloads for every capability.
//!
//! All payload types are plain data: every field combination is
//! representable on the wire, and the daemon applies authorization and scope
//! rules after decoding. The one constrained field, [`IdempotencyKey`], is
//! re-checked by [`crate::Message::check`] on the enclosing request.

use crate::budget::{Ceilings, Cost};
use crate::ids::{ArtifactRef, AuditSeq, GrantId, InvocationId, SessionId, TenantId, Timestamp};
use crate::outcome::{Failure, InvocationState, OutcomeKind};
use crate::vocab::{AuditScope, Capability, SessionScope};

/// Derive list shared by every payload type.
macro_rules! payload {
    ($(#[$meta:meta])* pub struct $name:ident { $($body:tt)* }) => {
        $(#[$meta])*
        #[derive(
            Clone, Debug, PartialEq, Eq, Hash,
            rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
        )]
        pub struct $name { $($body)* }
    };
}

payload! {
    /// `SessionFork`: branch `parent` into a new session with lineage.
    pub struct SessionForkRequest {
        /// The session to branch.
        pub parent_session: SessionId,
    }
}

payload! {
    /// Caller-set bounds on one capture. `None` leaves the dimension bounded
    /// only by the grant chain's ceilings.
    #[derive(Copy, Default)]
    pub struct CaptureLimits {
        /// Maximum bytes of extracted output returned to the caller. The
        /// first consumer's maximum output length maps here.
        pub max_output_bytes: Option<u64>,
        /// Maximum bytes the producer may transfer.
        pub max_transfer_bytes: Option<u64>,
    }
}

payload! {
    /// The caller's egress policy, carried opaquely to the producer.
    ///
    /// WHY opaque: the contract preserves the caller's policy and passes it
    /// through; its format belongs to the caller and the producer, and
    /// Dioptron neither interprets nor rewrites it.
    pub struct EgressPolicy {
        /// Policy bytes exactly as the caller supplied them.
        pub bytes: Vec<u8>,
    }
}

payload! {
    /// `Capture`: acquire `target` through the producer seam into `session`.
    pub struct CaptureRequest {
        /// Session that will own the artifact.
        pub session: SessionId,
        /// The target, for example `https://example.com/article`.
        pub target: String,
        /// Output and transfer bounds.
        pub limits: CaptureLimits,
        /// The caller's egress policy, passed through unchanged.
        pub egress_policy: Option<EgressPolicy>,
    }
}

payload! {
    /// `Ingest`: submit a stored artifact into the knowledge pipeline.
    pub struct IngestRequest {
        /// The artifact to ingest.
        pub artifact_ref: ArtifactRef,
    }
}

payload! {
    /// `Read`: one bounded chunk of a stored artifact's verbatim envelope.
    pub struct ReadRequest {
        /// The artifact to read.
        pub artifact_ref: ArtifactRef,
        /// Byte offset of the chunk.
        pub offset: u64,
        /// Maximum chunk length in bytes.
        pub len: u32,
    }
}

payload! {
    /// `Query`: records within the caller's read scope.
    pub struct QueryRequest {
        /// The session to search. Version 1 requires one: `None` is refused
        /// with `Denied{SessionRequired}`.
        pub session_scope: Option<SessionId>,
        /// The predicate. Its language is not fixed by contract version 1
        /// and is carried as text.
        pub predicate: String,
        /// Maximum number of results.
        pub limit: u32,
    }
}

payload! {
    /// `GrantIssue`: issue a child grant attenuating the request's
    /// designated grant ([`crate::Request::grant`]), which is the parent.
    ///
    /// WHY no parent field: the parent is the grant the issuer acts under,
    /// so a second field naming it could only disagree with it.
    pub struct GrantIssueRequest {
        /// Tenant that will hold the child.
        pub holder: TenantId,
        /// Conferred capabilities; must be a subset of the parent's.
        pub capabilities: Vec<Capability>,
        /// Session scope; must be a subset of the parent's.
        pub session_scope: SessionScope,
        /// Target origin patterns; must be a subset of the parent's.
        pub target_scope: Vec<String>,
        /// Per-dimension ceilings; each at most the parent's remaining.
        pub ceilings: Ceilings,
        /// Start of validity.
        pub not_before: Timestamp,
        /// End of validity (exclusive); at or before the parent's.
        pub expires_at: Timestamp,
        /// A lower maximum chain depth; `None` inherits the parent's.
        pub max_depth: Option<u8>,
    }
}

payload! {
    /// `GrantRevoke`: revoke a grant and, through chain validity, its
    /// descendants.
    pub struct GrantRevokeRequest {
        /// The grant to revoke.
        pub target_grant: GrantId,
    }
}

payload! {
    /// `AuditQuery`: a page of audit records within the caller's audit scope.
    pub struct AuditQueryRequest {
        /// The audit scope requested; the grant's scope bounds it.
        pub audit_scope: AuditScope,
        /// Restrict to one session; `None` covers the whole audit scope.
        pub session: Option<SessionId>,
        /// Return records after this sequence; `None` starts at the first.
        pub after: Option<AuditSeq>,
        /// Maximum number of records.
        pub limit: u32,
    }
}

/// The capability-specific body of a request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[non_exhaustive]
pub enum RequestBody {
    /// Open a new session owned by the acting tenant.
    SessionCreate,
    /// See [`SessionForkRequest`].
    SessionFork(SessionForkRequest),
    /// See [`CaptureRequest`].
    Capture(CaptureRequest),
    /// See [`IngestRequest`].
    Ingest(IngestRequest),
    /// See [`ReadRequest`].
    Read(ReadRequest),
    /// See [`QueryRequest`].
    Query(QueryRequest),
    /// See [`GrantIssueRequest`].
    GrantIssue(GrantIssueRequest),
    /// See [`GrantRevokeRequest`].
    GrantRevoke(GrantRevokeRequest),
    /// See [`AuditQueryRequest`].
    AuditQuery(AuditQueryRequest),
}

impl RequestBody {
    /// The capability this body invokes.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        match self {
            Self::SessionCreate => Capability::SessionCreate,
            Self::SessionFork(_) => Capability::SessionFork,
            Self::Capture(_) => Capability::Capture,
            Self::Ingest(_) => Capability::Ingest,
            Self::Read(_) => Capability::Read,
            Self::Query(_) => Capability::Query,
            Self::GrantIssue(_) => Capability::GrantIssue,
            Self::GrantRevoke(_) => Capability::GrantRevoke,
            Self::AuditQuery(_) => Capability::AuditQuery,
        }
    }
}

payload! {
    /// Reply to `SessionCreate` and `SessionFork`.
    pub struct SessionOpened {
        /// The new session.
        pub session: SessionId,
        /// Owner: the acting tenant.
        pub owner: TenantId,
        /// The session it was forked from, for `SessionFork`.
        pub parent_session: Option<SessionId>,
    }
}

payload! {
    /// The acquisition evidence identity of a capture: the fingerprint,
    /// schema identity, and producer revision the producer reported.
    pub struct SourceRef {
        /// Acquisition fingerprint.
        pub fingerprint: String,
        /// Schema identity of the stored envelope.
        pub schema_id: String,
        /// Revision of the producer that produced the envelope.
        pub producer_revision: String,
    }
}

payload! {
    /// Reply to `Capture`.
    pub struct CaptureOutcome {
        /// The stored artifact.
        pub artifact_ref: ArtifactRef,
        /// The evidence identity.
        pub source: SourceRef,
        /// Extracted text, cut to the output bound. A derived view; the
        /// verbatim envelope is read with `Read`.
        pub text_view: Option<String>,
        /// Whether `text_view` was cut to fit the output bound.
        pub truncated: bool,
        /// Length of `text_view` in bytes, charged to output bytes.
        pub output_bytes: u64,
        /// Whether the authorizing grant was revoked after the external
        /// effect had started.
        pub revoked_after_effect: bool,
    }
}

payload! {
    /// Reply to `Ingest`.
    pub struct IngestReceipt {
        /// The artifact accepted into the pipeline.
        pub artifact_ref: ArtifactRef,
    }
}

payload! {
    /// Reply to `Read`: one chunk of the verbatim envelope.
    pub struct ReadChunk {
        /// Byte offset of `bytes` in the envelope.
        pub offset: u64,
        /// The chunk; shorter than requested at the end of the envelope.
        pub bytes: Vec<u8>,
        /// Total envelope length in bytes.
        pub total_len: u64,
    }
}

payload! {
    /// Reply to `Query`.
    pub struct QueryPage {
        /// Matching artifacts within the caller's read scope.
        pub result_refs: Vec<ArtifactRef>,
        /// Whether more matches exist beyond the limit.
        pub more: bool,
    }
}

payload! {
    /// Reply to `GrantIssue`.
    pub struct GrantIssued {
        /// The new child grant.
        pub grant: GrantId,
        /// Its parent.
        pub parent_grant: GrantId,
    }
}

payload! {
    /// Reply to `GrantRevoke`: the revocation record.
    pub struct GrantRevoked {
        /// The revoked grant.
        pub revoked_grant: GrantId,
        /// Audit sequence at which the revocation took effect (its epoch).
        pub effect_sequence: AuditSeq,
        /// Wall time of the effect.
        pub effect_time: Timestamp,
    }
}

payload! {
    /// One audit record as returned by `AuditQuery`.
    pub struct AuditRecord {
        /// Position in the audit sequence.
        pub seq: AuditSeq,
        /// Wall time of the record.
        pub time: Timestamp,
        /// Acting tenant.
        pub tenant: TenantId,
        /// Session, when the invocation had one.
        pub session: Option<SessionId>,
        /// The invocation.
        pub invocation: InvocationId,
        /// Capability invoked.
        pub capability: Capability,
        /// State the record was committed with.
        pub state: InvocationState,
        /// Outcome kind at that state.
        pub outcome: OutcomeKind,
    }
}

payload! {
    /// Reply to `AuditQuery`.
    pub struct AuditPage {
        /// The audit scope the records were filtered by.
        pub scope_applied: AuditScope,
        /// Records in sequence order.
        pub records: Vec<AuditRecord>,
        /// Pass as `after` to continue; `None` at the end.
        pub next_after: Option<AuditSeq>,
    }
}

payload! {
    /// Reply to a dry-run: what an executed call would use and cost.
    pub struct Plan {
        /// The capability planned.
        pub capability: Capability,
        /// Declared maximum cost per dimension.
        pub cost: Cost,
        /// The authorizing grant chain, leaf first.
        pub grant_chain: Vec<GrantId>,
        /// Identifiers of the rules consulted, in evaluation order. Empty
        /// until a rule evaluator exists; the identifier format is not fixed
        /// by contract version 1.
        pub rule_chain: Vec<String>,
        /// The failure an `Execute` of the same request would receive, when
        /// the plan finds it would be refused. A refused dry-run still writes
        /// nothing.
        pub refusal: Option<Failure>,
    }
}

/// The body of a reply.
#[derive(Clone, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[non_exhaustive]
pub enum ResponseBody {
    /// A session was opened (create or fork).
    SessionOpened(SessionOpened),
    /// A capture completed.
    Captured(CaptureOutcome),
    /// An artifact was accepted for ingest.
    Ingested(IngestReceipt),
    /// A read chunk.
    Chunk(ReadChunk),
    /// Query results.
    QueryPage(QueryPage),
    /// A child grant was issued.
    GrantIssued(GrantIssued),
    /// A grant was revoked.
    GrantRevoked(GrantRevoked),
    /// Audit records.
    AuditPage(AuditPage),
    /// A dry-run plan.
    Plan(Plan),
    /// An idempotent replay found the original invocation still running.
    InProgress,
    /// The call failed.
    Failed(Failure),
}

impl ResponseBody {
    /// The outcome kind of this reply.
    #[must_use]
    pub const fn outcome(&self) -> OutcomeKind {
        match self {
            Self::SessionOpened(_)
            | Self::Captured(_)
            | Self::Ingested(_)
            | Self::Chunk(_)
            | Self::QueryPage(_)
            | Self::GrantIssued(_)
            | Self::GrantRevoked(_)
            | Self::AuditPage(_) => OutcomeKind::Success,
            Self::Plan(_) => OutcomeKind::Plan,
            Self::InProgress => OutcomeKind::InProgress,
            Self::Failed(failure) => failure.kind(),
        }
    }
}
