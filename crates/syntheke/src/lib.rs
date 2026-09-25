//! Capability contract shared by the Dioptron daemon and its clients.
//!
//! `syntheke` is the executable form of `docs/design/capability-contract.md`
//! (contract version [`CONTRACT_VERSION`]). It holds:
//!
//! - the 16-byte identifiers with ULID text form ([`TenantId`],
//!   [`GrantId`], [`SessionId`], [`InvocationId`], [`ArtifactRef`],
//!   [`ReservationId`]), the audit sequence [`AuditSeq`], and the
//!   caller-supplied [`IdempotencyKey`];
//! - the capability vocabulary ([`Capability`], [`Mode`], [`TenantClass`],
//!   [`AuditScope`], [`SessionScope`]) and budget vocabulary
//!   ([`Dimension`], [`Ceilings`], [`Cost`]);
//! - the request and response payload of every capability and the outcome
//!   taxonomy ([`Failure`], [`OutcomeKind`]);
//! - the wire protocol: frame header codec, bounds, handshake messages, the
//!   bytes an authenticating tenant signs, and a validating decoder.
//!
//! It is the only crate a consumer links, and it takes no dependency on
//! other fleet crates. It carries no signature implementation: the daemon
//! and each client verify and produce signatures over
//! [`auth_transcript`] with their own Ed25519 dependency.
#![deny(missing_docs)]

mod budget;
mod codec;
mod error;
mod ids;
mod names;
mod outcome;
mod payload;
mod vocab;
mod wire;

pub use budget::{Ceilings, Cost, Dimension};
pub use codec::{Message, decode, decode_frame, encode, encode_frame};
pub use error::Error;
pub use ids::{
    ArtifactRef, AuditSeq, GrantId, IdempotencyKey, InvocationId, ReservationId, SessionId,
    TenantId, Timestamp,
};
pub use outcome::{
    DenyCode, ExtractionClass, Failure, InvocationState, NarrowingAxis, OutcomeKind, ReleaseReason,
    TransferClass,
};
pub use payload::{
    AuditPage, AuditQueryRequest, AuditRecord, CaptureLimits, CaptureOutcome, CaptureRequest,
    EgressPolicy, GrantIssueRequest, GrantIssued, GrantRevokeRequest, GrantRevoked, IngestReceipt,
    IngestRequest, Plan, QueryPage, QueryRequest, ReadChunk, ReadRequest, RequestBody,
    ResponseBody, SessionForkRequest, SessionOpened, SourceRef,
};
pub use vocab::{AuditScope, Capability, Mode, SessionScope, TenantClass};
pub use wire::{
    AUTH_LABEL, AUTH_TRANSCRIPT_LEN, Admitted, Auth, CONTRACT_VERSION, Cancel, ClientHello,
    DEFAULT_MAX_BODY, Fault, FrameFlags, FrameHeader, FrameKind, HANDSHAKE_TIMEOUT_MS,
    HARD_MAX_BODY, HEADER_LEN, MAGIC, NONCE_LEN, Nonce, PRE_AUTH_MAX_BODY, Request, Response,
    SIGNATURE_LEN, ServerHello, VersionChoice, WIRE_VERSION, auth_transcript, negotiate_version,
};
