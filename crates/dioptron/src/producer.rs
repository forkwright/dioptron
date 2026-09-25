//! The producer seam (contract § Scope and non-goals).
//!
//! A producer turns a capture target into the acquisition evidence the
//! custody store keeps verbatim: the envelope bytes, their schema identity,
//! the producer revision, and the acquisition fingerprint. Static
//! acquisition belongs to Zetesis behind this seam; this crate has no
//! fetch, DNS, redirect, or extraction code, and an unavailable producer
//! is a producer failure, never permission to fetch locally.
//!
//! Two producers exist in Phase 01: [`UnavailableProducer`], the daemon's
//! default, which reports every call as never contacted, and
//! [`crate::FixtureProducer`], which replays scripted outcomes for tests.

use std::fmt;
use std::future::Future;

use syntheke::{
    CaptureLimits, EgressPolicy, ExtractionClass, InvocationId, SourceRef, TransferClass,
};
use tokio::time::Instant;

use crate::cancel::CancelSignal;

/// One acquisition the lifecycle asks a producer for.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AcquireRequest {
    /// The invocation the acquisition belongs to (B2 is already durable).
    pub invocation: InvocationId,
    /// The target exactly as the caller supplied it.
    pub target: String,
    /// The caller's output and transfer bounds.
    pub limits: CaptureLimits,
    /// The caller's egress policy, passed through unchanged.
    pub egress_policy: Option<EgressPolicy>,
}

impl AcquireRequest {
    /// A request for `target` within `limits`, with no egress policy.
    #[must_use]
    pub fn new(invocation: InvocationId, target: impl Into<String>, limits: CaptureLimits) -> Self {
        Self {
            invocation,
            target: target.into(),
            limits,
            egress_policy: None,
        }
    }
}

/// What a producer returns for a completed acquisition.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProducerOutput {
    /// The producer's envelope, stored byte for byte.
    pub envelope: Vec<u8>,
    /// Schema identity of the envelope.
    pub schema_id: String,
    /// Revision of the producer that wrote it.
    pub producer_revision: String,
    /// The acquisition fingerprint.
    pub fingerprint: String,
    /// Extracted text: a derived index over the envelope, never a
    /// replacement for it.
    pub text_view: Option<String>,
}

impl ProducerOutput {
    /// An output carrying `envelope` with the evidence identity `source`.
    #[must_use]
    pub fn new(envelope: Vec<u8>, source: SourceRef, text_view: Option<String>) -> Self {
        Self {
            envelope,
            schema_id: source.schema_id,
            producer_revision: source.producer_revision,
            fingerprint: source.fingerprint,
            text_view,
        }
    }

    /// The evidence identity the reply and the side record carry.
    #[must_use]
    pub fn source(&self) -> SourceRef {
        SourceRef {
            fingerprint: self.fingerprint.clone(),
            schema_id: self.schema_id.clone(),
            producer_revision: self.producer_revision.clone(),
        }
    }
}

/// Why a producer returned no output. Each variant maps to one outcome
/// class of the contract, and each says whether an external effect may
/// have happened, which decides between release and settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProducerError {
    /// The producer could not be reached (`ProducerUnavailable`).
    Unavailable {
        /// Whether the producer was reached at all. `false` proves no
        /// effect, and the reservation is released.
        contacted: bool,
    },
    /// The transfer began and failed (`TransferFailed`).
    Transfer {
        /// Coarse class.
        class: TransferClass,
    },
    /// The transfer completed and extraction failed (`ExtractionFailed`).
    Extraction {
        /// Coarse class.
        class: ExtractionClass,
    },
    /// The producer stopped on the cancel signal or the deadline.
    Cancelled {
        /// Whether the external effect had started before it stopped.
        effect_started: bool,
    },
}

impl ProducerError {
    /// Whether an external effect may have happened.
    #[must_use]
    pub const fn effect_started(self) -> bool {
        match self {
            Self::Unavailable { contacted } => contacted,
            Self::Cancelled { effect_started } => effect_started,
            Self::Transfer { .. } | Self::Extraction { .. } => true,
        }
    }
}

impl fmt::Display for ProducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { contacted } => {
                write!(f, "producer unavailable (contacted: {contacted})")
            }
            Self::Transfer { class } => write!(f, "transfer failed: {class}"),
            Self::Extraction { class } => write!(f, "extraction failed: {class}"),
            Self::Cancelled { effect_started } => {
                write!(f, "producer cancelled (effect started: {effect_started})")
            }
        }
    }
}

impl std::error::Error for ProducerError {}

/// Acquires a capture target.
///
/// The lifecycle calls [`Producer::acquire`] only after B2 is durable, and
/// at most once per invocation; restart recovery never calls it.
pub trait Producer: Send + Sync + 'static {
    /// Acquires `request.target`.
    ///
    /// `cancel` fires on a caller `Cancel`, a closed connection, a
    /// revocation of the authorizing chain, or the deadline. A producer
    /// that stops on it reports [`ProducerError::Cancelled`] and whether
    /// the effect had started. `deadline` is on the daemon's monotonic
    /// clock; a producer still running shortly after it is abandoned and
    /// the invocation ends as `UnknownEffect`.
    fn acquire(
        &self,
        request: AcquireRequest,
        cancel: CancelSignal,
        deadline: Instant,
    ) -> impl Future<Output = Result<ProducerOutput, ProducerError>> + Send;
}

/// A shared producer, so its owner can keep a handle (for example, to
/// read a fixture's call count) while the orchestrator uses it.
impl<P: Producer> Producer for std::sync::Arc<P> {
    fn acquire(
        &self,
        request: AcquireRequest,
        cancel: CancelSignal,
        deadline: Instant,
    ) -> impl Future<Output = Result<ProducerOutput, ProducerError>> + Send {
        (**self).acquire(request, cancel, deadline)
    }
}

/// The default producer: nothing is configured to acquire, so every call
/// reports [`ProducerError::Unavailable`] with `contacted: false`.
///
/// WHY a default that fails: a daemon started without an explicit producer
/// must never fetch anything, silently or otherwise.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableProducer;

impl Producer for UnavailableProducer {
    fn acquire(
        &self,
        _request: AcquireRequest,
        _cancel: CancelSignal,
        _deadline: Instant,
    ) -> impl Future<Output = Result<ProducerOutput, ProducerError>> + Send {
        std::future::ready(Err(ProducerError::Unavailable { contacted: false }))
    }
}

#[cfg(test)]
mod tests;
