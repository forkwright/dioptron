//! The invocation transition table and restart recovery (contract
//! § Invocation lifecycle, § Revocation of queued and running calls).
//!
//! The store runs each durable step in one transaction and checks the
//! current state inside it with [`next_state`], so settlement or release
//! happens exactly once.

use syntheke::{InvocationState, ReleaseReason};

use crate::error::{Error, IllegalTransitionSnafu};

/// One step an invocation may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Step {
    /// Authorization of an `Execute` failed; record the refusal.
    Deny,
    /// B1: commit reservation, intent, and idempotency index.
    PersistIntent,
    /// B2: record dispatch before calling the producer.
    Dispatch,
    /// B3: the producer returned and the blob is written, not yet visible.
    CompleteTransfer,
    /// B4: the atomic publish point.
    Publish,
    /// B5: settle the actual cost and release the remainder. From B2 this
    /// records a producer failure after the effect started.
    Settle,
    /// B5: release the whole reservation for `reason`.
    Release(ReleaseReason),
    /// B5: charge the reservation because the effect cannot be proven.
    MarkUnknownEffect,
}

/// The state `step` leads to from `from`.
///
/// | From | Legal steps |
/// |---|---|
/// | `Planned` | `Deny`, `PersistIntent` |
/// | B1 `IntentPersisted` | `Dispatch`; `Release` for `Abandoned`, `Revoked`, `Cancelled`, `DeadlineExceeded` |
/// | B2 `Dispatched` | `CompleteTransfer`, `Settle`, `MarkUnknownEffect`; `Release` for `Revoked`, `Cancelled`, `DeadlineExceeded`, `ProducerUnavailable` (each only when the producer reports it had not started) |
/// | B3 `TransferComplete` | `Publish` |
/// | B4 `Published` | `Settle` |
/// | terminal | none |
///
/// WHY no release at B3 or later: the effect is durable there, so the call
/// rolls forward and settles, even after a revocation. WHY no `Abandoned`
/// at B2: a restart at B2 may follow a live producer call and becomes
/// `UnknownEffect`, never a release.
///
/// # Errors
///
/// [`Error::IllegalTransition`] for every step the table does not list,
/// including any step from a terminal state and any state or reason a
/// later contract version adds.
pub fn next_state(from: InvocationState, step: Step) -> Result<InvocationState, Error> {
    use InvocationState as S;
    use ReleaseReason as R;
    let to = match (from, step) {
        (S::Planned, Step::Deny) => Some(S::Denied),
        (S::Planned, Step::PersistIntent) => Some(S::IntentPersisted),
        (S::IntentPersisted, Step::Dispatch) => Some(S::Dispatched),
        (
            S::IntentPersisted,
            Step::Release(R::Abandoned | R::Revoked | R::Cancelled | R::DeadlineExceeded),
        )
        | (
            S::Dispatched,
            Step::Release(R::Revoked | R::Cancelled | R::DeadlineExceeded | R::ProducerUnavailable),
        ) => Some(S::Released),
        (S::Dispatched, Step::CompleteTransfer) => Some(S::TransferComplete),
        (S::Dispatched | S::Published, Step::Settle) => Some(S::Settled),
        (S::Dispatched, Step::MarkUnknownEffect) => Some(S::UnknownEffect),
        (S::TransferComplete, Step::Publish) => Some(S::Published),
        _ => None,
    };
    to.map_or_else(|| IllegalTransitionSnafu { from, step }.fail(), Ok)
}

/// What restart recovery does with an invocation found in a state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecoveryAction {
    /// B1: the producer was never called; release as `Abandoned`.
    ReleaseAbandoned,
    /// B2: the producer may have been called; charge the reservation as
    /// `UnknownEffect` and never re-dispatch.
    MarkUnknownEffect,
    /// B3: the bytes exist; publish, then settle.
    RollForwardPublish,
    /// B4: the capture is visible; settle.
    RollForwardSettle,
}

impl RecoveryAction {
    /// The first step this action takes.
    #[must_use]
    pub const fn step(self) -> Step {
        match self {
            Self::ReleaseAbandoned => Step::Release(ReleaseReason::Abandoned),
            Self::MarkUnknownEffect => Step::MarkUnknownEffect,
            Self::RollForwardPublish => Step::Publish,
            Self::RollForwardSettle => Step::Settle,
        }
    }
}

/// The recovery action for an invocation found in `state` after a restart,
/// or `None` when nothing is recovered: `Planned` is never persisted, and a
/// terminal state is final.
#[must_use]
pub const fn recovery_action(state: InvocationState) -> Option<RecoveryAction> {
    match state {
        InvocationState::IntentPersisted => Some(RecoveryAction::ReleaseAbandoned),
        InvocationState::Dispatched => Some(RecoveryAction::MarkUnknownEffect),
        InvocationState::TransferComplete => Some(RecoveryAction::RollForwardPublish),
        InvocationState::Published => Some(RecoveryAction::RollForwardSettle),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
