//! Failure injection at lifecycle boundaries
//! (`docs/design/custody-store.md`, "Failure-injection specification").

use core::fmt;

/// A durable lifecycle boundary: one store transaction each.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Boundary {
    /// B1: reservation, intent, and idempotency index.
    PersistIntent,
    /// B2: dispatch recorded before the producer call.
    Dispatch,
    /// B3: the blob written with a pending side record, not visible.
    CompleteTransfer,
    /// B4: the atomic publish point.
    Publish,
    /// B5: settle, release, or `UnknownEffect`.
    Terminal,
}

impl Boundary {
    /// Every boundary, in lifecycle order.
    pub const ALL: [Self; 5] = [
        Self::PersistIntent,
        Self::Dispatch,
        Self::CompleteTransfer,
        Self::Publish,
        Self::Terminal,
    ];

    /// The contract's name for the boundary.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PersistIntent => "B1",
            Self::Dispatch => "B2",
            Self::CompleteTransfer => "B3",
            Self::Publish => "B4",
            Self::Terminal => "B5",
        }
    }
}

impl fmt::Display for Boundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Which side of a commit a failpoint fires on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Phase {
    /// The transaction is built and not committed; a crash discards it.
    BeforeCommit,
    /// The transaction is durable; a crash loses only the caller's reply.
    AfterCommit,
}

impl Phase {
    /// Both phases.
    pub const ALL: [Self; 2] = [Self::BeforeCommit, Self::AfterCommit];
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BeforeCommit => "before commit of",
            Self::AfterCommit => "after commit of",
        })
    }
}

/// A simulated crash requested by a [`Failpoint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Crash;

/// Hooks around every boundary commit.
///
/// The default methods do nothing, so the production store runs with
/// [`NoFailpoints`]. A test implementation returns [`Crash`] at one hook;
/// the store then returns [`crate::Error::InjectedCrash`] without running
/// the rest of the operation, and the test drops the store to simulate the
/// process dying there.
pub trait Failpoint: Send + Sync {
    /// Called with the transaction built and not yet committed.
    ///
    /// # Errors
    ///
    /// [`Crash`] to abandon the transaction.
    fn before_commit(&self, boundary: Boundary) -> Result<(), Crash> {
        let _ = boundary;
        Ok(())
    }

    /// Called after the transaction committed durably.
    ///
    /// # Errors
    ///
    /// [`Crash`] to stop before the caller sees the result.
    fn after_commit(&self, boundary: Boundary) -> Result<(), Crash> {
        let _ = boundary;
        Ok(())
    }
}

/// The production failpoint: never fires.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFailpoints;

impl Failpoint for NoFailpoints {}
