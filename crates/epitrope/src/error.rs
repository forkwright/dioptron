//! The crate error type.

use snafu::Snafu;
use syntheke::{Capability, Dimension, GrantId, InvocationState, TenantId};

use crate::budget::Settlement;
use crate::lifecycle::Step;
use crate::view::ViewError;

/// Faults raised while deciding.
///
/// A refusal (a denied call, an exceeded budget, a narrowing violation) is a
/// decision, not an error, and is returned as a value. An `Error` means the
/// decision could not be made: the store's view failed, its records are
/// inconsistent, arithmetic would overflow, or a caller asked for a
/// transition the lifecycle forbids. Every caller fails closed on an
/// `Error`.
///
/// No variant carries a target or URL, so an error never echoes one into a
/// log.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum Error {
    /// The read-only view failed to answer.
    #[snafu(display("the authorization view failed to read"))]
    View {
        /// The view's own error.
        source: ViewError,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A grant names a parent the view does not hold.
    #[snafu(display("grant chain is broken: parent {grant} is missing"))]
    ChainBroken {
        /// The missing parent.
        grant: GrantId,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A link in a grant chain is inconsistent with its parent: its depth is
    /// not the parent's plus one, a root has a nonzero depth, or its issuer
    /// is not the parent's holder.
    #[snafu(display("grant chain is malformed at {grant}"))]
    ChainMalformed {
        /// The inconsistent link.
        grant: GrantId,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A tenant's parent chain is longer than [`crate::MAX_TENANT_LINEAGE`]
    /// links, which only a cycle or corrupt records produce.
    #[snafu(display("tenant lineage of {tenant} does not end"))]
    TenantLineage {
        /// The tenant whose lineage was walked.
        tenant: TenantId,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// An origin or origin pattern did not parse. The text itself is not
    /// carried.
    #[snafu(display("origin does not parse: {reason}"))]
    OriginSyntax {
        /// What was wrong, without the offending text.
        reason: &'static str,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Adding to a ledger would overflow `u64` on `dimension`.
    #[snafu(display("ledger overflow on {dimension}"))]
    LedgerOverflow {
        /// The overflowing dimension.
        dimension: Dimension,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Releasing from a ledger would take `dimension` below zero.
    #[snafu(display("ledger underflow on {dimension}"))]
    LedgerUnderflow {
        /// The underflowing dimension.
        dimension: Dimension,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Actual consumption exceeded the reservation on `dimension`.
    /// `settlement` is the clamped settlement the caller still applies: it
    /// debits at most the reserved amount on every dimension.
    #[snafu(display("settlement overrun on {dimension}: reserved {reserved}, actual {actual}"))]
    SettleOverrun {
        /// The first overrun dimension, in [`Dimension::ALL`] order.
        dimension: Dimension,
        /// Reserved amount on `dimension`.
        reserved: u64,
        /// Actual amount on `dimension`.
        actual: u64,
        /// The clamped settlement.
        settlement: Settlement,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The call names a session, and `capability` acts in none
    /// ([`crate::SessionRequirement::Forbidden`]). Its request body carries
    /// no session, so only a caller fault supplies one.
    #[snafu(display("{capability} acts in no session, and the call names one"))]
    SessionNotApplicable {
        /// The capability invoked.
        capability: Capability,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The lifecycle forbids `step` from `from`.
    #[snafu(display("illegal invocation transition: {step:?} from {from}"))]
    IllegalTransition {
        /// The current state.
        from: InvocationState,
        /// The requested step.
        step: Step,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },
}
