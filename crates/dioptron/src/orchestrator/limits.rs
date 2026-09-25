//! The limits a capture declares and runs under (contract § Daemon
//! limits).
//!
//! A limit the caller sets is kept, lowered to the daemon's cap on that
//! dimension. A limit the caller omits becomes the smallest remaining
//! ceiling on that dimension among the ledgers the caller owns (its tenant
//! ledger, the grants in the designated chain it holds, and the session
//! when it owns it), lowered to the same cap; no ceiling there declares
//! the cap. The result is the capture's declared reservation and the bound
//! the producer is handed, so a capture never reserves or transfers more
//! than it may.
//!
//! WHY own ledgers only: the declared limit is visible to the caller in a
//! plan and in replies, so defaulting to an ancestor grant's remaining
//! budget would disclose it. Ancestor ledgers only gate the reservation:
//! one that cannot cover the declared amount refuses the call as
//! `Denied{BudgetUnavailable}`, which names no dimension.
//!
//! The daemon caps:
//!
//! - transfer: [`max_transfer_bytes`], the largest envelope the custody
//!   store seals;
//! - output: the connection's reply payload budget, because the text view
//!   travels whole in one reply frame.

use epitrope::{caller_remaining, designated_chain};
use phylake::crypto::MAX_PLAINTEXT_LEN;
use snafu::ResultExt as _;
use syntheke::{Capability, CaptureLimits, Ceilings, Cost, SessionId};

use super::{Call, Inner};
use crate::error::{AuthzSnafu, Error};
use crate::producer::Producer;

/// The daemon's transfer cap: the largest envelope the custody store
/// seals ([`MAX_PLAINTEXT_LEN`]).
pub(super) fn max_transfer_bytes() -> u64 {
    u64::try_from(MAX_PLAINTEXT_LEN).unwrap_or(u64::MAX)
}

/// The declared maximum cost of a capture running under `limits`, both of
/// which [`Inner::capture_limits`] has set.
pub(super) fn capture_cost(limits: &CaptureLimits, deadline_ms: u32) -> Cost {
    Cost {
        wall_time_ms: u64::from(deadline_ms),
        fetches: 1,
        bytes_transferred: limits.max_transfer_bytes.unwrap_or(0),
        output_bytes: limits.max_output_bytes.unwrap_or(0),
        tokens: 0,
        ops_band: 0,
    }
}

/// One dimension's declared limit: the caller's, else its own ledgers'
/// remaining ceiling, else the cap; never above the cap.
pub(super) fn declared(requested: Option<u64>, remaining: Option<u64>, cap: u64) -> u64 {
    requested.or(remaining).unwrap_or(cap).min(cap)
}

impl<P: Producer> Inner<P> {
    /// The limits `call` captures under in `session`, with both fields
    /// set.
    pub(super) fn capture_limits(
        &self,
        call: &Call,
        session: SessionId,
        requested: CaptureLimits,
    ) -> Result<CaptureLimits, Error> {
        let remaining = self.own_remaining(call, session)?;
        Ok(CaptureLimits {
            max_output_bytes: Some(declared(
                requested.max_output_bytes,
                remaining.output_bytes,
                u64::from(call.payload_budget()),
            )),
            max_transfer_bytes: Some(declared(
                requested.max_transfer_bytes,
                remaining.bytes_transferred,
                max_transfer_bytes(),
            )),
        })
    }

    /// The remaining ceiling on each dimension across the caller's own
    /// ledgers for a capture under the designated grant in `session`, over
    /// a snapshot. A grant that cannot authorize a capture yields no
    /// ceilings; authorization refuses the call anyway.
    ///
    /// NOTE: another call may reserve between this snapshot and B1, which
    /// re-reads every ledger in its own transaction; a declared limit that
    /// no longer fits is then refused as a budget shortfall, never
    /// over-reserved.
    fn own_remaining(&self, call: &Call, session: SessionId) -> Result<Ceilings, Error> {
        let snapshot = self.store.snapshot();
        let decided = designated_chain(
            &snapshot,
            call.tenant,
            call.grant,
            Capability::Capture,
            &*self.clock,
        )
        .context(AuthzSnafu)?;
        let Ok(chain) = decided else {
            return Ok(Ceilings::default());
        };
        caller_remaining(&snapshot, call.tenant, &chain, Some(session)).context(AuthzSnafu)
    }
}
