//! The limits a capture declares and runs under (contract § Daemon
//! limits).
//!
//! A limit the caller sets is kept, lowered to the daemon's cap on that
//! dimension. A limit the caller omits becomes the smallest remaining
//! ceiling on that dimension across the designated grant's chain, lowered
//! to the same cap; a chain with no ceiling there declares the cap. The
//! result is the capture's declared reservation and the bound the producer
//! is handed, so a capture never reserves or transfers more than it may.
//!
//! The daemon caps:
//!
//! - transfer: [`max_transfer_bytes`], the largest envelope the custody
//!   store seals;
//! - output: the connection's reply payload budget, because the text view
//!   travels whole in one reply frame.

use epitrope::{LedgerId, LedgerView as _, designated_chain};
use phylake::crypto::MAX_PLAINTEXT_LEN;
use snafu::ResultExt as _;
use syntheke::{Capability, CaptureLimits, Ceilings, Cost};

use super::{Call, Inner};
use crate::error::{AuthzSnafu, Error, ViewSnafu};
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

/// One dimension's declared limit: the caller's, else the chain's
/// remaining ceiling, else the cap; never above the cap.
pub(super) fn declared(requested: Option<u64>, remaining: Option<u64>, cap: u64) -> u64 {
    requested.or(remaining).unwrap_or(cap).min(cap)
}

/// The tighter of two optional ceilings; `None` is no ceiling.
fn tighter(current: Option<u64>, next: Option<u64>) -> Option<u64> {
    match (current, next) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

impl<P: Producer> Inner<P> {
    /// The limits `call` captures under, with both fields set.
    pub(super) fn capture_limits(
        &self,
        call: &Call,
        requested: CaptureLimits,
    ) -> Result<CaptureLimits, Error> {
        let remaining = self.chain_remaining(call)?;
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

    /// The remaining ceiling on each dimension across the designated
    /// grant's chain, over a snapshot. A grant that cannot authorize a
    /// capture yields no ceilings; authorization refuses the call anyway.
    ///
    /// NOTE: another call may reserve between this snapshot and B1, which
    /// re-reads every ledger in its own transaction; a declared limit that
    /// no longer fits is then refused as a budget shortfall, never
    /// over-reserved.
    fn chain_remaining(&self, call: &Call) -> Result<Ceilings, Error> {
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
        let mut remaining = Ceilings::default();
        for link in &chain {
            let used = snapshot.used(LedgerId::Grant(link.id)).context(ViewSnafu)?;
            let left = |ceiling: Option<u64>, spent: u64| ceiling.map(|c| c.saturating_sub(spent));
            remaining.bytes_transferred = tighter(
                remaining.bytes_transferred,
                left(link.ceilings.bytes_transferred, used.bytes_transferred),
            );
            remaining.output_bytes = tighter(
                remaining.output_bytes,
                left(link.ceilings.output_bytes, used.output_bytes),
            );
        }
        Ok(remaining)
    }
}
