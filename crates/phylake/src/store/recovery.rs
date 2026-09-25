//! Restart recovery: bring every non-terminal invocation to one known
//! state, never calling the producer.
//!
//! The action for each state is epitrope's [`recovery_action`]: B1 is
//! released as `Abandoned`, B2 becomes `UnknownEffect` (the reservation is
//! charged, the call is never dispatched again), B3 rolls forward to
//! publish and settle, B4 rolls forward to settle. Each step is the same
//! state-checked transaction the live path uses, so recovery is
//! idempotent: a second run finds only terminal states and writes nothing.

use epitrope::{RecoveryAction, recovery_action};
use fjall::Readable as _;
use snafu::ResultExt as _;
use syntheke::{InvocationId, ReleaseReason};

use super::codec::StoredRecord as _;
use super::invocation::SettleOutcome;
use super::records::InvocationRecord;
use super::{Store, slot};
use crate::Result;
use crate::error::DatabaseSnafu;

/// What one recovery run did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryReport {
    /// B1 invocations released as `Abandoned`.
    pub released: u32,
    /// B2 invocations charged as `UnknownEffect`.
    pub unknown_effect: u32,
    /// B3 invocations published and settled.
    pub published: u32,
    /// B4 invocations settled.
    pub settled: u32,
}

impl RecoveryReport {
    /// Whether the run changed nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.released == 0 && self.unknown_effect == 0 && self.published == 0 && self.settled == 0
    }
}

impl Store {
    /// Scans every invocation and applies the recovery action to each one
    /// not in a terminal state.
    ///
    /// PERF: the scan reads every invocation record, terminal ones
    /// included. An index of open invocations would bound it by the number
    /// in flight; Phase 01 volumes do not need one.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure, or
    /// [`crate::Error::InjectedCrash`] when a failpoint is installed.
    pub fn recover(&self) -> Result<RecoveryReport> {
        let mut report = RecoveryReport::default();
        for (id, action) in self.open_invocations()? {
            match action {
                RecoveryAction::ReleaseAbandoned => {
                    self.release(id, ReleaseReason::Abandoned)?;
                    report.released = report.released.saturating_add(1);
                }
                RecoveryAction::MarkUnknownEffect => {
                    self.mark_unknown_effect(id)?;
                    report.unknown_effect = report.unknown_effect.saturating_add(1);
                }
                RecoveryAction::RollForwardPublish => {
                    self.publish(id)?;
                    self.settle(id, SettleOutcome::Success)?;
                    report.published = report.published.saturating_add(1);
                }
                RecoveryAction::RollForwardSettle => {
                    self.settle(id, SettleOutcome::Success)?;
                    report.settled = report.settled.saturating_add(1);
                }
                // WHY skip: an action a later epitrope adds has no store
                // step yet; leaving the invocation open is the closed side.
                _ => {}
            }
        }
        Ok(report)
    }

    /// Every invocation with a recovery action, from one snapshot.
    fn open_invocations(&self) -> Result<Vec<(InvocationId, RecoveryAction)>> {
        let snapshot = self.db.read_tx();
        let mut open = Vec::new();
        for guard in snapshot.iter(self.ks.get(slot::INVOCATION.keyspace)?) {
            let (key, sealed) = guard.into_inner().context(DatabaseSnafu)?;
            let plain = Self::open_bytes(&[self.keys.meta()], slot::INVOCATION, &key, &sealed)?;
            let record = InvocationRecord::decode(&plain, slot::INVOCATION.keyspace.name())?;
            if let Some(action) = recovery_action(record.state) {
                open.push((record.id, action));
            }
        }
        Ok(open)
    }
}
