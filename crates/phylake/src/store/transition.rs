//! Lifecycle transactions B2 through B5.
//!
//! Each runs in one transaction that reads the invocation's current state
//! and asks epitrope's [`next_state`] whether the step is legal before it
//! writes anything, so a settlement or release commits exactly once: a
//! second attempt finds a terminal state and fails with
//! [`crate::Error::Authz`] wrapping `IllegalTransition`, leaving the
//! ledgers untouched.

use epitrope::{Settlement, Step, next_state, release, settle, unknown_effect_settlement};
use fjall::Readable as _;
use snafu::{OptionExt as _, ResultExt as _, ensure};
use syntheke::{DenyCode, Failure, InvocationId, InvocationState, OutcomeKind, ReleaseReason};

use super::audit::AuditEntry;
use super::invocation::{InvocationStatus, SettleOutcome, Transfer};
use super::record_key;
use super::records::{ArtifactRecord, InvocationRecord, LocatorRecord, SessionIndexRecord};
use super::view::View;
use super::{Boundary, Store, WriteTx, slot};
use crate::Result;
use crate::crypto::provenance_digest;
use crate::error::{
    AuthzSnafu, ConflictSnafu, DatabaseSnafu, InconsistentSnafu, SettleMismatchSnafu,
};

impl Store {
    /// Runs one state-checked step on `id` in one transaction: loads the
    /// record, checks `step` against the transition table, lets `apply`
    /// stage the step's writes, stores the record in its new state, and
    /// commits at `boundary`.
    fn transition<F>(
        &self,
        id: InvocationId,
        step: Step,
        boundary: Boundary,
        apply: F,
    ) -> Result<InvocationStatus>
    where
        F: FnOnce(&Self, &mut WriteTx<'_>, &mut InvocationRecord) -> Result<()>,
    {
        let mut tx = self.write_tx();
        let mut record = self.existing_invocation(&tx, id)?;
        let next = next_state(record.state, step).context(AuthzSnafu)?;
        apply(self, &mut tx, &mut record)?;
        record.state = next;
        record.updated_at = self.now();
        if next.is_terminal() {
            let outcome = record.outcome.context(InconsistentSnafu {
                what: "terminal state without an outcome",
            })?;
            let entry = AuditEntry::new(record.tenant, record.id, record.capability, next, outcome)
                .in_session(record.session);
            self.append_audit(&mut tx, entry)?;
        }
        self.put_invocation(&mut tx, &record)?;
        self.commit(tx, Some(boundary))?;
        Ok(InvocationStatus::from(&record))
    }

    /// B2: records dispatch before the producer is called.
    ///
    /// # Errors
    ///
    /// [`crate::Error::InvocationMissing`], [`crate::Error::Authz`] for an
    /// illegal step, [`crate::Error::InjectedCrash`], or a storage failure.
    pub fn dispatch(&self, id: InvocationId) -> Result<InvocationStatus> {
        self.transition(id, Step::Dispatch, Boundary::Dispatch, |_, _, _| Ok(()))
    }

    /// B3: writes the envelope as a tenant-sealed blob at its keyed address
    /// and a pending side record. Nothing points readers at either until
    /// B4, so neither is visible.
    ///
    /// # Errors
    ///
    /// As [`Store::dispatch`], plus [`crate::Error::Conflict`] when the
    /// artifact id is already published and
    /// [`crate::Error::PlaintextTooLarge`] for an oversized envelope.
    pub fn complete_transfer(
        &self,
        id: InvocationId,
        transfer: &Transfer<'_>,
    ) -> Result<InvocationStatus> {
        self.transition(
            id,
            Step::CompleteTransfer,
            Boundary::CompleteTransfer,
            |store, tx, record| store.stage_transfer(tx, record, transfer),
        )
    }

    fn stage_transfer(
        &self,
        tx: &mut WriteTx<'_>,
        record: &mut InvocationRecord,
        transfer: &Transfer<'_>,
    ) -> Result<()> {
        let locator = record_key::store::locator(self.keys.index(), transfer.artifact)?;
        ensure!(
            !tx.contains_key(self.ks.get(slot::LOCATOR.keyspace)?, locator)
                .context(DatabaseSnafu)?,
            ConflictSnafu { what: "artifact" }
        );
        let tenant_keys = self.tenant_keys(&*tx, record.tenant)?;
        let address = tenant_keys.blob_address(transfer.envelope)?;
        let blob_key = record_key::tenant::blob(tenant_keys.index(), record.tenant, &address)?;
        let blobs = self.ks.get(slot::BLOB.keyspace)?;
        // WHY skip an existing blob: the address is a keyed hash of the
        // plaintext, so an existing blob holds these exact bytes, and a
        // published blob is never rewritten.
        if !tx.contains_key(blobs, blob_key).context(DatabaseSnafu)? {
            let sealed =
                self.seal_bytes(tenant_keys.blob(), slot::BLOB, &blob_key, transfer.envelope)?;
            tx.insert(blobs, blob_key, sealed);
        }
        let pending = ArtifactRecord {
            artifact: transfer.artifact,
            invocation: record.id,
            tenant: record.tenant,
            session: record.session,
            grant_chain: record.grant_chain.clone(),
            reservation: record.id,
            classification: None,
            lineage: None,
            provenance_digest: *provenance_digest(transfer.envelope).as_bytes(),
            blob_address: *address.as_bytes(),
            blob_len: u64::try_from(transfer.envelope.len()).unwrap_or(u64::MAX),
            source: transfer.source.clone(),
            text_view: transfer.text_view.clone(),
            truncated: transfer.truncated,
            output_bytes: transfer.output_bytes,
            revoked_after_effect: transfer.revoked_after_effect,
            published_at: None,
        };
        let pending_key =
            record_key::tenant::pending(tenant_keys.index(), record.tenant, record.id)?;
        self.put(
            tx,
            slot::PENDING_ARTIFACT,
            &pending_key,
            tenant_keys.meta(),
            &pending,
        )?;
        record.artifact = Some(transfer.artifact);
        record.actual = Some(transfer.actual);
        record.revoked_after_effect = transfer.revoked_after_effect;
        Ok(())
    }

    /// B4, the atomic publish point: commits the side record, the artifact
    /// locator, the session index entry, and the state together, and
    /// removes the pending record.
    ///
    /// # Errors
    ///
    /// As [`Store::dispatch`], plus [`crate::Error::Inconsistent`] when the
    /// pending record is missing.
    pub fn publish(&self, id: InvocationId) -> Result<InvocationStatus> {
        self.transition(id, Step::Publish, Boundary::Publish, Self::stage_publish)
    }

    fn stage_publish(&self, tx: &mut WriteTx<'_>, record: &mut InvocationRecord) -> Result<()> {
        let tenant_keys = self.tenant_keys(&*tx, record.tenant)?;
        let pending_key =
            record_key::tenant::pending(tenant_keys.index(), record.tenant, record.id)?;
        let mut artifact: ArtifactRecord = self
            .get(
                &*tx,
                slot::PENDING_ARTIFACT,
                &pending_key,
                &[tenant_keys.meta()],
            )?
            .context(InconsistentSnafu {
                what: "transfer-complete invocation has no pending record",
            })?;
        let now = self.now();
        artifact.published_at = Some(now);
        let side_key =
            record_key::tenant::artifact(tenant_keys.index(), record.tenant, artifact.artifact)?;
        self.put(tx, slot::ARTIFACT, &side_key, tenant_keys.meta(), &artifact)?;
        tx.remove(self.ks.get(slot::PENDING_ARTIFACT.keyspace)?, pending_key);
        let locator = LocatorRecord {
            artifact: artifact.artifact,
            owner: record.tenant,
            session: record.session,
        };
        let locator_key = record_key::store::locator(self.keys.index(), artifact.artifact)?;
        self.put_global(tx, slot::LOCATOR, &locator_key, &locator)?;
        if let Some(session) = record.session {
            let owner = View {
                store: self,
                reader: &*tx,
            }
            .session_record(session)?
            .context(InconsistentSnafu {
                what: "invocation names a missing session",
            })?
            .owner;
            let owner_keys = self.tenant_keys(&*tx, owner)?;
            let prefix = record_key::tenant::session_index(owner_keys.index(), owner, session)?;
            let key = record_key::join(&prefix, &artifact.artifact.to_bytes());
            let entry = SessionIndexRecord {
                artifact: artifact.artifact,
                captured_by: record.tenant,
                published_at: now,
            };
            self.put(tx, slot::SESSION_INDEX, &key, owner_keys.meta(), &entry)?;
        }
        Ok(())
    }

    /// B5: settles the actual consumption and releases the remainder of
    /// the reservation to every ledger.
    ///
    /// `Success` settles a published capture at the consumption recorded
    /// at B3; `Failed` settles a dispatched call whose producer started
    /// and failed. Consumption above the reservation is clamped to it.
    ///
    /// # Errors
    ///
    /// As [`Store::dispatch`], plus [`crate::Error::SettleMismatch`] when
    /// the outcome does not fit the state.
    pub fn settle(&self, id: InvocationId, outcome: SettleOutcome) -> Result<InvocationStatus> {
        self.transition(id, Step::Settle, Boundary::Terminal, |store, tx, record| {
            let (actual, kind, failure) = match (record.state, outcome) {
                (InvocationState::Published, SettleOutcome::Success) => (
                    record.actual.context(InconsistentSnafu {
                        what: "published invocation has no recorded consumption",
                    })?,
                    OutcomeKind::Success,
                    None,
                ),
                (InvocationState::Dispatched, SettleOutcome::Failed { failure, actual }) => {
                    (actual, failure.kind(), Some(failure))
                }
                (state, _) => return SettleMismatchSnafu { state }.fail(),
            };
            let settlement = match settle(&record.reserved, &actual) {
                Ok(settlement) | Err(epitrope::Error::SettleOverrun { settlement, .. }) => {
                    settlement
                }
                Err(error) => return Err(error).context(AuthzSnafu),
            };
            record.actual = Some(actual);
            record.outcome = Some(kind);
            record.failure = failure;
            store.apply_settlement(tx, record, settlement)
        })
    }

    /// B5: releases the whole reservation for `reason`.
    ///
    /// # Errors
    ///
    /// As [`Store::dispatch`].
    pub fn release(&self, id: InvocationId, reason: ReleaseReason) -> Result<InvocationStatus> {
        self.transition(
            id,
            Step::Release(reason),
            Boundary::Terminal,
            |store, tx, record| {
                let failure = release_failure(reason);
                record.release_reason = Some(reason);
                record.outcome = Some(failure.kind());
                record.failure = Some(failure);
                let settlement = Settlement {
                    debit: syntheke::Cost::default(),
                    release: record.reserved,
                };
                store.apply_settlement(tx, record, settlement)
            },
        )
    }

    /// B5: charges the whole reservation as `UnknownEffect`, because a
    /// dispatched call's effect can be neither proven nor ruled out.
    ///
    /// # Errors
    ///
    /// As [`Store::dispatch`].
    pub fn mark_unknown_effect(&self, id: InvocationId) -> Result<InvocationStatus> {
        self.transition(
            id,
            Step::MarkUnknownEffect,
            Boundary::Terminal,
            |store, tx, record| {
                record.outcome = Some(OutcomeKind::UnknownEffect);
                record.failure = Some(Failure::UnknownEffect);
                let settlement = unknown_effect_settlement(&record.reserved);
                store.apply_settlement(tx, record, settlement)
            },
        )
    }

    /// Returns `settlement.release` to every ledger the reservation
    /// debited and records the debit.
    fn apply_settlement(
        &self,
        tx: &mut WriteTx<'_>,
        record: &mut InvocationRecord,
        settlement: Settlement,
    ) -> Result<()> {
        for &ledger in &record.ledgers {
            let used = View {
                store: self,
                reader: &*tx,
            }
            .ledger(ledger)?;
            let used = release(&used, &settlement.release).context(AuthzSnafu)?;
            self.put_ledger(tx, ledger, used)?;
        }
        record.debited = Some(settlement.debit);
        Ok(())
    }
}

/// The failure a caller observes for a released invocation.
///
/// WHY `Cancelled` for `Abandoned`: an abandoned call was never dispatched
/// and its caller never received a reply; a replay reports that it did
/// not run, which is what a cancellation before any effect means.
const fn release_failure(reason: ReleaseReason) -> Failure {
    match reason {
        ReleaseReason::Revoked => Failure::denied(DenyCode::GrantRevoked),
        ReleaseReason::ProducerUnavailable => Failure::ProducerUnavailable,
        ReleaseReason::DeadlineExceeded => Failure::DeadlineExceeded,
        _ => Failure::Cancelled,
    }
}
