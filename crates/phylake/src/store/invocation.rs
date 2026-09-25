//! Invocation intent (B1), the dry-run plan, and the types the lifecycle
//! transactions share.

use epitrope::{AuthzRequest, Decision, ReservationPlan, authorize, plan, reserve};
use snafu::{OptionExt as _, ResultExt as _, ensure};
use syntheke::{
    ArtifactRef, AuditSeq, Capability, Cost, Failure, GrantId, IdempotencyKey, InvocationId,
    InvocationState, OutcomeKind, Plan, ReleaseReason, SessionId, SourceRef, TenantId,
};

use super::audit::AuditEntry;
use super::record_key;
use super::records::{IdemRecord, InvocationRecord, LedgerRecord, LedgerRef};
use super::view::View;
use super::{Boundary, Store, WriteTx, slot};
use crate::Result;
use crate::error::{AuthzSnafu, ConflictSnafu, InconsistentSnafu, InvocationMissingSnafu};

/// An `Execute` call to persist at B1.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Intent<'a> {
    /// The new invocation's id.
    pub invocation: InvocationId,
    /// Tenant, designated grant, capability, target, session, and the
    /// declared maximum cost.
    pub authz: AuthzRequest<'a>,
    /// The caller's idempotency key.
    pub idempotency_key: &'a IdempotencyKey,
    /// Digest of the request, including the designated grant.
    pub request_digest: [u8; 32],
}

impl<'a> Intent<'a> {
    /// An intent for `authz` under `idempotency_key`.
    #[must_use]
    pub const fn new(
        invocation: InvocationId,
        authz: AuthzRequest<'a>,
        idempotency_key: &'a IdempotencyKey,
        request_digest: [u8; 32],
    ) -> Self {
        Self {
            invocation,
            authz,
            idempotency_key,
            request_digest,
        }
    }
}

/// The result of [`Store::begin`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Begin {
    /// B1 committed: reservation, intent, and idempotency entry.
    Persisted(InvocationStatus),
    /// The idempotency key and digest match an existing invocation; nothing
    /// was written. The caller reports its current state and never
    /// dispatches it again.
    Replayed(InvocationStatus),
    /// The idempotency key is bound to a different request; nothing was
    /// written.
    Conflict,
    /// Authorization refused the call; the audit entry is the only write.
    Refused {
        /// What the caller observes.
        failure: Failure,
        /// The audit entry's sequence.
        audit_seq: AuditSeq,
    },
}

/// An invocation as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct InvocationStatus {
    /// The invocation.
    pub id: InvocationId,
    /// The acting tenant.
    pub tenant: TenantId,
    /// The capability invoked.
    pub capability: Capability,
    /// The session it acts in.
    pub session: Option<SessionId>,
    /// Its lifecycle state.
    pub state: InvocationState,
    /// Why it released its reservation, when `Released`.
    pub release_reason: Option<ReleaseReason>,
    /// The reply kind recorded at a terminal state.
    pub outcome: Option<OutcomeKind>,
    /// The failure recorded at a terminal state, if any.
    pub failure: Option<Failure>,
    /// The artifact written at B3 (visible from B4).
    pub artifact: Option<ArtifactRef>,
    /// The reservation debited from every ledger at B1.
    pub reserved: Cost,
    /// The amount kept as spent at B5.
    pub debited: Option<Cost>,
    /// The authorizing chain, leaf first.
    pub grant_chain: Vec<GrantId>,
    /// Whether the authorizing grant was revoked after the effect started.
    pub revoked_after_effect: bool,
}

impl From<&InvocationRecord> for InvocationStatus {
    fn from(record: &InvocationRecord) -> Self {
        Self {
            id: record.id,
            tenant: record.tenant,
            capability: record.capability,
            session: record.session,
            state: record.state,
            release_reason: record.release_reason,
            outcome: record.outcome,
            failure: record.failure,
            artifact: record.artifact,
            reserved: record.reserved,
            debited: record.debited,
            grant_chain: record.grant_chain.clone(),
            revoked_after_effect: record.revoked_after_effect,
        }
    }
}

/// What the producer returned, stored at B3.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Transfer<'a> {
    /// The artifact id the capture will publish under.
    pub artifact: ArtifactRef,
    /// The producer's envelope, stored verbatim.
    pub envelope: &'a [u8],
    /// Its evidence identity.
    pub source: SourceRef,
    /// The derived text view, already cut to the output bound.
    pub text_view: Option<String>,
    /// Whether `text_view` was cut.
    pub truncated: bool,
    /// Length of `text_view` in bytes.
    pub output_bytes: u64,
    /// Actual consumption, settled at B5.
    pub actual: Cost,
    /// Whether the authorizing grant was revoked after the effect started.
    pub revoked_after_effect: bool,
}

impl<'a> Transfer<'a> {
    /// A transfer of `envelope` into `artifact`, costing `actual`, with no
    /// text view.
    #[must_use]
    pub const fn new(
        artifact: ArtifactRef,
        envelope: &'a [u8],
        source: SourceRef,
        actual: Cost,
    ) -> Self {
        Self {
            artifact,
            envelope,
            source,
            text_view: None,
            truncated: false,
            output_bytes: 0,
            actual,
            revoked_after_effect: false,
        }
    }
}

/// How a B5 settlement ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SettleOutcome {
    /// From B4: the capture is published; settle the consumption recorded
    /// at B3.
    Success,
    /// From B2: the producer started and failed; settle `actual`.
    Failed {
        /// What the caller observes.
        failure: Failure,
        /// Actual consumption.
        actual: Cost,
    },
}

impl Store {
    /// The invocation `id`, or `None` when it has no record.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure.
    pub fn invocation(&self, id: InvocationId) -> Result<Option<InvocationStatus>> {
        let snapshot = self.db.read_tx();
        Ok(self
            .invocation_record(&snapshot, id)?
            .as_ref()
            .map(InvocationStatus::from))
    }

    /// Plans a dry-run over a read snapshot. Writes nothing, including no
    /// audit entry.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Authz`] when the decision cannot be made.
    pub fn plan(&self, request: &AuthzRequest<'_>) -> Result<Plan> {
        let snapshot = self.snapshot();
        plan(&snapshot, request, &*self.clock).context(AuthzSnafu)
    }

    /// B1: authorizes `intent` and, when allowed, commits the reservation
    /// against every ledger, the intent, and the idempotency entry in one
    /// transaction.
    ///
    /// Authorization reads the ledgers inside the writing transaction, and
    /// writers serialize, so two concurrent reservations cannot both spend
    /// the same remaining budget. A refused call writes its audit entry
    /// and nothing else. An idempotency key already bound to this request
    /// returns the stored invocation; bound to another, a conflict.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Authz`] when the decision cannot be made or a
    /// ledger would overflow, [`crate::Error::Conflict`] when the
    /// invocation id is taken, [`crate::Error::InjectedCrash`] from a
    /// failpoint, or a storage failure.
    pub fn begin(&self, intent: &Intent<'_>) -> Result<Begin> {
        let tenant = intent.authz.tenant;
        let mut tx = self.write_tx();
        let tenant_keys = self.tenant_keys(&tx, tenant)?;
        let idem_key = record_key::tenant::idem(
            tenant_keys.index(),
            tenant,
            intent.authz.capability,
            intent.idempotency_key,
        )?;
        if let Some(idem) =
            self.get::<IdemRecord, _>(&tx, slot::IDEM, &idem_key, &[tenant_keys.meta()])?
        {
            if idem.request_digest != intent.request_digest {
                return Ok(Begin::Conflict);
            }
            let record =
                self.invocation_record(&tx, idem.invocation)?
                    .context(InconsistentSnafu {
                        what: "idempotency entry names a missing invocation",
                    })?;
            return Ok(Begin::Replayed(InvocationStatus::from(&record)));
        }
        ensure!(
            self.invocation_record(&tx, intent.invocation)?.is_none(),
            ConflictSnafu { what: "invocation" }
        );
        let decision = {
            let view = View {
                store: self,
                reader: &tx,
            };
            authorize(&view, &intent.authz, &*self.clock).context(AuthzSnafu)?
        };
        let (chain, reservation) = match decision {
            Decision::Allowed { chain, reservation } => (chain, reservation),
            refused => {
                let failure = refused.refusal().unwrap_or(Failure::NotFoundOrDenied);
                let entry = AuditEntry::new(
                    tenant,
                    intent.invocation,
                    intent.authz.capability,
                    InvocationState::Denied,
                    failure.kind(),
                )
                .in_session(intent.authz.session);
                let audit_seq = self.append_audit(&mut tx, entry)?;
                self.commit(tx, None)?;
                return Ok(Begin::Refused { failure, audit_seq });
            }
        };
        let ledgers = self.debit_reservation(&mut tx, &reservation)?;
        let now = self.now();
        let record = InvocationRecord {
            id: intent.invocation,
            tenant,
            capability: intent.authz.capability,
            session: intent.authz.session,
            grant_chain: chain,
            ledgers,
            reserved: reservation.cost(),
            request_digest: intent.request_digest,
            state: InvocationState::IntentPersisted,
            release_reason: None,
            outcome: None,
            failure: None,
            actual: None,
            debited: None,
            artifact: None,
            revoked_after_effect: false,
            created_at: now,
            updated_at: now,
        };
        self.put_invocation(&mut tx, &record)?;
        let idem = IdemRecord {
            invocation: intent.invocation,
            request_digest: intent.request_digest,
        };
        self.put(&mut tx, slot::IDEM, &idem_key, tenant_keys.meta(), &idem)?;
        self.commit(tx, Some(Boundary::PersistIntent))?;
        Ok(Begin::Persisted(InvocationStatus::from(&record)))
    }

    /// Debits the reservation from every ledger it names.
    fn debit_reservation(
        &self,
        tx: &mut WriteTx<'_>,
        reservation: &ReservationPlan,
    ) -> Result<Vec<LedgerRef>> {
        let mut ledgers = Vec::with_capacity(reservation.ledgers().len());
        for (id, amount) in reservation.debits() {
            let ledger = LedgerRef::from_ledger_id(id).context(InconsistentSnafu {
                what: "ledger kind has no stored form",
            })?;
            let used = View {
                store: self,
                reader: &*tx,
            }
            .ledger(ledger)?;
            let used = reserve(&used, &amount).context(AuthzSnafu)?;
            self.put_ledger(tx, ledger, used)?;
            ledgers.push(ledger);
        }
        Ok(ledgers)
    }

    /// Stages a ledger's new `used` amount.
    pub(crate) fn put_ledger(
        &self,
        tx: &mut WriteTx<'_>,
        ledger: LedgerRef,
        used: Cost,
    ) -> Result<()> {
        let key = record_key::store::ledger(self.keys.index(), ledger)?;
        self.put_global(tx, slot::LEDGER, &key, &LedgerRecord { used })
    }

    /// The invocation record `id`.
    pub(crate) fn invocation_record<R: fjall::Readable>(
        &self,
        reader: &R,
        id: InvocationId,
    ) -> Result<Option<InvocationRecord>> {
        let key = record_key::store::invocation(self.keys.index(), id)?;
        self.get_global(reader, slot::INVOCATION, &key)
    }

    /// The invocation record `id`, which must exist.
    pub(crate) fn existing_invocation<R: fjall::Readable>(
        &self,
        reader: &R,
        id: InvocationId,
    ) -> Result<InvocationRecord> {
        self.invocation_record(reader, id)?
            .context(InvocationMissingSnafu { invocation: id })
    }

    /// Stages an invocation record.
    pub(crate) fn put_invocation(
        &self,
        tx: &mut WriteTx<'_>,
        record: &InvocationRecord,
    ) -> Result<()> {
        let key = record_key::store::invocation(self.keys.index(), record.id)?;
        self.put_global(tx, slot::INVOCATION, &key, record)
    }
}
