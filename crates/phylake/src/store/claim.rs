//! Idempotency claims for calls outside the capture lifecycle, standalone
//! audit entries, and the logical digest of the whole store.
//!
//! `SessionCreate`, `SessionFork`, `GrantIssue`, `GrantRevoke`, and
//! `Ingest` change durable state (or claim to) without the B1 to B5
//! lifecycle. Their idempotency entry is written by [`Store::claim`]
//! after authorization and before the call runs, in the same `idem`
//! keyspace [`Store::begin`] uses. The call itself is idempotent on the
//! invocation id the claim returns, so a crash between the claim and the
//! call is repaired by the replay: it finds the claim, reuses the id, and
//! the store returns the record the first attempt wrote, or writes it now.

use fjall::Readable as _;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use syntheke::{
    AuditSeq, Capability, Failure, GrantId, IdempotencyKey, InvocationId, InvocationState,
    SessionId, TenantId,
};

use super::audit::AuditEntry;
use super::record_key;
use super::records::{IdemRecord, Terminal};
use super::{ALL_KEYSPACES, Store, slot};
use crate::Result;
use crate::error::DatabaseSnafu;

/// A request to bind an idempotency key; see [`Store::claim`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct IdemClaim<'a> {
    /// The acting tenant.
    pub tenant: TenantId,
    /// The designated grant.
    pub grant: GrantId,
    /// The capability invoked.
    pub capability: Capability,
    /// The caller's idempotency key.
    pub key: &'a IdempotencyKey,
    /// The caller's digest of the request.
    pub request_digest: [u8; 32],
    /// The invocation id to bind when the key is unbound.
    pub invocation: InvocationId,
}

impl<'a> IdemClaim<'a> {
    /// A claim of `key` by `tenant` under `grant` for `invocation`.
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        grant: GrantId,
        capability: Capability,
        key: &'a IdempotencyKey,
        request_digest: [u8; 32],
        invocation: InvocationId,
    ) -> Self {
        Self {
            tenant,
            grant,
            capability,
            key,
            request_digest,
            invocation,
        }
    }

    /// The binding stored with the key: the caller's digest tied to the
    /// designated grant and the capability, so the same key under another
    /// grant conflicts whatever the caller's digest covers.
    fn binding(&self) -> [u8; 32] {
        let name = self.capability.name().as_bytes();
        Sha256::new()
            .chain_update(b"dioptron/v1/idem-claim")
            .chain_update(self.request_digest)
            .chain_update(self.grant.to_bytes())
            .chain_update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_le_bytes())
            .chain_update(name)
            .finalize()
            .into()
    }
}

/// The result of [`Store::claim`] and [`Store::claimed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Claimed {
    /// The key was unbound; it now names the claim's invocation.
    Fresh(InvocationId),
    /// The key already names this request; the invocation is the first
    /// attempt's.
    Replay(InvocationId),
    /// The key is bound to a different request. Nothing was written.
    Conflict,
}

/// How a call outside the lifecycle ended, for its audit entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditOutcome {
    /// Authorization refused the call (`Denied`, terminal).
    Refused(Failure),
    /// The call ran (`Settled`); a failure it answered with, if any.
    Completed(Option<Failure>),
}

/// One standalone audit entry; see [`Store::record_audit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditNote {
    /// The acting tenant.
    pub tenant: TenantId,
    /// The invocation the entry names.
    pub invocation: InvocationId,
    /// The capability invoked.
    pub capability: Capability,
    /// The session the caller named, if any.
    pub session: Option<SessionId>,
    /// How the call ended.
    pub outcome: AuditOutcome,
}

impl AuditNote {
    /// A note with no session.
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        invocation: InvocationId,
        capability: Capability,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            tenant,
            invocation,
            capability,
            session: None,
            outcome,
        }
    }
}

impl Store {
    /// Binds an idempotency key to a request, in one transaction.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TenantMissing`] for an unregistered tenant, or a
    /// storage, sealing, or decoding failure.
    pub fn claim(&self, claim: &IdemClaim<'_>) -> Result<Claimed> {
        let mut tx = self.write_tx();
        let keys = self.tenant_keys(&tx, claim.tenant)?;
        let idem_key =
            record_key::tenant::idem(keys.index(), claim.tenant, claim.capability, claim.key)?;
        let binding = claim.binding();
        if let Some(existing) =
            self.get::<IdemRecord, _>(&tx, slot::IDEM, &idem_key, &[keys.meta()])?
        {
            return Ok(compare(&existing, binding));
        }
        let record = IdemRecord {
            invocation: claim.invocation,
            request_binding: binding,
        };
        self.put(&mut tx, slot::IDEM, &idem_key, keys.meta(), &record)?;
        self.commit(tx, None)?;
        Ok(Claimed::Fresh(claim.invocation))
    }

    /// What [`Store::claim`] would find for `claim`, without writing:
    /// `None` when the key is unbound.
    ///
    /// # Errors
    ///
    /// As [`Store::claim`].
    pub fn claimed(&self, claim: &IdemClaim<'_>) -> Result<Option<Claimed>> {
        let snapshot = self.db.read_tx();
        let keys = self.tenant_keys(&snapshot, claim.tenant)?;
        let idem_key =
            record_key::tenant::idem(keys.index(), claim.tenant, claim.capability, claim.key)?;
        Ok(self
            .get::<IdemRecord, _>(&snapshot, slot::IDEM, &idem_key, &[keys.meta()])?
            .map(|existing| compare(&existing, claim.binding())))
    }

    /// Commits one audit entry on its own: the record of a refused call
    /// outside [`Store::begin`], or of a call that ran outside the
    /// lifecycle, such as an audited read.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TenantMissing`] for an unregistered tenant, or a
    /// storage or sealing failure.
    pub fn record_audit(&self, note: &AuditNote) -> Result<AuditSeq> {
        let entry = match note.outcome {
            AuditOutcome::Refused(failure) => AuditEntry::new(
                note.tenant,
                note.invocation,
                note.capability,
                InvocationState::Denied,
                failure.kind(),
            ),
            AuditOutcome::Completed(failure) => AuditEntry::terminal(
                note.tenant,
                note.invocation,
                note.capability,
                Terminal::Settled { failure },
            ),
        }
        .in_session(note.session);
        let mut tx = self.write_tx();
        let seq = self.append_audit(&mut tx, entry)?;
        self.commit(tx, None)?;
        Ok(seq)
    }

    /// A SHA-256 digest over every key and sealed value in every keyspace,
    /// in keyspace and key order.
    ///
    /// Two digests are equal exactly when the stored records are byte for
    /// byte the same, so a caller can prove an operation wrote nothing.
    /// The digest covers ciphertext only and reveals no plaintext.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn logical_digest(&self) -> Result<[u8; 32]> {
        let snapshot = self.db.read_tx();
        let mut hasher = Sha256::new();
        hasher.update(b"phylake-logical-digest-v1");
        for keyspace in ALL_KEYSPACES {
            let name = keyspace.name().as_bytes();
            hasher.update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(name);
            for guard in snapshot.iter(self.ks.get(keyspace)?) {
                let (key, value) = guard.into_inner().context(DatabaseSnafu)?;
                for part in [&*key, &*value] {
                    hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
                    hasher.update(part);
                }
            }
            // WHY a separator: the keyspace boundary is part of the digest.
            hasher.update([0xff]);
        }
        Ok(hasher.finalize().into())
    }
}

/// The claim result for a stored entry.
fn compare(existing: &IdemRecord, binding: [u8; 32]) -> Claimed {
    if existing.request_binding == binding {
        Claimed::Replay(existing.invocation)
    } else {
        Claimed::Conflict
    }
}
