//! Idempotency claims for calls outside the capture lifecycle, standalone
//! audit entries, and the logical digest of the whole store.
//!
//! `SessionCreate`, `SessionFork`, `GrantIssue`, `GrantRevoke`, and
//! `Ingest` change durable state (or claim to) without the B1 to B5
//! lifecycle. Their idempotency entry is written by [`Store::claim`]
//! before the call runs, in the same `idem` keyspace [`Store::begin`]
//! uses. The call itself is idempotent on the invocation id the claim
//! returns, so a crash between the claim and the call is repaired by the
//! replay: it finds the claim, reuses the id, and the store returns the
//! record the first attempt wrote, or writes it now.

use fjall::Readable as _;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use syntheke::{AuditSeq, Capability, IdempotencyKey, InvocationId, TenantId};

use super::audit::AuditEntry;
use super::record_key;
use super::records::IdemRecord;
use super::{ALL_KEYSPACES, Store, slot};
use crate::Result;
use crate::error::DatabaseSnafu;

/// A request to bind an idempotency key; see [`Store::claim`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct IdemClaim<'a> {
    /// The acting tenant.
    pub tenant: TenantId,
    /// The capability invoked.
    pub capability: Capability,
    /// The caller's idempotency key.
    pub key: &'a IdempotencyKey,
    /// Digest of the request, including the designated grant.
    pub request_digest: [u8; 32],
    /// The invocation id to bind when the key is unbound.
    pub invocation: InvocationId,
}

impl<'a> IdemClaim<'a> {
    /// A claim of `key` for `invocation`.
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        capability: Capability,
        key: &'a IdempotencyKey,
        request_digest: [u8; 32],
        invocation: InvocationId,
    ) -> Self {
        Self {
            tenant,
            capability,
            key,
            request_digest,
            invocation,
        }
    }
}

/// The result of [`Store::claim`].
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
        if let Some(existing) =
            self.get::<IdemRecord, _>(&tx, slot::IDEM, &idem_key, &[keys.meta()])?
        {
            return Ok(if existing.request_digest == claim.request_digest {
                Claimed::Replay(existing.invocation)
            } else {
                Claimed::Conflict
            });
        }
        let record = IdemRecord {
            invocation: claim.invocation,
            request_digest: claim.request_digest,
        };
        self.put(&mut tx, slot::IDEM, &idem_key, keys.meta(), &record)?;
        self.commit(tx, None)?;
        Ok(Claimed::Fresh(claim.invocation))
    }

    /// Commits one audit entry on its own: the record of a refused call
    /// outside [`Store::begin`], or of a read that is itself audited.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TenantMissing`] for an unregistered tenant, or a
    /// storage or sealing failure.
    pub fn record_audit(&self, entry: AuditEntry) -> Result<AuditSeq> {
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
