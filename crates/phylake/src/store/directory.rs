//! Tenant, grant, revocation, and session writes.
//!
//! Each write is one transaction. Writes that answer a tenant request
//! (grant issue and revoke, session create and fork) append an audit entry
//! in the same transaction. Each is idempotent on its caller-chosen id: a
//! repeat with identical content returns the stored result and writes
//! nothing; a different record under the same id is
//! [`crate::Error::Conflict`].

use std::collections::BTreeSet;

use epitrope::{Grant, IssueContext, IssueDecision, Revocation, TargetScope, check_issue};
use snafu::{OptionExt as _, ResultExt as _, ensure};
use syntheke::{
    AuditScope, Capability, Ceilings, Failure, GrantId, GrantIssueRequest, InvocationId,
    InvocationState, OutcomeKind, SessionId, SessionOpened, SessionScope, TenantClass, TenantId,
    Timestamp,
};

use super::audit::AuditEntry;
use super::record_key::store as keys;
use super::records::{GrantRecord, RevocationRecord, SessionRecord, TenantRecord};
use super::view::View;
use super::{INITIAL_DATA_KEY_ID, Store, WriteTx, slot};
use crate::Result;
use crate::crypto::{Keyspace, TenantDataKey};
use crate::error::{AuthzSnafu, ConflictSnafu, TenantMissingSnafu, TenantShreddedSnafu};

/// A tenant to register.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TenantRegistration {
    /// The tenant.
    pub id: TenantId,
    /// Its class.
    pub class: TenantClass,
    /// Its Ed25519 verifying key.
    pub verifying_key: [u8; 32],
    /// The local user ids it may connect from.
    pub bound_uids: Vec<u32>,
    /// Its parent tenant, which must already be registered.
    pub parent: Option<TenantId>,
    /// Ceilings on its tenant ledger.
    pub ceilings: Ceilings,
}

impl TenantRegistration {
    /// A registration with no parent, no bound uids, and no ceilings.
    #[must_use]
    pub const fn new(id: TenantId, class: TenantClass, verifying_key: [u8; 32]) -> Self {
        Self {
            id,
            class,
            verifying_key,
            bound_uids: Vec::new(),
            parent: None,
            ceilings: Ceilings {
                wall_time_ms: None,
                fetches: None,
                bytes_transferred: None,
                output_bytes: None,
                tokens: None,
                ops_band: None,
            },
        }
    }
}

/// A root grant: no parent, depth 0, issued by its holder. Installed by
/// the operator's administration path, not through a tenant request.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RootGrant {
    /// The grant.
    pub id: GrantId,
    /// Its holder and issuer.
    pub holder: TenantId,
    /// Conferred capabilities.
    pub capabilities: BTreeSet<Capability>,
    /// Session scope.
    pub session_scope: SessionScope,
    /// Target origin patterns.
    pub target_scope: Vec<String>,
    /// Audit scope.
    pub audit_scope: AuditScope,
    /// Ceilings on the grant's ledger.
    pub ceilings: Ceilings,
    /// Start of validity.
    pub not_before: Timestamp,
    /// End of validity (exclusive).
    pub expires_at: Timestamp,
    /// The chain's maximum depth.
    pub max_depth: u8,
}

impl RootGrant {
    /// A root grant with every field given; see the field docs.
    #[must_use]
    pub const fn new(
        id: GrantId,
        holder: TenantId,
        capabilities: BTreeSet<Capability>,
        target_scope: Vec<String>,
        validity: (Timestamp, Timestamp),
        max_depth: u8,
    ) -> Self {
        Self {
            id,
            holder,
            capabilities,
            session_scope: SessionScope::Own,
            target_scope,
            audit_scope: AuditScope::OwnAndOwnedSessions,
            ceilings: Ceilings {
                wall_time_ms: None,
                fetches: None,
                bytes_transferred: None,
                output_bytes: None,
                tokens: None,
                ops_band: None,
            },
            not_before: validity.0,
            expires_at: validity.1,
            max_depth,
        }
    }

    fn to_grant(&self) -> Result<Grant> {
        Ok(Grant {
            id: self.id,
            issuer: self.holder,
            holder: self.holder,
            capabilities: self.capabilities.clone(),
            session_scope: self.session_scope.clone(),
            target_scope: TargetScope::parse(&self.target_scope).context(AuthzSnafu)?,
            audit_scope: self.audit_scope,
            ceilings: self.ceilings,
            not_before: self.not_before,
            expires_at: self.expires_at,
            parent: None,
            depth: 0,
            max_depth: self.max_depth,
        })
    }
}

/// A `GrantIssue` request, decided inside the writing transaction.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct GrantIssue<'a> {
    /// Issuer, designated parent, and the child's id.
    pub context: IssueContext,
    /// The child's requested shape.
    pub request: &'a GrantIssueRequest,
    /// The invocation the audit entry names.
    pub invocation: InvocationId,
}

impl<'a> GrantIssue<'a> {
    /// A grant issue request.
    #[must_use]
    pub const fn new(
        context: IssueContext,
        request: &'a GrantIssueRequest,
        invocation: InvocationId,
    ) -> Self {
        Self {
            context,
            request,
            invocation,
        }
    }
}

/// The result of [`Store::issue_grant`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IssueOutcome {
    /// The child grant is stored.
    Issued {
        /// The child.
        grant: GrantId,
        /// Its parent.
        parent: GrantId,
    },
    /// The request was refused; only the audit entry was written.
    Refused {
        /// What the caller observes.
        failure: Failure,
    },
}

/// A revocation, authorized by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RevokeGrant {
    /// The revoking tenant.
    pub actor: TenantId,
    /// The grant to revoke.
    pub grant: GrantId,
    /// The invocation the audit entry names.
    pub invocation: InvocationId,
}

impl RevokeGrant {
    /// A revocation of `grant` by `actor`.
    #[must_use]
    pub const fn new(actor: TenantId, grant: GrantId, invocation: InvocationId) -> Self {
        Self {
            actor,
            grant,
            invocation,
        }
    }
}

/// A session to open, authorized by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewSession {
    /// The new session.
    pub session: SessionId,
    /// Its owner: the acting tenant.
    pub owner: TenantId,
    /// Ceilings on its ledger.
    pub ceilings: Ceilings,
    /// The invocation the audit entry names.
    pub invocation: InvocationId,
}

impl NewSession {
    /// A session with no ceilings.
    #[must_use]
    pub const fn new(session: SessionId, owner: TenantId, invocation: InvocationId) -> Self {
        Self {
            session,
            owner,
            ceilings: Ceilings {
                wall_time_ms: None,
                fetches: None,
                bytes_transferred: None,
                output_bytes: None,
                tokens: None,
                ops_band: None,
            },
            invocation,
        }
    }
}

impl Store {
    /// Registers a tenant with a fresh random data key, wrapped under the
    /// store's key-encryption subkey.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TenantMissing`] for an unregistered parent,
    /// [`crate::Error::Conflict`] for a different tenant under the same id,
    /// [`crate::Error::TenantShredded`] for the id of a shredded tenant,
    /// [`crate::Error::Entropy`] when the data key cannot be drawn, or a
    /// storage failure.
    pub fn register_tenant(&self, registration: &TenantRegistration) -> Result<()> {
        let mut tx = self.write_tx();
        let id = registration.id;
        if let Some(existing) = self.tenant_record(&tx, id)? {
            ensure!(
                same_identity(&existing, registration),
                ConflictSnafu { what: "tenant" }
            );
            return Ok(());
        }
        ensure!(
            self.tombstone(&tx, id)?.is_none(),
            TenantShreddedSnafu { tenant: id }
        );
        if let Some(parent) = registration.parent {
            self.tenant_record(&tx, parent)?
                .context(TenantMissingSnafu { tenant: parent })?;
        }
        let wrapped = {
            let mut entropy = self
                .entropy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let data_key = TenantDataKey::generate_with(INITIAL_DATA_KEY_ID, &mut *entropy)?;
            self.keys
                .wrap_tenant_key_with(&id.to_bytes(), &data_key, &mut *entropy)?
        };
        let key_slot = keys::data_key(self.keys.index(), id, INITIAL_DATA_KEY_ID)?;
        tx.insert(self.ks.get(Keyspace::Keys)?, key_slot, wrapped);
        let record = TenantRecord {
            id,
            class: registration.class,
            verifying_key: registration.verifying_key,
            bound_uids: registration.bound_uids.clone(),
            parent: registration.parent,
            ceilings: registration.ceilings,
            data_key_id: INITIAL_DATA_KEY_ID.get(),
            registered_at: self.now(),
        };
        self.put_global(
            &mut tx,
            slot::TENANT,
            &keys::tenant(self.keys.index(), id)?,
            &record,
        )?;
        self.commit(tx, None)
    }

    /// Installs a root grant.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TenantMissing`] for an unregistered holder,
    /// [`crate::Error::Authz`] for a target pattern that does not parse,
    /// [`crate::Error::Conflict`] for a different grant under the same id,
    /// or a storage failure.
    pub fn install_root_grant(&self, root: &RootGrant) -> Result<()> {
        let grant = root.to_grant()?;
        let mut tx = self.write_tx();
        self.tenant_record(&tx, root.holder)?
            .context(TenantMissingSnafu {
                tenant: root.holder,
            })?;
        let record = GrantRecord::from_grant(&grant, root.target_scope.clone());
        if self.put_new_grant(&mut tx, &record)? {
            self.commit(tx, None)?;
        }
        Ok(())
    }

    /// Stages `record` unless the same grant exists; returns whether it
    /// staged a write.
    fn put_new_grant(&self, tx: &mut WriteTx<'_>, record: &GrantRecord) -> Result<bool> {
        let view = View {
            store: self,
            reader: &*tx,
        };
        if let Some(existing) = view.grant_record(record.id)? {
            ensure!(existing == *record, ConflictSnafu { what: "grant" });
            return Ok(false);
        }
        let key = keys::grant(self.keys.index(), record.id)?;
        self.put_global(tx, slot::GRANT, &key, record)?;
        Ok(true)
    }

    /// Decides and, when it attenuates its parent, stores a child grant.
    /// The decision reads the parent's ledger inside the writing
    /// transaction. Issued or refused, an audit entry records the call.
    ///
    /// A repeat of an issued request (same child id, issuer, parent, and
    /// shape) returns `Issued` and writes nothing, before any decision: the
    /// parent's remaining budget or validity may have moved since, and a
    /// stored grant is not re-decided.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Authz`] when the decision cannot be made (a broken
    /// chain, a failed read), [`crate::Error::Conflict`] for a different
    /// grant under the child's id, or a storage failure.
    pub fn issue_grant(&self, issue: &GrantIssue<'_>) -> Result<IssueOutcome> {
        let mut tx = self.write_tx();
        let decision = {
            let view = View {
                store: self,
                reader: &tx,
            };
            if let Some(existing) = view.grant_record(issue.context.child)?
                && existing.issuer == issue.context.issuer
                && existing.parent == Some(issue.context.designated)
            {
                ensure!(
                    issued_from(&view, &existing, issue.request)?,
                    ConflictSnafu { what: "grant" }
                );
                return Ok(IssueOutcome::Issued {
                    grant: existing.id,
                    parent: issue.context.designated,
                });
            }
            check_issue(&view, &issue.context, issue.request, &*self.clock).context(AuthzSnafu)?
        };
        let (outcome, state) = match decision {
            IssueDecision::Issued(child) => {
                let record = GrantRecord::from_grant(&child, issue.request.target_scope.clone());
                if !self.put_new_grant(&mut tx, &record)? {
                    return Ok(IssueOutcome::Issued {
                        grant: record.id,
                        parent: issue.context.designated,
                    });
                }
                let outcome = IssueOutcome::Issued {
                    grant: record.id,
                    parent: issue.context.designated,
                };
                (outcome, InvocationState::Settled)
            }
            refused => {
                let failure = refused.refusal().unwrap_or(Failure::NotFoundOrDenied);
                (IssueOutcome::Refused { failure }, InvocationState::Denied)
            }
        };
        let kind = match outcome {
            IssueOutcome::Issued { .. } => OutcomeKind::Success,
            IssueOutcome::Refused { failure } => failure.kind(),
        };
        let entry = AuditEntry::new(
            issue.context.issuer,
            issue.invocation,
            Capability::GrantIssue,
            state,
            kind,
        );
        self.append_audit(&mut tx, entry)?;
        self.commit(tx, None)?;
        Ok(outcome)
    }

    /// Records the revocation of a grant, with the audit sequence of the
    /// revoking call as its epoch. Revoking a revoked grant returns the
    /// first record and writes nothing.
    ///
    /// Returns `None` when the grant does not exist.
    ///
    /// # Errors
    ///
    /// A storage failure, or [`crate::Error::TenantMissing`] for an
    /// unregistered actor.
    pub fn revoke_grant(&self, revoke: &RevokeGrant) -> Result<Option<Revocation>> {
        let mut tx = self.write_tx();
        {
            let view = View {
                store: self,
                reader: &tx,
            };
            if view.grant_record(revoke.grant)?.is_none() {
                return Ok(None);
            }
            if let Some(existing) = view.revocation_record(revoke.grant)? {
                return Ok(Some(existing.to_revocation()));
            }
        }
        let entry = AuditEntry::new(
            revoke.actor,
            revoke.invocation,
            Capability::GrantRevoke,
            InvocationState::Settled,
            OutcomeKind::Success,
        );
        let at_seq = self.append_audit(&mut tx, entry)?;
        let record = RevocationRecord {
            grant: revoke.grant,
            at_seq,
            at_time: self.now(),
            by: revoke.actor,
        };
        let key = keys::revocation(self.keys.index(), revoke.grant)?;
        self.put_global(&mut tx, slot::REVOCATION, &key, &record)?;
        self.commit(tx, None)?;
        Ok(Some(record.to_revocation()))
    }

    /// Opens a new session owned by `new.owner`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TenantMissing`] for an unregistered owner,
    /// [`crate::Error::Conflict`] for a different session under the same
    /// id, or a storage failure.
    pub fn create_session(&self, new: &NewSession) -> Result<SessionOpened> {
        // NOTE: with no parent, `open_session` never reports a missing one.
        self.open_session(new, None)
            .map(|opened| opened.unwrap_or_else(|| session_opened(new, None)))
    }

    /// Forks `parent` into a new session owned by `new.owner`, recording
    /// the lineage. Returns `None` when `parent` does not exist.
    ///
    /// # Errors
    ///
    /// As [`Store::create_session`].
    pub fn fork_session(
        &self,
        new: &NewSession,
        parent: SessionId,
    ) -> Result<Option<SessionOpened>> {
        self.open_session(new, Some(parent))
    }

    fn open_session(
        &self,
        new: &NewSession,
        parent: Option<SessionId>,
    ) -> Result<Option<SessionOpened>> {
        let mut tx = self.write_tx();
        let opened = session_opened(new, parent);
        {
            let view = View {
                store: self,
                reader: &tx,
            };
            view.tenant_record(new.owner)?
                .context(TenantMissingSnafu { tenant: new.owner })?;
            if let Some(parent) = parent
                && view.session_record(parent)?.is_none()
            {
                return Ok(None);
            }
            if let Some(existing) = view.session_record(new.session)? {
                ensure!(
                    existing.owner == new.owner
                        && existing.parent == parent
                        && existing.ceilings == new.ceilings,
                    ConflictSnafu { what: "session" }
                );
                return Ok(Some(opened));
            }
        }
        let record = SessionRecord {
            id: new.session,
            owner: new.owner,
            parent,
            ceilings: new.ceilings,
            created_at: self.now(),
        };
        let key = keys::session(self.keys.index(), new.session)?;
        self.put_global(&mut tx, slot::SESSION, &key, &record)?;
        let capability = if parent.is_some() {
            Capability::SessionFork
        } else {
            Capability::SessionCreate
        };
        let entry = AuditEntry::new(
            new.owner,
            new.invocation,
            capability,
            InvocationState::Settled,
            OutcomeKind::Success,
        )
        .in_session(Some(new.session));
        self.append_audit(&mut tx, entry)?;
        self.commit(tx, None)?;
        Ok(Some(opened))
    }
}

/// The reply for `new`, forked from `parent`.
const fn session_opened(new: &NewSession, parent: Option<SessionId>) -> SessionOpened {
    SessionOpened {
        session: new.session,
        owner: new.owner,
        parent_session: parent,
    }
}

/// Whether the stored child grant `existing` is the one `request` asks
/// for under its stored parent.
fn issued_from<R: fjall::Readable>(
    view: &View<'_, R>,
    existing: &GrantRecord,
    request: &GrantIssueRequest,
) -> Result<bool> {
    let max_depth = match request.max_depth {
        Some(max_depth) => Some(max_depth),
        None => match existing.parent {
            Some(parent) => view.grant_record(parent)?.map(|parent| parent.max_depth),
            None => None,
        },
    };
    let capabilities: BTreeSet<Capability> = request.capabilities.iter().copied().collect();
    let stored: BTreeSet<Capability> = existing.capabilities.iter().copied().collect();
    Ok(existing.holder == request.holder
        && stored == capabilities
        && existing.session_scope == request.session_scope
        && existing.target_patterns == request.target_scope
        && existing.ceilings == request.ceilings
        && existing.not_before == request.not_before
        && existing.expires_at == request.expires_at
        && Some(existing.max_depth) == max_depth)
}

/// Whether a stored tenant is the one `registration` describes.
fn same_identity(existing: &TenantRecord, registration: &TenantRegistration) -> bool {
    existing.class == registration.class
        && existing.verifying_key == registration.verifying_key
        && existing.bound_uids == registration.bound_uids
        && existing.parent == registration.parent
        && existing.ceilings == registration.ceilings
}
