//! Session and grant calls: `SessionCreate`, `SessionFork`, `GrantIssue`,
//! and `GrantRevoke`.
//!
//! Each runs outside the capture lifecycle, in this order:
//!
//! 1. A key already bound to another request is `IdempotencyConflict`; a
//!    key bound to this request re-authorizes the designated chain and
//!    then replays the first attempt's result when that result is stored.
//!    A chain that no longer authorizes the call is refused with the
//!    current reason, as a fresh call would be.
//! 2. The call is authorized under its designated grant over a snapshot;
//!    a refusal commits a `Denied` audit entry and binds nothing.
//! 3. The key is bound ([`phylake::Store::claim`]) to a fresh invocation
//!    id, which is also the id of the session or grant the call creates,
//!    so a replay after a crash between the claim and the write finds the
//!    same id and the store's own idempotency completes the write.

use epitrope::{GrantView as _, IssueContext, RevokeDecision, check_issue, check_revoke};
use phylake::store::{Claimed, GrantIssue, IdemClaim, IssueOutcome, NewSession, RevokeGrant};
use snafu::ResultExt as _;
use syntheke::{
    Capability, Cost, Failure, GrantId, GrantIssueRequest, GrantIssued, GrantRevoked,
    IdempotencyKey, InvocationId, ResponseBody, SessionId, SessionOpened,
};

use super::{Call, Inner, Reply};
use crate::error::{AuthzSnafu, Error, StoreSnafu, ViewSnafu};
use crate::producer::Producer;

/// What an idempotency key already names.
pub(super) enum Prior {
    /// Nothing: the key is unbound.
    Unbound,
    /// This request, under the first attempt's invocation.
    Replay(InvocationId),
}

impl<P: Producer> Inner<P> {
    /// Step 1: the key's binding, or the conflict reply.
    pub(super) fn prior(
        &self,
        call: &Call,
        capability: Capability,
        key: &IdempotencyKey,
    ) -> Result<Result<Prior, Reply>, Error> {
        let claim = IdemClaim::new(
            call.tenant,
            call.grant,
            capability,
            key,
            call.digest,
            InvocationId::from_bytes([0; 16]),
        );
        Ok(match self.store.claimed(&claim).context(StoreSnafu)? {
            None => Ok(Prior::Unbound),
            Some(Claimed::Replay(invocation)) => Ok(Prior::Replay(invocation)),
            Some(_) => Err(Reply::failed(Failure::IdempotencyConflict)),
        })
    }

    /// Step 3: binds the key and returns the invocation it names, or the
    /// conflict reply when a concurrent request bound it differently.
    pub(super) fn bind(
        &self,
        call: &Call,
        capability: Capability,
        key: &IdempotencyKey,
    ) -> Result<Result<InvocationId, Reply>, Error> {
        let claim = IdemClaim::new(
            call.tenant,
            call.grant,
            capability,
            key,
            call.digest,
            self.fresh_invocation()?,
        );
        Ok(match self.store.claim(&claim).context(StoreSnafu)? {
            Claimed::Fresh(invocation) | Claimed::Replay(invocation) => Ok(invocation),
            _ => Err(Reply::failed(Failure::IdempotencyConflict)),
        })
    }

    /// `SessionCreate`: a new session owned by the caller.
    pub(super) fn session_create(&self, call: &Call) -> Result<Reply, Error> {
        self.open_session(call, None)
    }

    /// `SessionFork`: a new session with `parent` as its lineage.
    pub(super) fn session_fork(&self, call: &Call, parent: SessionId) -> Result<Reply, Error> {
        self.open_session(call, Some(parent))
    }

    fn open_session(&self, call: &Call, parent: Option<SessionId>) -> Result<Reply, Error> {
        let capability = if parent.is_some() {
            Capability::SessionFork
        } else {
            Capability::SessionCreate
        };
        let Some(key) = &call.key else {
            return Ok(Reply::failed(Failure::ProtocolError));
        };
        match self.prior(call, capability, key)? {
            Err(reply) => return Ok(reply),
            Ok(Prior::Replay(invocation)) => {
                if let Some(failure) = self.replay_refusal(call, capability)? {
                    return self.deny(call, capability, parent, failure);
                }
                if let Some(reply) = self.stored_session(call, invocation, parent)? {
                    return Ok(reply);
                }
            }
            Ok(Prior::Unbound) => {}
        }
        let authz = Self::authz(call, capability, None, parent, Cost::default());
        if let Some(failure) = self.decide(&authz)?.refusal {
            return self.deny(call, capability, parent, failure);
        }
        let invocation = match self.bind(call, capability, key)? {
            Ok(invocation) => invocation,
            Err(reply) => return Ok(reply),
        };
        let new = NewSession::new(
            SessionId::from_bytes(invocation.to_bytes()),
            call.tenant,
            invocation,
        );
        let opened = match parent {
            None => Some(self.store.create_session(&new).context(StoreSnafu)?),
            Some(parent) => self.store.fork_session(&new, parent).context(StoreSnafu)?,
        };
        Ok(opened.map_or_else(
            || Reply::failed(Failure::NotFoundOrDenied),
            |opened| Reply::of(invocation, ResponseBody::SessionOpened(opened)),
        ))
    }

    /// The session a replayed call already opened, if it is stored.
    fn stored_session(
        &self,
        call: &Call,
        invocation: InvocationId,
        parent: Option<SessionId>,
    ) -> Result<Option<Reply>, Error> {
        let session = SessionId::from_bytes(invocation.to_bytes());
        let owner = self
            .store
            .snapshot()
            .session_owner(session)
            .context(ViewSnafu)?;
        Ok((owner == Some(call.tenant)).then(|| {
            let opened = SessionOpened {
                session,
                owner: call.tenant,
                parent_session: parent,
            };
            Reply::of(invocation, ResponseBody::SessionOpened(opened))
        }))
    }

    /// `GrantIssue`: a child of the designated grant.
    pub(super) fn grant_issue(
        &self,
        call: &Call,
        request: &GrantIssueRequest,
    ) -> Result<Reply, Error> {
        let capability = Capability::GrantIssue;
        let Some(key) = &call.key else {
            return Ok(Reply::failed(Failure::ProtocolError));
        };
        match self.prior(call, capability, key)? {
            Err(reply) => return Ok(reply),
            Ok(Prior::Replay(invocation)) => {
                if let Some(failure) = self.replay_refusal(call, capability)? {
                    return self.deny(call, capability, None, failure);
                }
                let child = GrantId::from_bytes(invocation.to_bytes());
                if self
                    .store
                    .snapshot()
                    .grant(child)
                    .context(ViewSnafu)?
                    .is_some()
                {
                    return Ok(issued(invocation, child, call.grant));
                }
            }
            Ok(Prior::Unbound) => {}
        }
        if let Some(failure) = self.issue_refusal(call, request, GrantId::from_bytes([0; 16]))? {
            return self.deny(call, capability, None, failure);
        }
        let invocation = match self.bind(call, capability, key)? {
            Ok(invocation) => invocation,
            Err(reply) => return Ok(reply),
        };
        let context = IssueContext {
            issuer: call.tenant,
            designated: call.grant,
            child: GrantId::from_bytes(invocation.to_bytes()),
        };
        let outcome = self
            .store
            .issue_grant(&GrantIssue::new(context, request, invocation))
            .context(StoreSnafu)?;
        Ok(match outcome {
            IssueOutcome::Issued { grant, parent } => issued(invocation, grant, parent),
            IssueOutcome::Refused { failure } => Reply::failed(failure),
            _ => Reply::failed(Failure::UnknownEffect),
        })
    }

    /// The refusal a `GrantIssue` under the designated grant would get, over
    /// a snapshot.
    pub(super) fn issue_refusal(
        &self,
        call: &Call,
        request: &GrantIssueRequest,
        child: GrantId,
    ) -> Result<Option<Failure>, Error> {
        let context = IssueContext {
            issuer: call.tenant,
            designated: call.grant,
            child,
        };
        let snapshot = self.store.snapshot();
        Ok(check_issue(&snapshot, &context, request, &*self.clock)
            .context(AuthzSnafu)?
            .refusal())
    }

    /// The revocation decision of `target` under the designated grant.
    pub(super) fn revoke_decision(
        &self,
        call: &Call,
        target: GrantId,
    ) -> Result<RevokeDecision, Error> {
        let snapshot = self.store.snapshot();
        check_revoke(&snapshot, call.tenant, call.grant, target, &*self.clock).context(AuthzSnafu)
    }

    /// `GrantRevoke`: revokes `target` and cancels the running calls its
    /// chain authorizes.
    pub(super) fn grant_revoke(&self, call: &Call, target: GrantId) -> Result<Reply, Error> {
        let capability = Capability::GrantRevoke;
        let Some(key) = &call.key else {
            return Ok(Reply::failed(Failure::ProtocolError));
        };
        match self.prior(call, capability, key)? {
            Err(reply) => return Ok(reply),
            Ok(Prior::Replay(invocation)) => {
                if let Some(failure) = self.replay_refusal(call, capability)? {
                    return self.deny(call, capability, None, failure);
                }
                let existing = self
                    .store
                    .snapshot()
                    .revocation(target)
                    .context(ViewSnafu)?;
                if let Some(record) = existing {
                    return Ok(revoked(invocation, &record));
                }
            }
            Ok(Prior::Unbound) => {}
        }
        let decision = self.revoke_decision(call, target)?;
        if let Some(failure) = decision.refusal() {
            return self.deny(call, capability, None, failure);
        }
        let invocation = match self.bind(call, capability, key)? {
            Ok(invocation) => invocation,
            Err(reply) => return Ok(reply),
        };
        let record = match decision {
            RevokeDecision::AlreadyRevoked { record } => Some(record),
            _ => self
                .store
                .revoke_grant(&RevokeGrant::new(call.tenant, target, invocation))
                .context(StoreSnafu)?,
        };
        let Some(record) = record else {
            return Ok(Reply::failed(Failure::NotFoundOrDenied));
        };
        self.cancel_revoked(target);
        Ok(revoked(invocation, &record))
    }
}

/// The reply for an issued child grant.
fn issued(invocation: InvocationId, grant: GrantId, parent_grant: GrantId) -> Reply {
    Reply::of(
        invocation,
        ResponseBody::GrantIssued(GrantIssued {
            grant,
            parent_grant,
        }),
    )
}

/// The reply for a revocation record.
fn revoked(invocation: InvocationId, record: &epitrope::Revocation) -> Reply {
    Reply::of(
        invocation,
        ResponseBody::GrantRevoked(GrantRevoked {
            revoked_grant: record.grant,
            effect_sequence: record.at_seq,
            effect_time: record.at_time,
        }),
    )
}
