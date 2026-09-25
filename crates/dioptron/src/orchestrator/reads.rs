//! `Read`, `Query`, `AuditQuery`, and `Ingest` (contract § Read scopes,
//! § Query and read results, § Audit partitions).
//!
//! Each read authorizes the session it touches under the designated grant
//! before it reads, and each reply fits the connection's frame bound:
//! `Read` returns at most one frame's worth of the envelope per chunk, and
//! the pages are cut to what one frame holds. `Ingest` is refused at
//! authorization as `NotSupported`.

use epitrope::{GrantView as _, applied_audit_scope};
use phylake::store::{AuditNote, AuditOutcome, AuditQuery};
use snafu::ResultExt as _;
use syntheke::{
    ArtifactRef, AuditPage, AuditQueryRequest, AuditScope, Capability, Cost, DenyCode, Failure,
    Plan, QueryPage, QueryRequest, ReadRequest, ResponseBody,
};

use super::{Call, Inner, Reply};
use crate::error::{Error, StoreSnafu, ViewSnafu};
use crate::producer::Producer;

/// Encoded bytes one query result takes in a reply, with room to spare.
const QUERY_REF_BYTES: u32 = 32;

/// Encoded bytes one audit record takes in a reply, with room to spare.
const AUDIT_RECORD_BYTES: u32 = 160;

impl<P: Producer> Inner<P> {
    /// The decision for a call on the artifact `artifact`, whose session is
    /// the one checked. A missing artifact answers `NotFoundOrDenied` at
    /// the session check, after the grant, chain, and capability checks,
    /// exactly as a foreign one does.
    pub(super) fn artifact_plan(
        &self,
        call: &Call,
        capability: Capability,
        artifact: ArtifactRef,
    ) -> Result<Plan, Error> {
        let info = self.store.artifact(artifact).context(StoreSnafu)?;
        let session = info.and_then(|info| info.session);
        let mut plan = self.decide(&Self::authz(
            call,
            capability,
            None,
            session,
            Cost::default(),
        ))?;
        if session.is_none() && plan.refusal == Some(Failure::denied(DenyCode::SessionRequired)) {
            plan.refusal = Some(Failure::NotFoundOrDenied);
        }
        Ok(plan)
    }

    /// `Read`: one chunk of the verbatim envelope.
    pub(super) fn read(&self, call: &Call, read: &ReadRequest) -> Result<Reply, Error> {
        let plan = self.artifact_plan(call, Capability::Read, read.artifact_ref)?;
        if let Some(failure) = plan.refusal {
            // NOTE: the artifact's session is not recorded: the caller did
            // not supply it, and a refusal must not store what it hides.
            return self.deny(call, Capability::Read, None, failure);
        }
        let len = read.len.min(call.payload_budget());
        let chunk = self
            .store
            .read_artifact(read.artifact_ref, read.offset, len)
            .context(StoreSnafu)?;
        Ok(chunk.map_or_else(
            || Reply::failed(Failure::NotFoundOrDenied),
            |chunk| Reply {
                invocation: None,
                body: ResponseBody::Chunk(chunk),
            },
        ))
    }

    /// `Query`: the caller's session's artifacts whose text view contains
    /// the predicate (an empty predicate matches every artifact).
    pub(super) fn query(&self, call: &Call, query: &QueryRequest) -> Result<Reply, Error> {
        let session = query.session_scope;
        let authz = Self::authz(call, Capability::Query, None, session, Cost::default());
        if let Some(failure) = self.decide(&authz)?.refusal {
            return self.deny(call, Capability::Query, session, failure);
        }
        let Some(session) = session else {
            return Ok(Reply::failed(Failure::denied(DenyCode::SessionRequired)));
        };
        let limit = query.limit.min(call.payload_budget() / QUERY_REF_BYTES);
        let Some(page) = self
            .store
            .session_artifacts(session, None, u32::MAX)
            .context(StoreSnafu)?
        else {
            return Ok(Reply::failed(Failure::NotFoundOrDenied));
        };
        let mut matches = Vec::new();
        for artifact in page.result_refs {
            if self.matches(artifact, &query.predicate)? {
                matches.push(artifact);
            }
        }
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let more = matches.len() > limit;
        matches.truncate(limit);
        Ok(Reply {
            invocation: None,
            body: ResponseBody::QueryPage(QueryPage {
                result_refs: matches,
                more,
            }),
        })
    }

    /// Whether `artifact`'s text view contains `predicate`.
    fn matches(&self, artifact: ArtifactRef, predicate: &str) -> Result<bool, Error> {
        if predicate.is_empty() {
            return Ok(true);
        }
        Ok(self
            .store
            .artifact(artifact)
            .context(StoreSnafu)?
            .and_then(|info| info.text_view)
            .is_some_and(|text| text.contains(predicate)))
    }

    /// `AuditQuery`: records within the scope the designated grant allows.
    /// The read is itself audited.
    pub(super) fn audit_query(
        &self,
        call: &Call,
        request: &AuditQueryRequest,
    ) -> Result<Reply, Error> {
        let capability = Capability::AuditQuery;
        let session = request.session;
        let authz = Self::authz(call, capability, None, session, Cost::default());
        if let Some(failure) = self.decide(&authz)?.refusal {
            return self.deny(call, capability, session, failure);
        }
        let scope = self.audit_scope(call, request.audit_scope)?;
        let limit = request
            .limit
            .min(call.payload_budget() / AUDIT_RECORD_BYTES);
        // WHY one extra: a record beyond the limit is how the page knows
        // more remain.
        let mut query = AuditQuery::new(call.tenant, scope, limit.saturating_add(1));
        query.session = session;
        query.after = request.after;
        let mut records: Vec<_> = self
            .store
            .audit_query(&query)
            .context(StoreSnafu)?
            .into_iter()
            .map(|event| event.record)
            .collect();
        let more = records.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        records.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        let invocation = self.fresh_invocation()?;
        let mut note = AuditNote::new(
            call.tenant,
            invocation,
            capability,
            AuditOutcome::Completed(None),
        );
        note.session = session;
        note.grant = Some(call.grant);
        note.audit_scope = Some(scope);
        self.store.record_audit(&note).context(StoreSnafu)?;
        let next_after = if more {
            records.last().map(|record| record.seq)
        } else {
            None
        };
        let page = AuditPage {
            scope_applied: scope,
            records,
            next_after,
        };
        Ok(Reply::of(invocation, ResponseBody::AuditPage(page)))
    }

    /// The scope an audit read is answered with: the requested scope when
    /// the designated grant's covers it, otherwise the grant's.
    fn audit_scope(&self, call: &Call, requested: AuditScope) -> Result<AuditScope, Error> {
        let granted = self
            .store
            .snapshot()
            .grant(call.grant)
            .context(ViewSnafu)?
            .map_or(AuditScope::OwnAndOwnedSessions, |grant| grant.audit_scope);
        Ok(applied_audit_scope(requested, granted))
    }

    /// The decision for an `Ingest`: the designated-grant, chain, and
    /// capability checks, then `NotSupported` until the knowledge pipeline
    /// (D7) lands. The named artifact is never read, so a missing, a
    /// foreign, and an own artifact get the same answer.
    pub(super) fn ingest_plan(&self, call: &Call) -> Result<Plan, Error> {
        let authz = Self::authz(call, Capability::Ingest, None, None, Cost::default());
        let mut plan = self.decide(&authz)?;
        if plan.refusal.is_none() {
            // WHY: a build whose authorizer served Ingest would still have
            // no pipeline here; refusing is the closed side.
            plan.refusal = Some(Failure::denied(DenyCode::NotSupported));
            plan.grant_chain.clear();
        }
        Ok(plan)
    }

    /// `Ingest`: refused at authorization. The refusal's `Denied` audit
    /// entry is the only write; no idempotency key is bound and nothing is
    /// reserved.
    pub(super) fn ingest(&self, call: &Call) -> Result<Reply, Error> {
        let failure = self
            .ingest_plan(call)?
            .refusal
            .unwrap_or(Failure::denied(DenyCode::NotSupported));
        self.deny(call, Capability::Ingest, None, failure)
    }
}
