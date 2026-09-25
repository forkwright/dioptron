//! Dry-run: the plan an `Execute` of the same request would follow, over a
//! read snapshot (contract § Capabilities and mode, D17.16).
//!
//! Nothing here writes: no intent, no idempotency binding, no audit
//! entry, and the producer is never called. Each capability is decided by
//! the same check its `Execute` path runs first, so the plan reports the
//! refusal the call would get.

use syntheke::{Capability, Cost, GrantIssueRequest, Plan, RequestBody};

use super::capture::capture_cost;
use super::{Call, Inner, Reply};
use crate::error::Error;
use crate::producer::Producer;

impl<P: Producer> Inner<P> {
    /// The dry-run plan of `body`.
    pub(super) fn plan(&self, call: &Call, body: &RequestBody) -> Result<Reply, Error> {
        let zero = Cost::default();
        let plan = match body {
            RequestBody::Capture(capture) => {
                let declared = capture_cost(&capture.limits, call.deadline_ms);
                self.decide(&Self::authz(
                    call,
                    Capability::Capture,
                    Some(&capture.target),
                    Some(capture.session),
                    declared,
                ))?
            }
            RequestBody::SessionCreate => self.decide(&Self::authz(
                call,
                Capability::SessionCreate,
                None,
                None,
                zero,
            ))?,
            RequestBody::SessionFork(fork) => self.decide(&Self::authz(
                call,
                Capability::SessionFork,
                None,
                Some(fork.parent_session),
                zero,
            ))?,
            RequestBody::Query(query) => self.decide(&Self::authz(
                call,
                Capability::Query,
                None,
                query.session_scope,
                zero,
            ))?,
            RequestBody::AuditQuery(query) => self.decide(&Self::authz(
                call,
                Capability::AuditQuery,
                None,
                query.session,
                zero,
            ))?,
            RequestBody::Read(read) => {
                self.artifact_plan(call, Capability::Read, read.artifact_ref)?
            }
            RequestBody::Ingest(ingest) => {
                self.artifact_plan(call, Capability::Ingest, ingest.artifact_ref)?
            }
            RequestBody::GrantIssue(issue) => self.issue_plan(call, issue)?,
            RequestBody::GrantRevoke(revoke) => {
                let refusal = self.revoke_decision(call, revoke.target_grant)?.refusal();
                self.with_refusal(call, Capability::GrantRevoke, refusal)?
            }
            // WHY: a body a later contract version adds has no plan yet;
            // refusing it is the closed side.
            _ => return Ok(Reply::failed(syntheke::Failure::ProtocolError)),
        };
        Ok(Reply::plan(plan))
    }

    /// The plan of a `GrantIssue`: the narrowing decision, and on success
    /// the designated grant's chain.
    fn issue_plan(&self, call: &Call, issue: &GrantIssueRequest) -> Result<Plan, Error> {
        let refusal = self.issue_refusal(call, issue, syntheke::GrantId::from_bytes([0; 16]))?;
        self.with_refusal(call, Capability::GrantIssue, refusal)
    }

    /// A zero-cost plan for `capability` carrying `refusal`, or, when there
    /// is none, the designated grant's chain.
    fn with_refusal(
        &self,
        call: &Call,
        capability: Capability,
        refusal: Option<syntheke::Failure>,
    ) -> Result<Plan, Error> {
        if let Some(refusal) = refusal {
            return Ok(Plan {
                capability,
                cost: Cost::default(),
                grant_chain: Vec::new(),
                rule_chain: Vec::new(),
                refusal: Some(refusal),
            });
        }
        let mut plan = self.decide(&Self::authz(call, capability, None, None, Cost::default()))?;
        // NOTE: the designated-grant checks already passed above, so the
        // chain walk here only supplies the chain; its own verdict on the
        // capability is not the call's.
        plan.refusal = None;
        Ok(plan)
    }
}
