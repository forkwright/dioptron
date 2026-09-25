//! Ingest refused as not supported, audit entries that record the grant
//! and scope, declared capture limits, the query predicate, and the
//! release of a call whose step failed inside the daemon.

use std::sync::Arc;

use phylake::store::{AuditQuery, Intent, Terminal};
use syntheke::{
    ArtifactRef, AuditQueryRequest, AuditScope, Capability, CaptureLimits, CaptureRequest,
    Ceilings, DenyCode, Failure, IngestRequest, InvocationId, InvocationState, Mode, Plan,
    QueryRequest, ReleaseReason, RequestBody, ResponseBody, TransferClass,
};

use super::super::test_support::{
    AGENT, OK, OPERATOR, ROOT, Rig, SESSION, child, far, idem, signal,
};
use super::{failure, run};

/// `max_frame - 1024`: the reply payload budget the orchestrator
/// reserves, written out independently.
fn payload(max_frame: u32) -> u64 {
    u64::from(max_frame).saturating_sub(1_024)
}

fn ingest(artifact: ArtifactRef) -> RequestBody {
    RequestBody::Ingest(IngestRequest {
        artifact_ref: artifact,
    })
}

#[tokio::test]
async fn ingest_is_refused_not_supported_with_only_a_denied_audit_entry() {
    let rig = Rig::new();
    let first = run(&rig, "ingest-source", OK).await;
    let ResponseBody::Captured(outcome) = first.body else {
        panic!("capture failed");
    };
    let pinned = |key: &str, artifact| {
        let mut request = rig.request(ROOT, Some(key), Mode::Execute, ingest(artifact));
        request.request_id = 9;
        request
    };
    let own = pinned("ingest-key", outcome.artifact_ref);
    let missing = pinned("ingest-key", ArtifactRef::from_bytes([3; 16]));
    let audit_before = rig
        .store
        .audit_records(OPERATOR, None, 1_000)
        .expect("audit")
        .len();

    let own = rig.call(OPERATOR, own).await;
    let missing = rig.call(OPERATOR, missing).await;
    let planned = rig
        .call(
            OPERATOR,
            rig.request(ROOT, None, Mode::DryRun, ingest(outcome.artifact_ref)),
        )
        .await;

    assert_eq!(
        own.body,
        ResponseBody::Failed(Failure::denied(DenyCode::NotSupported)),
        "Ingest is defined and not served in Phase 01"
    );
    assert_eq!(own.invocation, None, "a refusal names no invocation");
    assert_eq!(
        syntheke::encode(&own).expect("encode").as_slice(),
        syntheke::encode(&missing).expect("encode").as_slice(),
        "an own and a missing artifact answer the same bytes, and the key \
         was never bound (no conflict for the second artifact)"
    );
    let ResponseBody::Plan(Plan { refusal, .. }) = planned.body else {
        panic!("no plan: {planned:?}");
    };
    assert_eq!(
        refusal,
        Some(Failure::denied(DenyCode::NotSupported)),
        "a dry-run plans the same refusal"
    );
    let audit = rig
        .store
        .audit_records(OPERATOR, None, 1_000)
        .expect("audit");
    let added: Vec<_> = audit.iter().skip(audit_before).collect();
    assert_eq!(added.len(), 2, "one audit entry per executed ingest");
    assert!(
        added
            .iter()
            .all(|event| event.record.state == InvocationState::Denied
                && event.record.capability == Capability::Ingest
                && event.grant == Some(ROOT)),
        "each is a Denied entry naming the designated grant: {added:?}"
    );
    assert_eq!(rig.producer.calls(), 1, "only the source capture ran");
}

#[tokio::test]
async fn audit_reads_record_the_designated_grant_and_the_applied_scope() {
    let rig = Rig::new();
    let grant = rig.agent_grant(vec![Capability::AuditQuery]).await;
    let query = |scope| {
        RequestBody::AuditQuery(AuditQueryRequest {
            audit_scope: scope,
            session: None,
            after: None,
            limit: 10,
        })
    };

    let agent = rig
        .call(
            AGENT,
            rig.request(grant, None, Mode::Execute, query(AuditScope::All)),
        )
        .await;
    let operator = rig
        .call(
            OPERATOR,
            rig.request(ROOT, None, Mode::Execute, query(AuditScope::All)),
        )
        .await;

    let entry = |id: Option<InvocationId>| {
        let id = id.expect("an audit read names its invocation");
        rig.store
            .audit_query(&AuditQuery::new(OPERATOR, AuditScope::All, 1_000))
            .expect("audit")
            .into_iter()
            .find(|event| event.record.invocation == id)
            .expect("the read was audited")
    };
    let agent_entry = entry(agent.invocation);
    let operator_entry = entry(operator.invocation);
    assert_eq!(
        (agent_entry.grant, agent_entry.audit_scope),
        (Some(grant), Some(AuditScope::OwnAndOwnedSessions)),
        "the agent's read records its grant and the narrowed scope"
    );
    assert_eq!(
        (operator_entry.grant, operator_entry.audit_scope),
        (Some(ROOT), Some(AuditScope::All)),
        "the operator's read records the root grant and All"
    );
}

/// The declared cost of a dry-run capture of `target` with `limits`
/// under `grant`, on a connection whose frame bound is `max_frame`.
async fn planned_cost(
    rig: &Rig,
    grant: syntheke::GrantId,
    limits: CaptureLimits,
    max_frame: u32,
) -> syntheke::Cost {
    let body = RequestBody::Capture(CaptureRequest {
        session: SESSION,
        target: OK.to_owned(),
        limits,
        egress_policy: None,
    });
    let request = rig.request(grant, None, Mode::DryRun, body);
    let (_handle, cancel) = signal();
    let response = rig
        .call_with(OPERATOR, request, cancel, far(), max_frame)
        .await;
    let ResponseBody::Plan(plan) = response.body else {
        panic!("no plan: {response:?}");
    };
    assert_eq!(plan.refusal, None, "the capture would run");
    plan.cost
}

const UNSET: CaptureLimits = CaptureLimits {
    max_output_bytes: None,
    max_transfer_bytes: None,
};

#[tokio::test]
async fn unset_limits_without_a_ceiling_declare_the_daemon_caps() {
    let rig = Rig::new();

    let default_frame = planned_cost(&rig, ROOT, UNSET, 1 << 20).await;
    let small_frame = planned_cost(&rig, ROOT, UNSET, 4_096).await;
    let above_caps = planned_cost(
        &rig,
        ROOT,
        CaptureLimits {
            max_output_bytes: Some(u64::MAX),
            max_transfer_bytes: Some(u64::MAX),
        },
        4_096,
    )
    .await;

    assert_eq!(
        default_frame.bytes_transferred,
        64 * 1024 * 1024,
        "the store's largest sealed envelope"
    );
    assert_eq!(
        default_frame.output_bytes,
        payload(1 << 20),
        "one reply frame's payload"
    );
    assert_eq!(
        small_frame.output_bytes,
        payload(4_096),
        "the negotiated frame bounds the output"
    );
    assert_eq!(
        above_caps, small_frame,
        "a caller's limit above a cap is lowered to it"
    );
}

#[tokio::test]
async fn unset_limits_under_a_ceiling_declare_the_chain_remaining() {
    let rig = Rig::new();
    let mut issue = child(OPERATOR, vec![Capability::Capture]);
    issue.ceilings = Ceilings {
        bytes_transferred: Some(50_000),
        output_bytes: Some(300),
        ..Ceilings::default()
    };
    let grant = rig.issue(issue, "ceilinged").await;

    let fresh = planned_cost(&rig, grant, UNSET, 1 << 20).await;
    let unset = RequestBody::Capture(CaptureRequest {
        session: SESSION,
        target: OK.to_owned(),
        limits: UNSET,
        egress_policy: None,
    });
    let request = rig.request(grant, Some("spend"), Mode::Execute, unset);
    let spent = rig.call(OPERATOR, request).await;
    let after = planned_cost(&rig, grant, UNSET, 1 << 20).await;
    let explicit = planned_cost(
        &rig,
        grant,
        CaptureLimits {
            max_output_bytes: Some(7),
            max_transfer_bytes: Some(9),
        },
        1 << 20,
    )
    .await;

    assert_eq!(
        (fresh.bytes_transferred, fresh.output_bytes),
        (50_000, 300),
        "an unspent chain declares its ceilings"
    );
    let ResponseBody::Captured(outcome) = spent.body else {
        panic!("the capture fits: {spent:?}");
    };
    assert_eq!(outcome.output_bytes, 80, "40 two-byte characters kept");
    assert_eq!(
        (after.bytes_transferred, after.output_bytes),
        (50_000 - 10_000, 300 - 80),
        "the ceilings less what the capture settled"
    );
    assert_eq!(
        (explicit.bytes_transferred, explicit.output_bytes),
        (9, 7),
        "an explicit limit under the caps is kept"
    );
}

#[tokio::test]
async fn unset_transfer_limit_bounds_the_producer_to_the_chain_remaining() {
    let rig = Rig::new();
    let mut issue = child(OPERATOR, vec![Capability::Capture]);
    issue.ceilings.bytes_transferred = Some(5_000);
    let grant = rig.issue(issue, "small-transfer").await;
    let body = RequestBody::Capture(CaptureRequest {
        session: SESSION,
        target: OK.to_owned(),
        limits: UNSET,
        egress_policy: None,
    });

    let response = rig
        .call(
            OPERATOR,
            rig.request(grant, Some("too-large"), Mode::Execute, body),
        )
        .await;

    assert_eq!(
        failure(&response),
        Some(Failure::TransferFailed {
            class: TransferClass::TooLarge
        }),
        "the 10 000-byte envelope exceeds the 5 000 bytes the chain has left"
    );
    assert_eq!(rig.producer.calls(), 1, "the producer ran under that bound");
}

#[tokio::test]
async fn replay_survives_a_new_deadline_and_the_first_attempts_own_spend() {
    let rig = Rig::new();
    let mut issue = child(OPERATOR, vec![Capability::Capture]);
    issue.ceilings.bytes_transferred = Some(50_000);
    let grant = rig.issue(issue, "replay-ceiling").await;
    let body = RequestBody::Capture(CaptureRequest {
        session: SESSION,
        target: OK.to_owned(),
        limits: UNSET,
        egress_policy: None,
    });
    let request = rig.request(grant, Some("retried"), Mode::Execute, body);
    let mut retry = request.clone();
    retry.request_id = request.request_id.saturating_add(100);
    retry.deadline_ms = request.deadline_ms.saturating_sub(5_000);

    let first = rig.call(OPERATOR, request).await;
    let replay = rig.call(OPERATOR, retry).await;

    assert!(
        matches!(first.body, ResponseBody::Captured(_)),
        "captured: {first:?}"
    );
    assert_eq!(
        (replay.invocation, &replay.body),
        (first.invocation, &first.body),
        "a retry with another deadline, after the first attempt lowered the \
         chain's remaining ceiling, replays instead of conflicting"
    );
    assert_eq!(rig.producer.calls(), 1, "never dispatched twice");
}

#[tokio::test]
async fn query_predicate_is_a_case_sensitive_substring() {
    let rig = Rig::new();
    let _captured = run(&rig, "query-source", OK).await;
    let query = |predicate: &str| {
        RequestBody::Query(QueryRequest {
            session_scope: Some(SESSION),
            predicate: predicate.to_owned(),
            limit: 10,
        })
    };
    let mut hits = Vec::new();

    for predicate in ["", "é", "éé", "É", "e"] {
        let response = rig
            .call(
                OPERATOR,
                rig.request(ROOT, None, Mode::Execute, query(predicate)),
            )
            .await;
        let ResponseBody::QueryPage(page) = response.body else {
            panic!("query failed: {response:?}");
        };
        hits.push(page.result_refs.len());
    }

    assert_eq!(
        hits,
        [1, 1, 1, 0, 0],
        "empty matches all; é and éé are substrings; É and e are not"
    );
}

#[tokio::test]
async fn a_failed_step_releases_at_b1_and_charges_at_b2() {
    let rig = Rig::new();
    let inner = Arc::clone(&rig.orchestrator.inner);
    let begin = |byte: u8| {
        let key = idem(&format!("after-error-{byte}"));
        let id = InvocationId::from_bytes([byte; 16]);
        let limits = CaptureLimits {
            max_output_bytes: Some(10),
            max_transfer_bytes: Some(10),
        };
        let authz = epitrope::AuthzRequest {
            tenant: OPERATOR,
            grant: ROOT,
            capability: Capability::Capture,
            target: Some(OK),
            session: Some(SESSION),
            declared: super::super::limits::capture_cost(&limits, 1_000),
        };
        rig.store
            .begin(&Intent::new(id, authz, &key, [byte; 32]))
            .expect("B1");
        id
    };
    let at_b1 = begin(0x71);
    let at_b2 = begin(0x72);
    rig.store.dispatch(at_b2).expect("B2");

    let released = inner.after_error(at_b1).expect("resolve");
    let charged = inner.after_error(at_b2).expect("resolve");

    let ended = |id| {
        rig.store
            .invocation(id)
            .expect("read")
            .expect("exists")
            .terminal
    };
    assert_eq!(
        ended(at_b1),
        Some(Terminal::Released {
            reason: ReleaseReason::Abandoned
        }),
        "a call that never dispatched returns its reservation"
    );
    assert_eq!(
        released.body,
        ResponseBody::Failed(Failure::Cancelled),
        "and replies as its replay would"
    );
    assert_eq!(
        ended(at_b2),
        Some(Terminal::UnknownEffect),
        "a dispatched call is charged"
    );
    assert_eq!(
        charged.body,
        ResponseBody::Failed(Failure::UnknownEffect),
        "unknown effect"
    );
}
