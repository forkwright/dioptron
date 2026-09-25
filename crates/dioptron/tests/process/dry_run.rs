//! Dry-run has no effects: no producer call and a byte-identical store
//! (contract § Capabilities and mode, D17.16).
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use syntheke::{
    ArtifactRef, AuditQueryRequest, AuditScope, Capability, Failure, GrantRevokeRequest, Mode,
    NarrowingAxis, QueryRequest, ReadRequest, RequestBody, ResponseBody, SessionForkRequest,
    SessionId,
};

use crate::test_support::{Harness, OK, ROOT, agent, capture, child_grant, open_session, operator};

#[test]
fn dry_runs_call_no_producer_and_leave_the_store_byte_identical() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut client = harness.connect(&operator());
    let session = open_session(&harness, &mut client, ROOT, "op-session");
    drop(client);
    daemon.stop();
    let before = harness.digest();

    let daemon = harness.start();
    let mut client = harness.connect(&operator());
    let bodies = dry_bodies(session);
    let mut plans = Vec::new();
    for body in bodies {
        let request = harness.request(ROOT, None, Mode::DryRun, body);
        let response = client.call(&request).expect("dry run");
        assert_eq!(response.invocation, None, "a plan persists no invocation");
        let ResponseBody::Plan(plan) = response.body else {
            panic!("a dry run answers with a plan: {response:?}");
        };
        plans.push(plan);
    }
    drop(client);
    daemon.stop();

    assert_eq!(harness.calls(), 0, "no dry run calls the producer");
    assert_eq!(
        harness.digest(),
        before,
        "the store is byte for byte unchanged"
    );
    let capture_plan = plans.first().expect("capture plan");
    assert_eq!(capture_plan.refusal, None, "the capture would run");
    assert_eq!(capture_plan.grant_chain, vec![ROOT], "under the root grant");
    assert_eq!(capture_plan.cost.fetches, 1, "declaring one fetch");
    assert_eq!(
        plans.get(1),
        Some(capture_plan),
        "an identical dry run plans the same"
    );
    assert_eq!(
        plans.get(2).and_then(|plan| plan.refusal),
        Some(Failure::NotFoundOrDenied),
        "a refused dry run reports the refusal and still writes nothing"
    );
    assert_eq!(
        plans.get(6).and_then(|plan| plan.refusal),
        Some(Failure::narrowing(NarrowingAxis::Expiry)),
        "a grant issue dry run runs the narrowing check"
    );
    assert_eq!(
        plans.get(8).and_then(|plan| plan.refusal),
        Some(Failure::NotFoundOrDenied),
        "a read of a missing artifact plans the same refusal as its execution"
    );
}

/// One dry run of every capability, some allowed and some refused.
fn dry_bodies(session: SessionId) -> Vec<RequestBody> {
    let mut wide = child_grant(agent().id, vec![Capability::Capture]);
    wide.target_scope = vec!["*.example.org".to_owned(), "example.net".to_owned()];
    wide.capabilities.push(Capability::Read);
    let mut too_long = wide.clone();
    too_long.expires_at = syntheke::Timestamp::from_unix_millis(i64::MAX);
    vec![
        capture(session, OK),
        capture(session, OK),
        capture(SessionId::from_bytes([0x71; 16]), OK),
        RequestBody::SessionCreate,
        RequestBody::SessionFork(SessionForkRequest {
            parent_session: session,
        }),
        RequestBody::GrantIssue(wide),
        RequestBody::GrantIssue(too_long),
        RequestBody::GrantRevoke(GrantRevokeRequest { target_grant: ROOT }),
        RequestBody::Read(ReadRequest {
            artifact_ref: ArtifactRef::from_bytes([0x72; 16]),
            offset: 0,
            len: 64,
        }),
        RequestBody::Query(QueryRequest {
            session_scope: Some(session),
            predicate: String::new(),
            limit: 10,
        }),
        RequestBody::AuditQuery(AuditQueryRequest {
            audit_scope: AuditScope::All,
            session: None,
            after: None,
            limit: 10,
        }),
    ]
}
