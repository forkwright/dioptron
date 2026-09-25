//! Unset capture limits default to the caller's own ledgers only, so a
//! plan or reply never discloses an ancestor grant's remaining budget
//! (contract § Daemon limits, § Reservation and settlement).

use syntheke::{
    Capability, CaptureLimits, CaptureRequest, Cost, DenyCode, Failure, GrantId, GrantIssueRequest,
    Mode, RequestBody, ResponseBody, SessionId,
};

use super::super::test_support::{AGENT, OK, OPERATOR, ROOT, Rig, SESSION, child};
use super::failure;

const UNSET: CaptureLimits = CaptureLimits {
    max_output_bytes: None,
    max_transfer_bytes: None,
};

/// The envelope the `OK` target delivers, written out independently.
const ENVELOPE_BYTES: u64 = 10_000;

fn unset_capture(session: SessionId) -> RequestBody {
    RequestBody::Capture(CaptureRequest {
        session,
        target: OK.to_owned(),
        limits: UNSET,
        egress_policy: None,
    })
}

fn with_transfer_ceiling(mut issue: GrantIssueRequest, bytes: u64) -> GrantIssueRequest {
    issue.ceilings.bytes_transferred = Some(bytes);
    issue
}

/// Issues `issue` as the operator under `parent`.
async fn issue_under(rig: &Rig, parent: GrantId, issue: GrantIssueRequest, key: &str) -> GrantId {
    let request = rig.request(
        parent,
        Some(key),
        Mode::Execute,
        RequestBody::GrantIssue(issue),
    );
    match rig.call(OPERATOR, request).await.body {
        ResponseBody::GrantIssued(issued) => issued.grant,
        other => panic!("grant not issued: {other:?}"),
    }
}

/// The operator's intermediate grant `P` (transfer ceiling `parent_bytes`)
/// and, under it, the agent's grant (transfer ceiling `own_bytes`) with an
/// agent-owned session.
async fn delegated(rig: &Rig, parent_bytes: u64, own_bytes: u64) -> (GrantId, GrantId, SessionId) {
    let caps = vec![
        Capability::SessionCreate,
        Capability::Capture,
        Capability::GrantIssue,
    ];
    let parent = issue_under(
        rig,
        ROOT,
        with_transfer_ceiling(child(OPERATOR, caps), parent_bytes),
        "issue-parent",
    )
    .await;
    let agent_caps = vec![Capability::SessionCreate, Capability::Capture];
    let grant = issue_under(
        rig,
        parent,
        with_transfer_ceiling(child(AGENT, agent_caps), own_bytes),
        "issue-agent",
    )
    .await;
    let session = rig.agent_session(grant, "agent-session").await;
    (parent, grant, session)
}

/// The agent's dry-run cost for an unset-limits capture into `session`.
async fn agent_plan(rig: &Rig, grant: GrantId, session: SessionId) -> Cost {
    let request = rig.request(grant, None, Mode::DryRun, unset_capture(session));
    let response = rig.call(AGENT, request).await;
    let ResponseBody::Plan(plan) = response.body else {
        panic!("no plan: {response:?}");
    };
    plan.cost
}

#[tokio::test]
async fn unset_limit_declares_the_callers_own_bound_not_an_ancestors() {
    let rig = Rig::new();
    let (parent, grant, session) = delegated(&rig, 50_000, 50_000).await;
    let parent_capture = rig.request(
        parent,
        Some("parent-spend"),
        Mode::Execute,
        unset_capture(SESSION),
    );
    let spent = rig.call(OPERATOR, parent_capture).await;
    assert!(
        matches!(spent.body, ResponseBody::Captured(_)),
        "the operator's capture settles {ENVELOPE_BYTES} bytes on P: {spent:?}"
    );

    let planned = agent_plan(&rig, grant, session).await;
    let executed = rig
        .call(
            AGENT,
            rig.request(
                grant,
                Some("agent-spend"),
                Mode::Execute,
                unset_capture(session),
            ),
        )
        .await;

    assert_eq!(
        planned.bytes_transferred, 50_000,
        "the agent's own grant ceiling, not P's 40 000 bytes left"
    );
    assert_eq!(
        failure(&executed),
        Some(Failure::denied(DenyCode::BudgetUnavailable)),
        "P cannot cover 50 000 bytes; the refusal names no dimension"
    );
    assert_eq!(rig.producer.calls(), 1, "only the operator's capture ran");
}

#[tokio::test]
async fn unset_limit_under_a_roomier_ancestor_declares_the_own_bound() {
    let rig = Rig::new();
    let (_parent, grant, session) = delegated(&rig, 50_000, 20_000).await;

    let fresh = agent_plan(&rig, grant, session).await;
    let executed = rig
        .call(
            AGENT,
            rig.request(
                grant,
                Some("agent-spend"),
                Mode::Execute,
                unset_capture(session),
            ),
        )
        .await;
    let after = agent_plan(&rig, grant, session).await;

    assert_eq!(fresh.bytes_transferred, 20_000, "the agent's own ceiling");
    assert!(
        matches!(executed.body, ResponseBody::Captured(_)),
        "every ledger covers 20 000 bytes: {executed:?}"
    );
    assert_eq!(
        after.bytes_transferred,
        20_000 - ENVELOPE_BYTES,
        "the own ceiling less what the capture settled"
    );
}
