//! Grant attenuation, expiry, and revocation, including revocation of
//! running calls, cancellation, and deadlines.
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use syntheke::{
    Capability, DenyCode, Failure, GrantId, GrantRevokeRequest, Mode, NarrowingAxis, ReadRequest,
    RequestBody, ResponseBody, SessionId, Timestamp,
};
use xenos::Client;

use crate::test_support::{
    EXPIRES_MS, Harness, LATE, OK, ROOT, STALL, agent, capture, child_grant, issue, open_session,
    operator, own_uid, sub_agent,
};

/// The agent's grant under `ROOT`: session create, capture, read, grant
/// issue, and grant revoke on example.com.
fn agent_grant(harness: &Harness, operator_client: &mut Client, key: &str) -> GrantId {
    issue(
        harness,
        operator_client,
        child_grant(
            agent().id,
            vec![
                Capability::SessionCreate,
                Capability::Capture,
                Capability::Read,
                Capability::GrantIssue,
                Capability::GrantRevoke,
            ],
        ),
        key,
    )
}

fn issue_as(
    harness: &Harness,
    client: &mut Client,
    parent: GrantId,
    request: syntheke::GrantIssueRequest,
    key: &str,
) -> ResponseBody {
    let request = harness.request(
        parent,
        Some(key),
        Mode::Execute,
        RequestBody::GrantIssue(request),
    );
    client.call(&request).expect("grant issue").body
}

fn capture_as(
    harness: &Harness,
    client: &mut Client,
    grant: GrantId,
    session: SessionId,
    key: &str,
) -> ResponseBody {
    let request = harness.request(grant, Some(key), Mode::Execute, capture(session, OK));
    client.call(&request).expect("capture").body
}

fn revoke(
    harness: &Harness,
    client: &mut Client,
    under: GrantId,
    target: GrantId,
    key: &str,
) -> syntheke::Response {
    let request = harness.request(
        under,
        Some(key),
        Mode::Execute,
        RequestBody::GrantRevoke(GrantRevokeRequest {
            target_grant: target,
        }),
    );
    client.call(&request).expect("revoke")
}

fn denied(code: DenyCode) -> ResponseBody {
    ResponseBody::Failed(Failure::denied(code))
}

#[test]
fn child_grant_is_refused_on_every_widened_axis_and_issued_when_narrower() {
    let harness = Harness::with_cast();
    harness.add_tenant(&sub_agent(), "sub-agent", own_uid(), &agent());
    let daemon = harness.start();
    let mut operator_client = harness.connect(&operator());
    let parent = agent_grant(&harness, &mut operator_client, "issue-agent");
    let mut client = harness.connect(&agent());
    let narrower = child_grant(
        sub_agent().id,
        vec![Capability::SessionCreate, Capability::Capture],
    );
    let mut caps = narrower.clone();
    caps.capabilities.push(Capability::AuditQuery);
    let mut targets = narrower.clone();
    targets.target_scope = vec!["*".to_owned()];
    let mut expiry = narrower.clone();
    expiry.expires_at = Timestamp::from_unix_millis(EXPIRES_MS.saturating_add(1));

    let widened = [
        (caps, NarrowingAxis::Capabilities),
        (targets, NarrowingAxis::TargetScope),
        (expiry, NarrowingAxis::Expiry),
    ];
    for (index, (request, axis)) in widened.into_iter().enumerate() {
        let body = issue_as(
            &harness,
            &mut client,
            parent,
            request,
            &format!("widen-{index}"),
        );
        assert_eq!(
            body,
            ResponseBody::Failed(Failure::narrowing(axis)),
            "a child wider on {axis} is refused"
        );
    }
    let issued = issue_as(&harness, &mut client, parent, narrower, "narrower");
    let ResponseBody::GrantIssued(issued) = issued else {
        panic!("a narrower child is issued: {issued:?}");
    };
    let mut sub_client = harness.connect(&sub_agent());
    let session = open_session(&harness, &mut sub_client, issued.grant, "sub-session");
    let captured = capture_as(
        &harness,
        &mut sub_client,
        issued.grant,
        session,
        "sub-capture",
    );

    assert_eq!(issued.parent_grant, parent, "the child names its parent");
    assert!(
        matches!(captured, ResponseBody::Captured(_)),
        "the attenuated child authorizes what it names: {captured:?}"
    );
    drop((client, sub_client, operator_client));
    daemon.stop();
}

#[cfg(feature = "test-clock")]
#[test]
fn grant_is_refused_outside_its_validity_window_as_the_clock_moves() {
    use crate::test_support::NOW_MS;

    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut operator_client = harness.connect(&operator());
    let standing = agent_grant(&harness, &mut operator_client, "issue-standing");
    let mut expiring = child_grant(agent().id, vec![Capability::Capture]);
    expiring.expires_at = Timestamp::from_unix_millis(NOW_MS.saturating_add(10_000));
    let expiring = issue(&harness, &mut operator_client, expiring, "issue-expiring");
    let mut later = child_grant(agent().id, vec![Capability::Capture]);
    later.not_before = Timestamp::from_unix_millis(NOW_MS.saturating_add(10_000));
    let later = issue(&harness, &mut operator_client, later, "issue-later");
    let mut client = harness.connect(&agent());
    let session = open_session(&harness, &mut client, standing, "agent-session");

    let before_expiry = capture_as(&harness, &mut client, expiring, session, "c1");
    let not_yet = capture_as(&harness, &mut client, later, session, "c2");
    harness.set_clock(NOW_MS.saturating_add(20_000));
    let expired = capture_as(&harness, &mut client, expiring, session, "c3");
    let now_valid = capture_as(&harness, &mut client, later, session, "c4");

    assert!(
        matches!(before_expiry, ResponseBody::Captured(_)),
        "valid before expiry: {before_expiry:?}"
    );
    assert_eq!(
        not_yet,
        denied(DenyCode::GrantNotYetValid),
        "before not_before"
    );
    assert_eq!(
        expired,
        denied(DenyCode::GrantExpired),
        "at or after expires_at"
    );
    assert!(
        matches!(now_valid, ResponseBody::Captured(_)),
        "valid once not_before passes: {now_valid:?}"
    );
    drop((client, operator_client));
    daemon.stop();
}

#[test]
fn revoking_a_parent_invalidates_descendants_and_stands_on_replay() {
    let harness = Harness::with_cast();
    harness.add_tenant(&sub_agent(), "sub-agent", own_uid(), &agent());
    let daemon = harness.start();
    let mut operator_client = harness.connect(&operator());
    let parent = agent_grant(&harness, &mut operator_client, "issue-agent");
    let mut client = harness.connect(&agent());
    let request = child_grant(
        sub_agent().id,
        vec![Capability::SessionCreate, Capability::Capture],
    );
    let ResponseBody::GrantIssued(child) =
        issue_as(&harness, &mut client, parent, request, "child")
    else {
        panic!("child not issued");
    };
    let mut sub_client = harness.connect(&sub_agent());
    let session = open_session(&harness, &mut sub_client, child.grant, "sub-session");
    let agent_session = open_session(&harness, &mut client, parent, "agent-session");
    let outside = revoke(&harness, &mut client, parent, ROOT, "agent-revokes-root");
    let missing = revoke(
        &harness,
        &mut client,
        parent,
        GrantId::from_bytes([0x44; 16]),
        "agent-revokes-none",
    );

    let first = revoke(&harness, &mut operator_client, ROOT, parent, "revoke-agent");
    let replay = revoke(&harness, &mut operator_client, ROOT, parent, "revoke-agent");
    let again = revoke(
        &harness,
        &mut operator_client,
        ROOT,
        parent,
        "revoke-agent-again",
    );
    let sub_capture = capture_as(
        &harness,
        &mut sub_client,
        child.grant,
        session,
        "sub-capture",
    );
    let agent_capture = capture_as(
        &harness,
        &mut client,
        parent,
        agent_session,
        "agent-capture",
    );

    assert_eq!(
        outside.body,
        ResponseBody::Failed(Failure::NotFoundOrDenied),
        "an ancestor is outside the revoker's subtree"
    );
    assert_eq!(
        outside.body, missing.body,
        "and reads exactly as a missing grant"
    );
    let ResponseBody::GrantRevoked(record) = &first.body else {
        panic!("revocation failed: {first:?}");
    };
    assert_eq!(record.revoked_grant, parent, "the record names the grant");
    assert_eq!(replay.body, first.body, "a replay returns the same record");
    assert_eq!(
        again.body, first.body,
        "a second revocation writes no new epoch"
    );
    assert_eq!(
        sub_capture,
        denied(DenyCode::GrantRevoked),
        "the descendant is invalid"
    );
    assert_eq!(
        agent_capture,
        denied(DenyCode::GrantRevoked),
        "the grant is invalid"
    );
    drop((client, sub_client, operator_client));
    daemon.stop();
}

/// Starts a capture of `target` by the agent, waits for the producer
/// call, revokes the agent's grant, and returns the capture's response.
fn revoke_during(harness: &Harness, target: &str) -> (GrantId, syntheke::Response, Client) {
    let mut operator_client = harness.connect(&operator());
    let grant = agent_grant(harness, &mut operator_client, "issue-agent");
    let mut client = harness.connect(&agent());
    let session = open_session(harness, &mut client, grant, "agent-session");
    let calls = harness.calls();
    let request = harness.request(
        grant,
        Some("running"),
        Mode::Execute,
        capture(session, target),
    );
    client.send_request(&request).expect("send");
    harness.wait_calls(calls.saturating_add(1));
    let revoked = revoke(harness, &mut operator_client, ROOT, grant, "revoke-running");
    assert!(
        matches!(revoked.body, ResponseBody::GrantRevoked(_)),
        "the revocation succeeds: {revoked:?}"
    );
    let response = client.recv_response().expect("capture response");
    (grant, response, client)
}

#[test]
fn revocation_of_a_dispatched_call_before_effect_releases_it() {
    let harness = Harness::with_cast();
    let daemon = harness.start();

    let (_, response, client) = revoke_during(&harness, STALL);

    assert_eq!(
        response.body,
        denied(DenyCode::GrantRevoked),
        "a call the producer had not started ends as revoked"
    );
    assert!(
        response.invocation.is_some(),
        "the invocation was persisted"
    );
    drop(client);
    daemon.stop();
}

#[test]
fn revocation_after_effect_publishes_the_marker_and_reads_need_a_live_grant() {
    let harness = Harness::with_cast();
    let daemon = harness.start();

    let (grant, response, mut client) = revoke_during(&harness, LATE);

    let ResponseBody::Captured(outcome) = response.body else {
        panic!("the completed effect is published: {response:?}");
    };
    assert!(
        outcome.revoked_after_effect,
        "the capture records the revocation"
    );
    let read = |grant| {
        harness.request(
            grant,
            None,
            Mode::Execute,
            RequestBody::Read(ReadRequest {
                artifact_ref: outcome.artifact_ref,
                offset: 0,
                len: 1_024,
            }),
        )
    };
    let refused = client.call(&read(grant)).expect("read");
    let mut operator_client = harness.connect(&operator());
    let allowed = operator_client.call(&read(ROOT)).expect("read");
    assert_eq!(
        refused.body,
        denied(DenyCode::GrantRevoked),
        "the revoked grant cannot read"
    );
    assert!(
        matches!(allowed.body, ResponseBody::Chunk(_)),
        "a live grant still reads the artifact: {allowed:?}"
    );
    drop((client, operator_client));
    daemon.stop();
}

#[test]
fn cancel_frame_and_deadline_stop_a_call_before_effect() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut client = harness.connect(&operator());
    let session = open_session(&harness, &mut client, ROOT, "op-session");
    let request = harness.request(
        ROOT,
        Some("cancel-me"),
        Mode::Execute,
        capture(session, STALL),
    );

    client.send_request(&request).expect("send");
    harness.wait_calls(1);
    client.cancel(request.request_id).expect("cancel");
    let cancelled = client.recv_response().expect("response");
    let mut late = harness.request(
        ROOT,
        Some("deadline"),
        Mode::Execute,
        capture(session, STALL),
    );
    late.deadline_ms = 200;
    let expired = client.call(&late).expect("response");
    let replay = client.call(&request).expect("replay");

    assert_eq!(
        cancelled.body,
        ResponseBody::Failed(Failure::Cancelled),
        "cancel"
    );
    assert_eq!(
        expired.body,
        ResponseBody::Failed(Failure::DeadlineExceeded),
        "deadline"
    );
    assert_eq!(replay.body, cancelled.body, "a replay reports the release");
    assert_eq!(
        harness.calls(),
        2,
        "each stopped call reached the producer once"
    );
    drop(client);
    daemon.stop();
}
