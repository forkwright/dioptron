//! Replay of the same invocation: idempotent, never a second producer
//! call (contract § Idempotency).
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use syntheke::{Capability, Failure, Mode, RequestBody, ResponseBody};

use crate::test_support::{
    DOWN, Harness, OK, ROOT, agent, capture, child_grant, issue, open_session, operator,
};

#[test]
fn replayed_capture_returns_the_first_outcome_across_restart_without_a_second_call() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut client = harness.connect(&operator());
    let session = open_session(&harness, &mut client, ROOT, "op-session");
    let request = harness.request(
        ROOT,
        Some("capture-once"),
        Mode::Execute,
        capture(session, OK),
    );

    let first = client.call(&request).expect("capture");
    let again = client.call(&request).expect("replay");
    drop(client);
    daemon.stop();
    let daemon = harness.start();
    let mut client = harness.connect(&operator());
    let after_restart = client.call(&request).expect("replay after restart");

    assert!(
        matches!(first.body, ResponseBody::Captured(_)),
        "the first call captures: {first:?}"
    );
    assert_eq!(again, first, "a replay returns the same response");
    assert_eq!(after_restart, first, "and so does a replay after a restart");
    assert_eq!(harness.calls(), 1, "the producer ran once");
    drop(client);
    daemon.stop();
}

#[test]
fn reused_key_for_another_request_or_grant_conflicts() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut client = harness.connect(&operator());
    let session = open_session(&harness, &mut client, ROOT, "op-session");
    let other_grant = issue(
        &harness,
        &mut client,
        child_grant(operator().id, vec![Capability::Capture]),
        "self-grant",
    );
    let first = harness.request(ROOT, Some("one-key"), Mode::Execute, capture(session, OK));
    let other_target =
        harness.request(ROOT, Some("one-key"), Mode::Execute, capture(session, DOWN));
    let other = harness.request(
        other_grant,
        Some("one-key"),
        Mode::Execute,
        capture(session, OK),
    );

    let _first = client.call(&first).expect("capture");
    let by_target = client.call(&other_target).expect("conflict");
    let by_grant = client.call(&other).expect("conflict");

    assert_eq!(
        by_target.body,
        ResponseBody::Failed(Failure::IdempotencyConflict),
        "the key is bound to the first target"
    );
    assert_eq!(
        by_grant.body,
        ResponseBody::Failed(Failure::IdempotencyConflict),
        "the key is bound to the first designated grant"
    );
    assert_eq!(harness.calls(), 1, "no conflict was dispatched");
    drop(client);
    daemon.stop();
}

#[test]
fn replayed_session_and_grant_calls_return_the_same_objects() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut client = harness.connect(&operator());
    let create = harness.request(
        ROOT,
        Some("session-once"),
        Mode::Execute,
        RequestBody::SessionCreate,
    );
    let grant = harness.request(
        ROOT,
        Some("grant-once"),
        Mode::Execute,
        RequestBody::GrantIssue(child_grant(agent().id, vec![Capability::Read])),
    );

    let session = client.call(&create).expect("create");
    let session_again = client.call(&create).expect("replay");
    let issued = client.call(&grant).expect("issue");
    let issued_again = client.call(&grant).expect("replay");

    assert!(
        matches!(session.body, ResponseBody::SessionOpened(_)),
        "a session opens: {session:?}"
    );
    assert_eq!(session_again, session, "the replay names the same session");
    assert!(
        matches!(issued.body, ResponseBody::GrantIssued(_)),
        "a grant issues: {issued:?}"
    );
    assert_eq!(issued_again, issued, "the replay names the same grant");
    drop(client);
    daemon.stop();
}
