//! Expiry distinct from revocation, at authorization, at the dispatch
//! re-check, and mid-call; and replays that re-authorize before they
//! answer (contract § Expiry and validity, § Idempotency).

use std::sync::Arc;

use phylake::store::Terminal;
use syntheke::{
    Capability, DenyCode, Failure, GrantId, Mode, ReleaseReason, RequestBody, Response,
    ResponseBody, SessionId, Timestamp,
};

use super::super::test_support::{
    AGENT, LATE, NOW, OK, Rig, STALL, capture, child, far, producer_called, signal,
};
use super::{failure, terminal};

/// When the expiring grant's validity ends: 10 s after the rig's clock.
const EXPIRES: i64 = NOW.unix_millis().saturating_add(10_000);

/// A capture of `target` into `session`.
fn capture_into(session: SessionId, target: &str) -> RequestBody {
    let RequestBody::Capture(mut request) = capture(target) else {
        panic!("capture body");
    };
    request.session = session;
    RequestBody::Capture(request)
}

/// An agent grant that confers session create, capture, and read, and
/// expires at [`EXPIRES`]; with a session the agent owns.
async fn expiring_agent(rig: &Rig) -> (GrantId, SessionId) {
    let mut issue = child(
        AGENT,
        vec![
            Capability::SessionCreate,
            Capability::Capture,
            Capability::Read,
        ],
    );
    issue.expires_at = Timestamp::from_unix_millis(EXPIRES);
    let grant = rig.issue(issue, "issue-expiring").await;
    let session = rig.agent_session(grant, "expiring-session").await;
    (grant, session)
}

fn denied(code: DenyCode) -> Failure {
    Failure::denied(code)
}

#[tokio::test]
async fn expired_grant_is_refused_at_authorization_as_expired() {
    let rig = Rig::new();
    let (grant, session) = expiring_agent(&rig).await;
    rig.clock.set(EXPIRES);

    let request = rig.request(
        grant,
        Some("after-expiry"),
        Mode::Execute,
        capture_into(session, OK),
    );
    let response = rig.call(AGENT, request).await;

    assert_eq!(
        failure(&response),
        Some(denied(DenyCode::GrantExpired)),
        "expiry"
    );
    assert_eq!(response.invocation, None, "a refusal names no invocation");
    assert_eq!(rig.producer.calls(), 0, "never dispatched");
}

#[tokio::test]
async fn dispatch_recheck_maps_expiry_and_revocation_to_their_own_reasons() {
    let rig = Rig::new();
    let inner = Arc::clone(&rig.orchestrator.inner);
    let (expiring, _) = expiring_agent(&rig).await;
    let revoked = rig.agent_grant(vec![Capability::Capture]).await;
    rig.revoke(revoked, "revoke-recheck").await;
    let mut both = child(AGENT, vec![Capability::Capture]);
    both.expires_at = Timestamp::from_unix_millis(EXPIRES);
    let both = rig.issue(both, "issue-both").await;
    rig.revoke(both, "revoke-both").await;

    let live = inner.pre_dispatch(expiring, false, far()).expect("check");
    rig.clock.set(EXPIRES);
    let expired = inner.pre_dispatch(expiring, false, far()).expect("check");
    let revoked = inner.pre_dispatch(revoked, false, far()).expect("check");
    let revoked_and_expired = inner.pre_dispatch(both, false, far()).expect("check");

    assert_eq!(live, None, "a live chain dispatches");
    assert_eq!(expired, Some(ReleaseReason::Expired), "expiry releases");
    assert_eq!(revoked, Some(ReleaseReason::Revoked), "revocation releases");
    assert_eq!(
        revoked_and_expired,
        Some(ReleaseReason::Revoked),
        "a link both revoked and expired reports revocation first"
    );
}

/// Starts a capture of `target` under the expiring grant, waits for the
/// producer call, moves the clock past expiry, and returns the reply.
async fn expire_while_running(rig: &Rig, target: &str) -> Response {
    let (grant, session) = expiring_agent(rig).await;
    let request = rig.request(
        grant,
        Some("running"),
        Mode::Execute,
        capture_into(session, target),
    );
    let calls = rig.producer.calls();
    let (_handle, cancel) = signal();
    let pending = rig.call_with(AGENT, request, cancel, far(), 1 << 20);
    let (response, ()) = tokio::join!(pending, async {
        producer_called(&rig.producer, calls.saturating_add(1)).await;
        rig.clock.set(EXPIRES);
    });
    response
}

#[tokio::test]
async fn expiry_mid_call_before_effect_releases_as_expired() {
    let rig = Rig::new();

    let response = expire_while_running(&rig, STALL).await;

    assert_eq!(
        failure(&response),
        Some(denied(DenyCode::GrantExpired)),
        "the call ends as expired, not revoked"
    );
    assert_eq!(
        terminal(&rig, &response),
        Some(Terminal::Released {
            reason: ReleaseReason::Expired
        }),
        "released for expiry"
    );
}

#[tokio::test]
async fn expiry_mid_call_after_effect_publishes_with_the_marker() {
    let rig = Rig::new();

    let response = expire_while_running(&rig, LATE).await;

    let ResponseBody::Captured(outcome) = &response.body else {
        panic!("the completed effect is published: {response:?}");
    };
    assert!(
        outcome.revoked_after_effect,
        "the capture records that its chain stopped being live"
    );
    assert_eq!(
        terminal(&rig, &response),
        Some(Terminal::Settled { failure: None }),
        "settled, not released"
    );
}

/// Captures `OK` under a fresh agent grant and returns the grant, the
/// session, the request, and the first reply.
async fn captured_once(rig: &Rig) -> (GrantId, syntheke::Request, Response) {
    let (grant, session) = expiring_agent(rig).await;
    let request = rig.request(
        grant,
        Some("capture-once"),
        Mode::Execute,
        capture_into(session, OK),
    );
    let first = rig.call(AGENT, request.clone()).await;
    assert!(
        matches!(first.body, ResponseBody::Captured(_)),
        "the first call captures: {first:?}"
    );
    (grant, request, first)
}

#[tokio::test]
async fn replay_after_revocation_is_denied_without_stored_content() {
    let rig = Rig::new();
    let (grant, request, first) = captured_once(&rig).await;
    rig.revoke(grant, "revoke-after-capture").await;

    let replay = rig.call(AGENT, request).await;

    assert_eq!(
        replay.body,
        ResponseBody::Failed(Failure::denied(DenyCode::GrantRevoked)),
        "the replay reports the current revocation"
    );
    assert_eq!(replay.invocation, None, "and names no invocation");
    assert_eq!(rig.producer.calls(), 1, "no second producer call");
    assert_eq!(
        terminal(&rig, &first),
        Some(Terminal::Settled { failure: None }),
        "the original effect stands"
    );
}

#[tokio::test]
async fn replay_after_expiry_is_denied_without_stored_content() {
    let rig = Rig::new();
    let (_, request, _) = captured_once(&rig).await;
    rig.clock.set(EXPIRES);

    let replay = rig.call(AGENT, request).await;

    assert_eq!(
        replay.body,
        ResponseBody::Failed(Failure::denied(DenyCode::GrantExpired)),
        "the replay reports the current expiry"
    );
    assert_eq!(rig.producer.calls(), 1, "no second producer call");
}

#[tokio::test]
async fn replay_of_a_session_create_after_revocation_is_denied() {
    let rig = Rig::new();
    let grant = rig.agent_grant(vec![Capability::SessionCreate]).await;
    let request = rig.request(
        grant,
        Some("open-once"),
        Mode::Execute,
        RequestBody::SessionCreate,
    );
    let first = rig.call(AGENT, request.clone()).await;
    let live_replay = rig.call(AGENT, request.clone()).await;
    rig.revoke(grant, "revoke-session-grant").await;

    let replay = rig.call(AGENT, request).await;

    assert!(
        matches!(first.body, ResponseBody::SessionOpened(_)),
        "opened: {first:?}"
    );
    assert_eq!(live_replay, first, "a live replay returns the same session");
    assert_eq!(
        replay.body,
        ResponseBody::Failed(Failure::denied(DenyCode::GrantRevoked)),
        "a replay under a revoked chain is refused"
    );
    assert_eq!(replay.invocation, None, "and names no invocation");
}
