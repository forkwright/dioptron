//! In-process orchestrator tests: every lifecycle path against a real
//! store and a scripted producer.
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use std::sync::Arc;

use phylake::store::Terminal;
use syntheke::{
    AuditQueryRequest, AuditScope, Capability, DenyCode, ExtractionClass, Failure,
    GrantRevokeRequest, InvocationState, Mode, ReadRequest, ReleaseReason, Request, RequestBody,
    Response, ResponseBody, Timestamp, TransferClass,
};
use tokio::time::Instant;

use super::capture::cut_text;
use super::test_support::{
    AGENT, BAD, CONTACTED, DOWN, LATE, OK, OPERATOR, RESET, ROOT, Rig, STALL, STARTED, capture,
    envelope, far, producer_called, signal,
};
use super::{fresh_id, request_digest};

mod expiry;
mod limits;
mod serving;

fn failure(response: &Response) -> Option<Failure> {
    match response.body {
        ResponseBody::Failed(failure) => Some(failure),
        _ => None,
    }
}

fn terminal(rig: &Rig, response: &Response) -> Option<Terminal> {
    let id = response.invocation.expect("a persisted invocation");
    rig.store
        .invocation(id)
        .expect("invocation read")
        .expect("invocation exists")
        .terminal
}

async fn run(rig: &Rig, key: &str, target: &str) -> Response {
    let request = rig.request(ROOT, Some(key), Mode::Execute, capture(target));
    rig.call(OPERATOR, request).await
}

#[tokio::test]
async fn capture_publishes_and_replay_never_calls_again() {
    let rig = Rig::new();

    let first = run(&rig, "capture-ok", OK).await;
    let replay = run(&rig, "capture-ok", OK).await;

    let ResponseBody::Captured(outcome) = &first.body else {
        panic!("capture failed: {first:?}");
    };
    assert_eq!(outcome.source.fingerprint, "fp-ok", "evidence identity");
    assert!(!outcome.truncated, "80 bytes fit the 1000-byte bound");
    assert!(!outcome.revoked_after_effect, "no revocation");
    assert_eq!(replay.body, first.body, "a replay returns the same outcome");
    assert_eq!(
        replay.invocation, first.invocation,
        "and the same invocation"
    );
    assert_eq!(rig.producer.calls(), 1, "the producer ran once");
    assert_eq!(
        terminal(&rig, &first),
        Some(Terminal::Settled { failure: None }),
        "settled at B5"
    );
    let chunk = rig
        .store
        .read_artifact(outcome.artifact_ref, 0, u32::MAX)
        .expect("read")
        .expect("published");
    assert_eq!(chunk.bytes, envelope(), "the envelope is stored verbatim");
}

#[tokio::test]
async fn capture_key_reused_for_another_target_conflicts() {
    let rig = Rig::new();
    let _first = run(&rig, "capture-key", OK).await;

    let second = run(&rig, "capture-key", RESET).await;

    assert_eq!(
        failure(&second),
        Some(Failure::IdempotencyConflict),
        "one key names one request"
    );
    assert_eq!(rig.producer.calls(), 1, "the conflict never dispatched");
}

#[tokio::test]
async fn dry_run_of_every_capability_writes_nothing() {
    let rig = Rig::new();
    let before = rig.store.logical_digest().expect("digest");
    let bodies = [
        capture(OK),
        RequestBody::SessionCreate,
        RequestBody::Read(ReadRequest {
            artifact_ref: syntheke::ArtifactRef::from_bytes([9; 16]),
            offset: 0,
            len: 16,
        }),
        RequestBody::AuditQuery(AuditQueryRequest {
            audit_scope: AuditScope::All,
            session: None,
            after: None,
            limit: 10,
        }),
        RequestBody::GrantRevoke(GrantRevokeRequest { target_grant: ROOT }),
    ];

    for body in bodies {
        let request = rig.request(ROOT, None, Mode::DryRun, body);
        let response = rig.call(OPERATOR, request).await;
        assert!(
            matches!(response.body, ResponseBody::Plan(_)),
            "a dry-run answers with a plan: {response:?}"
        );
        assert_eq!(response.invocation, None, "a plan persists no invocation");
    }

    assert_eq!(
        rig.producer.calls(),
        0,
        "a dry-run never calls the producer"
    );
    assert_eq!(
        rig.store.logical_digest().expect("digest"),
        before,
        "the store is byte for byte unchanged"
    );
}

#[tokio::test]
async fn dry_run_capture_plans_chain_and_cost() {
    let rig = Rig::new();

    let request = rig.request(ROOT, None, Mode::DryRun, capture(OK));
    let response = rig.call(OPERATOR, request).await;

    let ResponseBody::Plan(plan) = response.body else {
        panic!("no plan: {response:?}");
    };
    assert_eq!(plan.refusal, None, "the capture would be allowed");
    assert_eq!(plan.grant_chain, vec![ROOT], "under the root grant");
    assert_eq!(plan.cost.fetches, 1, "one fetch declared");
    assert_eq!(plan.cost.output_bytes, 1_000, "the caller's output bound");
}

#[tokio::test]
async fn producer_failures_map_to_their_outcome_and_terminal() {
    let rig = Rig::new();
    let cases = [
        (
            DOWN,
            Failure::ProducerUnavailable,
            Terminal::Released {
                reason: ReleaseReason::ProducerUnavailable,
            },
        ),
        (CONTACTED, Failure::UnknownEffect, Terminal::UnknownEffect),
        (
            RESET,
            Failure::TransferFailed {
                class: TransferClass::Reset,
            },
            Terminal::Settled {
                failure: Some(Failure::TransferFailed {
                    class: TransferClass::Reset,
                }),
            },
        ),
        (
            BAD,
            Failure::ExtractionFailed {
                class: ExtractionClass::Malformed,
            },
            Terminal::Settled {
                failure: Some(Failure::ExtractionFailed {
                    class: ExtractionClass::Malformed,
                }),
            },
        ),
    ];

    for (target, expected, ended) in cases {
        let response = run(&rig, target, target).await;
        assert_eq!(failure(&response), Some(expected), "{target} reply");
        assert_eq!(terminal(&rig, &response), Some(ended), "{target} terminal");
    }
}

#[tokio::test]
async fn cancel_before_effect_releases_and_after_effect_settles() {
    let rig = Rig::new();
    for (target, expected) in [
        (
            STALL,
            Terminal::Released {
                reason: ReleaseReason::Cancelled,
            },
        ),
        (
            STARTED,
            Terminal::Settled {
                failure: Some(Failure::Cancelled),
            },
        ),
    ] {
        let (handle, cancel) = signal();
        let request = rig.request(ROOT, Some(target), Mode::Execute, capture(target));
        let calls = rig.producer.calls();
        let pending = rig.call_with(OPERATOR, request, cancel, far(), 1 << 20);
        let (response, ()) = tokio::join!(pending, async {
            producer_called(&rig.producer, calls.saturating_add(1)).await;
            handle.cancel();
        });
        assert_eq!(failure(&response), Some(Failure::Cancelled), "{target}");
        assert_eq!(terminal(&rig, &response), Some(expected), "{target}");
    }
}

#[tokio::test]
async fn deadline_before_effect_releases_deadline_exceeded() {
    let rig = Rig::new();
    let (_handle, cancel) = signal();
    let request = rig.request(ROOT, Some("deadline"), Mode::Execute, capture(STALL));
    let deadline = Instant::now()
        .checked_add(std::time::Duration::from_millis(50))
        .expect("deadline");

    let response = rig
        .call_with(OPERATOR, request, cancel, deadline, 1 << 20)
        .await;

    assert_eq!(failure(&response), Some(Failure::DeadlineExceeded), "reply");
    assert_eq!(
        terminal(&rig, &response),
        Some(Terminal::Released {
            reason: ReleaseReason::DeadlineExceeded
        }),
        "released for the deadline"
    );
}

async fn revoke_while_running(rig: &Rig, target: &str) -> (Response, Response) {
    let grant = rig
        .agent_grant(vec![
            Capability::SessionCreate,
            Capability::Capture,
            Capability::Read,
        ])
        .await;
    let session = rig.request(
        grant,
        Some("agent-session"),
        Mode::Execute,
        RequestBody::SessionCreate,
    );
    let ResponseBody::SessionOpened(opened) = rig.call(AGENT, session).await.body else {
        panic!("agent session not opened");
    };
    let mut body = capture(target);
    if let RequestBody::Capture(capture) = &mut body {
        capture.session = opened.session;
    }
    let request = rig.request(grant, Some("agent-capture"), Mode::Execute, body);
    let revoke = rig.request(
        ROOT,
        Some("revoke-agent"),
        Mode::Execute,
        RequestBody::GrantRevoke(GrantRevokeRequest {
            target_grant: grant,
        }),
    );
    let calls = rig.producer.calls();
    let (captured, revoked) = tokio::join!(rig.call(AGENT, request), async {
        producer_called(&rig.producer, calls.saturating_add(1)).await;
        rig.call(OPERATOR, revoke).await
    });
    assert!(
        matches!(revoked.body, ResponseBody::GrantRevoked(_)),
        "the operator revokes: {revoked:?}"
    );
    (captured, revoked)
}

#[tokio::test]
async fn revocation_before_effect_releases_as_revoked() {
    let rig = Rig::new();

    let (captured, _) = revoke_while_running(&rig, STALL).await;

    assert_eq!(
        failure(&captured),
        Some(Failure::denied(DenyCode::GrantRevoked)),
        "the call ends as revoked"
    );
    assert_eq!(
        terminal(&rig, &captured),
        Some(Terminal::Released {
            reason: ReleaseReason::Revoked
        }),
        "the reservation is released"
    );
}

#[tokio::test]
async fn revocation_after_effect_publishes_with_marker_and_blocks_reads() {
    let rig = Rig::new();

    let (captured, _) = revoke_while_running(&rig, LATE).await;

    let ResponseBody::Captured(outcome) = &captured.body else {
        panic!("the completed effect is published: {captured:?}");
    };
    assert!(
        outcome.revoked_after_effect,
        "the capture carries the marker"
    );
    let read = rig.request(
        captured_grant(&rig, &captured),
        None,
        Mode::Execute,
        RequestBody::Read(ReadRequest {
            artifact_ref: outcome.artifact_ref,
            offset: 0,
            len: 64,
        }),
    );
    let response = rig.call(AGENT, read).await;
    assert_eq!(
        failure(&response),
        Some(Failure::denied(DenyCode::GrantRevoked)),
        "reading still needs a live grant"
    );
}

fn captured_grant(rig: &Rig, response: &Response) -> syntheke::GrantId {
    let id = response.invocation.expect("invocation");
    rig.store
        .invocation(id)
        .expect("read")
        .expect("exists")
        .grant_chain
        .first()
        .copied()
        .expect("chain")
}

#[tokio::test]
async fn dispatch_recheck_releases_after_revocation_cancel_or_deadline() {
    let rig = Rig::new();
    let inner = Arc::clone(&rig.orchestrator.inner);
    let grant = rig.agent_grant(vec![Capability::Capture]).await;

    let live = inner.pre_dispatch(grant, false, far()).expect("check");
    let cancelled = inner.pre_dispatch(grant, true, far()).expect("check");
    let late = inner
        .pre_dispatch(grant, false, Instant::now())
        .expect("check");
    let revoke = rig.request(
        ROOT,
        Some("revoke-recheck"),
        Mode::Execute,
        RequestBody::GrantRevoke(GrantRevokeRequest {
            target_grant: grant,
        }),
    );
    let _revoked = rig.call(OPERATOR, revoke).await;
    let revoked = inner.pre_dispatch(grant, false, far()).expect("check");

    assert_eq!(live, None, "a live chain dispatches");
    assert_eq!(
        cancelled,
        Some(ReleaseReason::Cancelled),
        "a cancel releases"
    );
    assert_eq!(
        late,
        Some(ReleaseReason::DeadlineExceeded),
        "a deadline releases"
    );
    assert_eq!(
        revoked,
        Some(ReleaseReason::Revoked),
        "a revocation releases"
    );
}

#[tokio::test]
async fn read_chunks_fit_the_frame_bound() {
    let rig = Rig::new();
    let first = run(&rig, "chunked", OK).await;
    let ResponseBody::Captured(outcome) = first.body else {
        panic!("capture failed");
    };
    let max_frame = 4_096;
    let mut bytes = Vec::new();
    let mut offset = 0;
    loop {
        let request = rig.request(
            ROOT,
            None,
            Mode::Execute,
            RequestBody::Read(ReadRequest {
                artifact_ref: outcome.artifact_ref,
                offset,
                len: u32::MAX,
            }),
        );
        let (_handle, cancel) = signal();
        let response = rig
            .call_with(OPERATOR, request, cancel, far(), max_frame)
            .await;
        let encoded = syntheke::encode(&response).expect("encode");
        assert!(
            encoded.len() <= usize::try_from(max_frame).expect("usize"),
            "every chunk fits the frame"
        );
        let ResponseBody::Chunk(chunk) = response.body else {
            panic!("no chunk");
        };
        if chunk.bytes.is_empty() {
            break;
        }
        offset += u64::try_from(chunk.bytes.len()).expect("len");
        bytes.extend(chunk.bytes);
    }
    assert_eq!(bytes, envelope(), "the chunks reassemble the envelope");
}

#[tokio::test]
async fn audit_query_answers_within_the_granted_scope_and_is_audited() {
    let rig = Rig::new();
    let grant = rig
        .agent_grant(vec![Capability::AuditQuery, Capability::SessionCreate])
        .await;
    let query = || {
        RequestBody::AuditQuery(AuditQueryRequest {
            audit_scope: AuditScope::All,
            session: None,
            after: None,
            limit: 100,
        })
    };

    let agent = rig
        .call(AGENT, rig.request(grant, None, Mode::Execute, query()))
        .await;
    let operator = rig
        .call(OPERATOR, rig.request(ROOT, None, Mode::Execute, query()))
        .await;

    let ResponseBody::AuditPage(agent) = agent.body else {
        panic!("agent audit failed");
    };
    let ResponseBody::AuditPage(operator) = operator.body else {
        panic!("operator audit failed");
    };
    assert_eq!(
        agent.scope_applied,
        AuditScope::OwnAndOwnedSessions,
        "an agent's grant narrows All"
    );
    assert!(
        agent.records.iter().all(|record| record.tenant == AGENT),
        "the agent sees only its own records"
    );
    assert_eq!(
        operator.scope_applied,
        AuditScope::All,
        "the operator reads All"
    );
    assert!(
        operator
            .records
            .iter()
            .any(|record| record.tenant == AGENT && record.capability == Capability::AuditQuery),
        "the agent's audit read was itself audited"
    );
}

#[tokio::test]
async fn refusal_bytes_do_not_depend_on_existence() {
    let rig = Rig::new();
    let grant = rig.agent_grant(vec![Capability::Read]).await;
    let first = run(&rig, "foreign", OK).await;
    let ResponseBody::Captured(outcome) = first.body else {
        panic!("capture failed");
    };
    let read = |artifact| {
        let mut request = rig.request(
            grant,
            None,
            Mode::Execute,
            RequestBody::Read(ReadRequest {
                artifact_ref: artifact,
                offset: 0,
                len: 64,
            }),
        );
        request.request_id = 7;
        request
    };

    let foreign = rig.call(AGENT, read(outcome.artifact_ref)).await;
    let missing = rig
        .call(AGENT, read(syntheke::ArtifactRef::from_bytes([4; 16])))
        .await;

    assert_eq!(
        failure(&foreign),
        Some(Failure::NotFoundOrDenied),
        "foreign"
    );
    assert_eq!(
        syntheke::encode(&foreign).expect("encode").as_slice(),
        syntheke::encode(&missing).expect("encode").as_slice(),
        "a foreign artifact and a missing one answer the same bytes"
    );
}

#[test]
fn request_digest_ignores_request_id_and_deadline() {
    let base = Request {
        request_id: 1,
        grant: ROOT,
        idempotency_key: Some(super::test_support::idem("digest")),
        mode: Mode::Execute,
        deadline_ms: 1_000,
        body: capture(OK),
    };
    let mut varied = base.clone();
    varied.request_id = 99;
    varied.deadline_ms = 5;
    let mut other_grant = base.clone();
    other_grant.grant = syntheke::GrantId::from_bytes([1; 16]);

    let digest = request_digest(&base).expect("digest");

    assert_eq!(
        request_digest(&varied).expect("digest"),
        digest,
        "same call"
    );
    assert_ne!(
        request_digest(&other_grant).expect("digest"),
        digest,
        "another grant is another call"
    );
}

#[test]
fn cut_text_keeps_character_boundaries() {
    let text = "ééé";

    assert_eq!(
        cut_text(Some(text), 6),
        (Some(text.to_owned()), false),
        "fits"
    );
    assert_eq!(
        cut_text(Some(text), 5),
        (Some("éé".to_owned()), true),
        "cut"
    );
    assert_eq!(
        cut_text(Some(text), 0),
        (Some(String::new()), true),
        "empty"
    );
    assert_eq!(cut_text(None, 0), (None, false), "no text");
}

#[test]
fn fresh_id_leads_with_the_clock_millis() {
    let id = fresh_id(Timestamp::from_unix_millis(0x0102_0304_0506)).expect("id");
    let other = fresh_id(Timestamp::from_unix_millis(0x0102_0304_0506)).expect("id");

    assert_eq!(
        id.get(..6),
        Some(&[1, 2, 3, 4, 5, 6][..]),
        "48-bit time prefix"
    );
    assert_ne!(id, other, "80 random bits differ");
    assert_eq!(
        fresh_id(Timestamp::from_unix_millis(-5))
            .expect("id")
            .get(..6),
        Some(&[0; 6][..]),
        "a time before the epoch clamps to zero"
    );
}

#[tokio::test]
async fn capture_in_progress_replays_in_progress() {
    let rig = Rig::new();
    let (handle, cancel) = signal();
    let request = rig.request(ROOT, Some("in-progress"), Mode::Execute, capture(STALL));
    let replay = request.clone();

    let pending = rig.call_with(OPERATOR, request, cancel, far(), 1 << 20);
    let (first, second) = tokio::join!(pending, async {
        producer_called(&rig.producer, 1).await;
        let response = rig.call(OPERATOR, replay).await;
        handle.cancel();
        response
    });

    assert_eq!(
        second.body,
        ResponseBody::InProgress,
        "a running call replays"
    );
    assert_eq!(second.invocation, first.invocation, "the same invocation");
    assert_eq!(rig.producer.calls(), 1, "never dispatched twice");
    let status = rig
        .store
        .invocation(first.invocation.expect("id"))
        .expect("read")
        .expect("exists");
    assert_eq!(status.state, InvocationState::Released, "then released");
}

#[tokio::test]
async fn exhausted_own_ledger_answers_budget_exceeded() {
    let rig = Rig::new();
    let mut issue = syntheke::GrantIssueRequest {
        holder: OPERATOR,
        capabilities: vec![Capability::Capture],
        session_scope: syntheke::SessionScope::Own,
        target_scope: vec!["example.com".to_owned()],
        ceilings: syntheke::Ceilings::default(),
        not_before: Timestamp::from_unix_millis(0),
        expires_at: Timestamp::from_unix_millis(8_000_000),
        max_depth: None,
    };
    issue.ceilings.fetches = Some(1);
    let request = rig.request(
        ROOT,
        Some("one-fetch"),
        Mode::Execute,
        RequestBody::GrantIssue(issue),
    );
    let ResponseBody::GrantIssued(issued) = rig.call(OPERATOR, request).await.body else {
        panic!("grant not issued");
    };

    let first = rig
        .call(
            OPERATOR,
            rig.request(issued.grant, Some("fetch-1"), Mode::Execute, capture(OK)),
        )
        .await;
    let second = rig
        .call(
            OPERATOR,
            rig.request(issued.grant, Some("fetch-2"), Mode::Execute, capture(OK)),
        )
        .await;

    assert!(
        matches!(first.body, ResponseBody::Captured(_)),
        "the first fetch fits: {first:?}"
    );
    assert_eq!(
        failure(&second),
        Some(Failure::BudgetExceeded {
            dimension: syntheke::Dimension::Fetches
        }),
        "the caller's own grant ledger names the dimension"
    );
    assert_eq!(rig.producer.calls(), 1, "the refused call never dispatched");
}

#[tokio::test]
async fn fork_and_query_answer_within_the_session_scope() {
    let rig = Rig::new();
    let _captured = run(&rig, "query-source", OK).await;
    let fork = RequestBody::SessionFork(syntheke::SessionForkRequest {
        parent_session: super::test_support::SESSION,
    });
    let query = |predicate: &str| {
        RequestBody::Query(syntheke::QueryRequest {
            session_scope: Some(super::test_support::SESSION),
            predicate: predicate.to_owned(),
            limit: 10,
        })
    };

    let forked = rig
        .call(
            OPERATOR,
            rig.request(ROOT, Some("fork"), Mode::Execute, fork),
        )
        .await;
    let all = rig
        .call(OPERATOR, rig.request(ROOT, None, Mode::Execute, query("")))
        .await;
    let none = rig
        .call(
            OPERATOR,
            rig.request(ROOT, None, Mode::Execute, query("absent")),
        )
        .await;

    let ResponseBody::SessionOpened(opened) = forked.body else {
        panic!("fork failed: {forked:?}");
    };
    assert_eq!(
        opened.parent_session,
        Some(super::test_support::SESSION),
        "the fork records its lineage"
    );
    let ResponseBody::QueryPage(all) = all.body else {
        panic!("query failed");
    };
    let ResponseBody::QueryPage(none) = none.body else {
        panic!("query failed");
    };
    assert_eq!(all.result_refs.len(), 1, "the session's one capture");
    assert!(
        none.result_refs.is_empty(),
        "a predicate no text holds matches nothing"
    );
}
