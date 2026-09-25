//! Cross-tenant read and metadata denial: a foreign resource and a
//! missing one answer the same bytes (contract § The non-leak rule).
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use syntheke::{
    ArtifactRef, AuditQueryRequest, AuditScope, Capability, DenyCode, Failure, GrantId,
    IngestRequest, Mode, QueryRequest, ReadRequest, Request, RequestBody, ResponseBody,
    SessionForkRequest, SessionId,
};

use xenos::Client;

use crate::test_support::{
    Harness, OK, ROOT, agent, bytes, capture, child_grant, issue, open_session, operator, stranger,
};

const EVERY: [Capability; 6] = [
    Capability::SessionCreate,
    Capability::SessionFork,
    Capability::Capture,
    Capability::Read,
    Capability::Query,
    Capability::AuditQuery,
];

fn pinned(mut request: Request) -> Request {
    request.request_id = 4_242;
    request
}

fn read(artifact: ArtifactRef) -> RequestBody {
    RequestBody::Read(ReadRequest {
        artifact_ref: artifact,
        offset: 0,
        len: 64,
    })
}

fn query(session: SessionId) -> RequestBody {
    RequestBody::Query(QueryRequest {
        session_scope: Some(session),
        predicate: String::new(),
        limit: 10,
    })
}

fn fork(parent_session: SessionId) -> RequestBody {
    RequestBody::SessionFork(SessionForkRequest { parent_session })
}

fn audit(session: SessionId) -> RequestBody {
    RequestBody::AuditQuery(AuditQueryRequest {
        audit_scope: AuditScope::All,
        session: Some(session),
        after: None,
        limit: 10,
    })
}

/// Grants for the agent and the stranger, and the agent's session.
fn cast_grants(harness: &Harness, operator_client: &mut Client) -> (GrantId, GrantId) {
    let agent_grant = issue(
        harness,
        operator_client,
        child_grant(agent().id, EVERY.to_vec()),
        "issue-agent",
    );
    let stranger_grant = issue(
        harness,
        operator_client,
        child_grant(stranger().id, EVERY.to_vec()),
        "issue-stranger",
    );
    (agent_grant, stranger_grant)
}

#[test]
fn foreign_and_missing_resources_answer_identical_bytes() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut operator_client = harness.connect(&operator());
    let (agent_grant, stranger_grant) = cast_grants(&harness, &mut operator_client);
    let mut owner = harness.connect(&agent());
    let session = open_session(&harness, &mut owner, agent_grant, "agent-session");
    let request = harness.request(
        agent_grant,
        Some("agent-capture"),
        Mode::Execute,
        capture(session, OK),
    );
    let ResponseBody::Captured(outcome) = owner.call(&request).expect("capture").body else {
        panic!("capture failed");
    };
    let missing_session = SessionId::from_bytes([0x66; 16]);
    let missing_artifact = ArtifactRef::from_bytes([0x67; 16]);
    let mut peer = harness.connect(&stranger());
    let mut ask = |grant: GrantId, key: Option<&str>, body: RequestBody| {
        let request = pinned(harness.request(grant, key, Mode::Execute, body));
        bytes(&peer.call(&request).expect("call"))
    };
    let pairs = [
        (
            "read an artifact",
            ask(stranger_grant, None, read(outcome.artifact_ref)),
            ask(stranger_grant, None, read(missing_artifact)),
        ),
        (
            "query a session",
            ask(stranger_grant, None, query(session)),
            ask(stranger_grant, None, query(missing_session)),
        ),
        (
            "fork a session",
            ask(stranger_grant, Some("fork-a"), fork(session)),
            ask(stranger_grant, Some("fork-b"), fork(missing_session)),
        ),
        (
            "capture into a session",
            ask(stranger_grant, Some("cap-a"), capture(session, OK)),
            ask(stranger_grant, Some("cap-b"), capture(missing_session, OK)),
        ),
        (
            "audit a session",
            ask(stranger_grant, None, audit(session)),
            ask(stranger_grant, None, audit(missing_session)),
        ),
        (
            "designate a grant",
            ask(agent_grant, None, read(outcome.artifact_ref)),
            ask(
                GrantId::from_bytes([0x68; 16]),
                None,
                read(outcome.artifact_ref),
            ),
        ),
    ];

    let refusal = bytes(&syntheke::Response {
        request_id: 4_242,
        invocation: None,
        body: ResponseBody::Failed(Failure::NotFoundOrDenied),
    });
    for (what, foreign, missing) in &pairs {
        assert_eq!(
            foreign, &refusal,
            "{what}: the foreign case is NotFoundOrDenied"
        );
        assert_eq!(
            foreign, missing,
            "{what}: foreign and missing are byte-identical"
        );
    }
    assert_eq!(
        harness.calls(),
        1,
        "no refused capture reached the producer"
    );
    drop((owner, peer, operator_client));
    daemon.stop();
}

#[test]
fn audit_reads_stay_inside_the_granted_scope() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut operator_client = harness.connect(&operator());
    let (agent_grant, stranger_grant) = cast_grants(&harness, &mut operator_client);
    let mut owner = harness.connect(&agent());
    let _session = open_session(&harness, &mut owner, agent_grant, "agent-session");
    let mut peer = harness.connect(&stranger());
    let _other = open_session(&harness, &mut peer, stranger_grant, "stranger-session");
    let all = |grant| {
        harness.request(
            grant,
            None,
            Mode::Execute,
            RequestBody::AuditQuery(AuditQueryRequest {
                audit_scope: AuditScope::All,
                session: None,
                after: None,
                limit: 100,
            }),
        )
    };

    let ResponseBody::AuditPage(peer_page) = peer.call(&all(stranger_grant)).expect("audit").body
    else {
        panic!("audit refused");
    };
    let ResponseBody::AuditPage(operator_page) = operator_client
        .call(&all(crate::test_support::ROOT))
        .expect("audit")
        .body
    else {
        panic!("audit refused");
    };

    assert_eq!(
        peer_page.scope_applied,
        AuditScope::OwnAndOwnedSessions,
        "an agent's default audit scope (D17.7) narrows a request for All"
    );
    assert!(
        peer_page
            .records
            .iter()
            .all(|record| record.tenant == stranger().id),
        "the stranger sees none of the agent's records"
    );
    assert_eq!(
        operator_page.scope_applied,
        AuditScope::All,
        "the operator reads All"
    );
    assert!(
        operator_page
            .records
            .iter()
            .any(|record| record.tenant == agent().id),
        "including the agent's records"
    );
    drop((owner, peer, operator_client));
    daemon.stop();
}

#[test]
fn ingest_is_not_supported_whatever_the_artifact() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut operator_client = harness.connect(&operator());
    let (agent_grant, _) = cast_grants(&harness, &mut operator_client);
    let mut owner = harness.connect(&agent());
    let session = open_session(&harness, &mut owner, agent_grant, "agent-session");
    let request = harness.request(
        agent_grant,
        Some("agent-capture"),
        Mode::Execute,
        capture(session, OK),
    );
    let ResponseBody::Captured(outcome) = owner.call(&request).expect("capture").body else {
        panic!("capture failed");
    };
    let mut ingest = |key: &str, artifact| {
        let body = RequestBody::Ingest(IngestRequest {
            artifact_ref: artifact,
        });
        let request = pinned(harness.request(ROOT, Some(key), Mode::Execute, body));
        bytes(&operator_client.call(&request).expect("ingest"))
    };

    let existing = ingest("ingest-a", outcome.artifact_ref);
    let missing = ingest("ingest-b", ArtifactRef::from_bytes([0x69; 16]));

    let refusal = bytes(&syntheke::Response {
        request_id: 4_242,
        invocation: None,
        body: ResponseBody::Failed(Failure::denied(DenyCode::NotSupported)),
    });
    assert_eq!(existing, refusal, "Ingest is refused as not supported");
    assert_eq!(existing, missing, "the artifact is never consulted");
    drop((owner, operator_client));
    daemon.stop();
}
