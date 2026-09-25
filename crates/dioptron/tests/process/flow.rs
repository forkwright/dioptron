//! The full flow: session, capture, read, restart, read again, and an
//! unauthorized peer's attempt at the same read.
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use syntheke::{
    ArtifactRef, Capability, CaptureLimits, CaptureRequest, ExtractionClass, Failure, GrantId,
    Mode, ReadRequest, RequestBody, ResponseBody, TransferClass,
};
use xenos::{Client, Error as XenosError, Timeouts, supported_versions};

use crate::test_support::{
    BAD, DOWN, ENVELOPE, Harness, LARGE, OK, RESET, TEXT, agent, bytes, capture, child_grant,
    issue, large_envelope, open_session, operator, stranger,
};

/// Reads a whole artifact in chunks and returns its bytes.
fn read_all(
    harness: &Harness,
    client: &mut Client,
    grant: GrantId,
    artifact: ArtifactRef,
) -> Vec<u8> {
    let mut envelope = Vec::new();
    let mut chunks = 0_u32;
    loop {
        let request = harness.request(
            grant,
            None,
            Mode::Execute,
            RequestBody::Read(ReadRequest {
                artifact_ref: artifact,
                offset: u64::try_from(envelope.len()).expect("offset"),
                len: u32::MAX,
            }),
        );
        let ResponseBody::Chunk(chunk) = client.call(&request).expect("read").body else {
            panic!("read refused");
        };
        assert_eq!(
            chunk.total_len,
            u64::try_from(large_envelope().len()).expect("len"),
            "every chunk reports the envelope length"
        );
        if chunk.bytes.is_empty() {
            break;
        }
        chunks = chunks.saturating_add(1);
        envelope.extend(chunk.bytes);
    }
    assert!(chunks > 2, "a 2.5 MiB envelope needs several 1 MiB frames");
    envelope
}

/// First run: grants for the agent and the stranger, the agent's session
/// and capture of the large target, and a full read; then a clean stop.
/// Returns the agent's grant, the stranger's grant, and the artifact.
fn capture_then_stop(harness: &Harness) -> (GrantId, GrantId, ArtifactRef) {
    let daemon = harness.start();
    let mut operator_client = harness.connect(&operator());
    let capabilities = vec![
        Capability::SessionCreate,
        Capability::Capture,
        Capability::Read,
    ];
    let grant = issue(
        harness,
        &mut operator_client,
        child_grant(agent().id, capabilities),
        "issue-agent",
    );
    let stranger_grant = issue(
        harness,
        &mut operator_client,
        child_grant(stranger().id, vec![Capability::Read]),
        "issue-stranger",
    );
    let mut client = harness.connect(&agent());
    let session = open_session(harness, &mut client, grant, "agent-session");
    let request = harness.request(
        grant,
        Some("capture-large"),
        Mode::Execute,
        capture(session, LARGE),
    );
    let ResponseBody::Captured(outcome) = client.call(&request).expect("capture").body else {
        panic!("capture failed");
    };
    assert_eq!(outcome.source.fingerprint, "fp-large", "evidence identity");
    assert_eq!(
        read_all(harness, &mut client, grant, outcome.artifact_ref),
        large_envelope(),
        "the first read returns the envelope verbatim"
    );
    drop((client, operator_client));
    daemon.stop();
    (grant, stranger_grant, outcome.artifact_ref)
}

#[test]
fn session_capture_read_restart_read_then_unauthorized_peer_is_refused() {
    let harness = Harness::with_cast();
    let (grant, stranger_grant, artifact) = capture_then_stop(&harness);

    let daemon = harness.start();
    let mut client = harness.connect(&agent());
    let reread = read_all(&harness, &mut client, grant, artifact);
    let mut peer = harness.connect(&stranger());
    let read = |artifact| {
        let mut request = harness.request(
            stranger_grant,
            None,
            Mode::Execute,
            RequestBody::Read(ReadRequest {
                artifact_ref: artifact,
                offset: 0,
                len: 1_024,
            }),
        );
        request.request_id = 77;
        request
    };
    let foreign = peer.call(&read(artifact)).expect("foreign read");
    let missing = peer
        .call(&read(ArtifactRef::from_bytes([0x33; 16])))
        .expect("missing read");
    let forged = Client::connect(
        harness.socket(),
        agent().id,
        &stranger().key,
        supported_versions(),
        Timeouts::default(),
    );

    assert_eq!(
        reread,
        large_envelope(),
        "the capture survives a restart verbatim"
    );
    assert_eq!(
        foreign.body,
        ResponseBody::Failed(Failure::NotFoundOrDenied),
        "an unauthorized peer cannot read the artifact"
    );
    assert_eq!(
        bytes(&foreign),
        bytes(&missing),
        "and cannot tell it exists"
    );
    assert!(
        matches!(forged, Err(XenosError::AuthFailed { .. })),
        "a peer that forges the agent's identity is not admitted: {forged:?}"
    );
    assert_eq!(harness.calls(), 1, "one producer call for the whole flow");
    drop(client);
    drop(peer);
    daemon.stop();
}

#[test]
fn producer_outcomes_stay_distinct_and_truncation_is_explicit() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut client = harness.connect(&operator());
    let session = open_session(
        &harness,
        &mut client,
        crate::test_support::ROOT,
        "op-session",
    );
    let cases = [
        (DOWN, Failure::ProducerUnavailable),
        (
            RESET,
            Failure::TransferFailed {
                class: TransferClass::Reset,
            },
        ),
        (
            BAD,
            Failure::ExtractionFailed {
                class: ExtractionClass::Malformed,
            },
        ),
    ];

    for (target, expected) in cases {
        let request = harness.request(
            crate::test_support::ROOT,
            Some(target),
            Mode::Execute,
            capture(session, target),
        );
        let response = client.call(&request).expect("capture");
        assert_eq!(response.body, ResponseBody::Failed(expected), "{target}");
    }
    let cut = RequestBody::Capture(CaptureRequest {
        session,
        target: OK.to_owned(),
        limits: CaptureLimits {
            max_output_bytes: Some(5),
            max_transfer_bytes: None,
        },
        egress_policy: None,
    });
    let request = harness.request(crate::test_support::ROOT, Some("cut"), Mode::Execute, cut);
    let ResponseBody::Captured(outcome) = client.call(&request).expect("capture").body else {
        panic!("capture failed");
    };

    assert!(outcome.truncated, "a cut text view says so");
    assert_eq!(
        outcome.text_view.as_deref(),
        TEXT.get(..5),
        "cut to the bound"
    );
    assert_eq!(outcome.output_bytes, 5, "output bytes counts the kept text");
    let read = harness.request(
        crate::test_support::ROOT,
        None,
        Mode::Execute,
        RequestBody::Read(ReadRequest {
            artifact_ref: outcome.artifact_ref,
            offset: 0,
            len: 4_096,
        }),
    );
    let ResponseBody::Chunk(chunk) = client.call(&read).expect("read").body else {
        panic!("read failed");
    };
    assert_eq!(chunk.bytes, ENVELOPE, "the envelope itself is never cut");
    drop(client);
    daemon.stop();
}

#[test]
fn default_producer_never_fetches() {
    let harness = Harness::with_cast();
    let daemon = harness.start_default();
    let mut client = harness.connect(&operator());
    let session = open_session(
        &harness,
        &mut client,
        crate::test_support::ROOT,
        "op-session",
    );
    let request = harness.request(
        crate::test_support::ROOT,
        Some("default-producer"),
        Mode::Execute,
        capture(session, OK),
    );

    let response = client.call(&request).expect("capture");

    assert_eq!(
        response.body,
        ResponseBody::Failed(Failure::ProducerUnavailable),
        "without an explicit producer nothing is acquired"
    );
    assert_eq!(harness.calls(), 0, "no fixture was consulted");
    drop(client);
    daemon.stop();
}
