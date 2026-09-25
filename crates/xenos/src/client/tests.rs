#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests abort loudly on a failed setup step"
)]

use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer as _};
use syntheke::{
    AUTH_LABEL, Admitted, ArtifactRef, Auth, CaptureLimits, CaptureRequest, ClientHello, Failure,
    Fault, FrameKind, IdempotencyKey, Mode, PRE_AUTH_MAX_BODY, ReadRequest, Request, RequestBody,
    Response, ResponseBody, ServerHello, SessionId, VersionChoice, auth_transcript,
};

use super::*;
use crate::frame::{WireMessage as _, header_bytes};
use crate::peer::{self, LONG, MAX, Peer, SERVER_NONCE, SHORT, TENANT, signing_key};

fn timeouts(bound: Duration) -> Timeouts {
    Timeouts {
        handshake: bound,
        frame: bound,
    }
}

fn connect(stream: UnixStream) -> Result<Client, Error> {
    Client::handshake(stream, TENANT, &signing_key(), 1..=1, timeouts(LONG))
}

fn read_request(request_id: u64) -> Request {
    Request {
        request_id,
        idempotency_key: None,
        mode: Mode::Execute,
        deadline_ms: 30_000,
        body: RequestBody::Read(ReadRequest {
            artifact_ref: ArtifactRef::from_bytes([7; 16]),
            offset: 0,
            len: 4096,
        }),
    }
}

fn capture_request(request_id: u64, target: String, key: Option<IdempotencyKey>) -> Request {
    Request {
        request_id,
        idempotency_key: key,
        mode: Mode::Execute,
        deadline_ms: 30_000,
        body: RequestBody::Capture(CaptureRequest {
            session: SessionId::from_bytes([3; 16]),
            target,
            limits: CaptureLimits::default(),
            egress_policy: None,
        }),
    }
}

fn reply(request_id: u64, body: ResponseBody) -> Response {
    Response {
        request_id,
        invocation: None,
        body,
    }
}

// --- handshake -----------------------------------------------------------

#[test]
fn handshake_admits_and_signs_the_syntheke_transcript() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| peer.admit(MAX));
    let client = connect(stream).expect("admitted");
    let (hello, auth) = script.finish();

    assert_eq!(client.version(), 1, "negotiated version");
    assert_eq!(client.max_frame(), MAX, "negotiated bound");
    assert_eq!(client.timeouts(), timeouts(LONG), "timeouts kept");
    assert_eq!(
        (hello.version_min, hello.version_max),
        (1, 1),
        "offered range"
    );
    assert_eq!(hello.tenant, TENANT, "tenant named in hello");

    // Independent expected transcript, assembled from the contract text.
    let mut expected = Vec::new();
    expected.extend_from_slice(b"dioptron-auth-v1");
    expected.extend_from_slice(&1_u16.to_le_bytes());
    expected.extend_from_slice(&[0x11; 16]);
    expected.extend_from_slice(&hello.client_nonce.to_bytes());
    expected.extend_from_slice(&[0x5a; 16]);
    let transcript = auth_transcript(1, TENANT, &hello.client_nonce, &SERVER_NONCE);
    assert_eq!(&AUTH_LABEL, b"dioptron-auth-v1", "label constant");
    assert_eq!(
        transcript.as_slice(),
        expected.as_slice(),
        "transcript layout"
    );

    let signature = Signature::from_bytes(&auth.signature);
    signing_key()
        .verifying_key()
        .verify_strict(&expected, &signature)
        .expect("signature verifies over the hand-built transcript");
    assert_eq!(
        auth.signature,
        signing_key().sign(&expected).to_bytes(),
        "Ed25519 is deterministic: the client signed exactly the transcript"
    );
}

#[test]
fn handshake_draws_a_fresh_nonce_per_connection() {
    let mut nonces = Vec::new();
    for _ in 0..2 {
        let (stream, script) = peer::spawn(|mut peer: Peer, _| peer.admit(MAX));
        connect(stream).expect("admitted");
        nonces.push(script.finish().0.client_nonce);
    }
    assert_ne!(nonces[0], nonces[1], "client nonces differ");
}

#[test]
fn connect_runs_the_handshake_over_a_socket_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dioptron.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let handle = std::thread::spawn(move || {
        let (server, _) = listener.accept().expect("accept");
        Peer::new(server).admit(MAX)
    });
    let client = Client::connect(&path, TENANT, &signing_key(), 1..=1, timeouts(LONG))
        .expect("admitted over path");
    assert_eq!(client.version(), 1, "negotiated version");
    handle.join().expect("peer thread");
}

#[test]
fn connect_fails_for_a_missing_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("absent.sock");
    let result = Client::connect(&path, TENANT, &signing_key(), 1..=1, timeouts(LONG));
    assert!(
        matches!(&result, Err(Error::Connect { path: p, .. }) if *p == path),
        "got {result:?}"
    );
}

#[test]
fn handshake_reports_incompatible_without_sending_auth() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        let hello: ClientHello = peer.recv();
        peer.send(&ServerHello {
            version: VersionChoice::Incompatible,
            server_nonce: SERVER_NONCE,
            max_frame: PRE_AUTH_MAX_BODY,
        });
        peer.expect_eof();
        hello
    });
    let result = Client::handshake(stream, TENANT, &signing_key(), 7..=9, timeouts(LONG));
    assert!(
        matches!(result, Err(Error::Incompatible { min: 7, max: 9, .. })),
        "got {result:?}"
    );
    drop(result);
    let hello = script.finish();
    assert_eq!(
        (hello.version_min, hello.version_max),
        (7, 9),
        "range offered"
    );
}

#[test]
fn handshake_rejects_a_version_outside_the_offered_range() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        let _: ClientHello = peer.recv();
        peer.send(&ServerHello {
            version: VersionChoice::Chosen(2),
            server_nonce: SERVER_NONCE,
            max_frame: MAX,
        });
        peer.expect_eof();
    });
    let result = connect(stream);
    assert!(
        matches!(
            result,
            Err(Error::VersionOutOfRange {
                chosen: 2,
                min: 1,
                max: 1,
                ..
            })
        ),
        "got {result:?}"
    );
    drop(result);
    script.finish();
}

#[test]
fn handshake_rejects_an_empty_version_range_before_sending() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| peer.expect_eof());
    let (low, high) = (2_u16, 1_u16);
    let result = Client::handshake(stream, TENANT, &signing_key(), low..=high, timeouts(LONG));
    assert!(
        matches!(
            result,
            Err(Error::Contract {
                source: syntheke::Error::InvalidVersionRange { min: 2, max: 1, .. },
                ..
            })
        ),
        "got {result:?}"
    );
    drop(result);
    script.finish();
}

#[test]
fn handshake_reports_auth_failed() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        let _: ClientHello = peer.recv();
        peer.send(&ServerHello {
            version: VersionChoice::Chosen(1),
            server_nonce: SERVER_NONCE,
            max_frame: MAX,
        });
        let _: Auth = peer.recv();
        peer.send(&Fault {
            failure: Failure::AuthFailed,
        });
    });
    let result = connect(stream);
    assert!(
        matches!(result, Err(Error::AuthFailed { .. })),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn handshake_reports_a_protocol_fault() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        let _: ClientHello = peer.recv();
        peer.send(&Fault {
            failure: Failure::ProtocolError,
        });
    });
    let result = connect(stream);
    assert!(
        matches!(
            result,
            Err(Error::Fault {
                failure: Failure::ProtocolError,
                ..
            })
        ),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn handshake_rejects_admitted_before_server_hello() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        let _: ClientHello = peer.recv();
        peer.send(&Admitted);
    });
    let result = connect(stream);
    assert!(
        matches!(
            result,
            Err(Error::UnexpectedFrame {
                expected: FrameKind::ServerHello,
                found: FrameKind::Admitted,
                ..
            })
        ),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn handshake_rejects_a_server_hello_bound_outside_the_contract() {
    // WHY patch bytes: syntheke refuses to encode an out-of-range bound,
    // so a valid body is encoded with a sentinel bound and the sentinel's
    // little-endian bytes are overwritten.
    const SENTINEL: u32 = 0x0012_3456;
    let valid = ServerHello {
        version: VersionChoice::Chosen(1),
        server_nonce: SERVER_NONCE,
        max_frame: SENTINEL,
    }
    .encode_body()
    .expect("encode");
    let at = valid
        .windows(4)
        .position(|window| window == SENTINEL.to_le_bytes())
        .expect("sentinel present");
    for max_frame in [PRE_AUTH_MAX_BODY - 1, syntheke::HARD_MAX_BODY + 1] {
        let mut body = valid.clone();
        body[at..at + 4].copy_from_slice(&max_frame.to_le_bytes());
        let len = u32::try_from(body.len()).expect("len");
        let mut frame = header_bytes(2, 0, 0, len).to_vec();
        frame.extend_from_slice(&body);
        let result = hello_answered_with(frame);
        assert!(
            matches!(
                result,
                Err(Error::Contract {
                    source: syntheke::Error::MaxFrameOutOfRange { max_frame: m, .. },
                    ..
                }) if m == max_frame
            ),
            "max_frame {max_frame}: got {result:?}"
        );
    }
}

#[test]
fn handshake_times_out_on_a_silent_server() {
    let (stream, script) = peer::spawn(|mut peer: Peer, gate| {
        let _: ClientHello = peer.recv();
        gate.wait();
    });
    let result = Client::handshake(stream, TENANT, &signing_key(), 1..=1, timeouts(SHORT));
    assert!(
        matches!(result, Err(Error::Timeout { .. })),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn handshake_times_out_on_a_partial_header() {
    let (stream, script) = peer::spawn(|mut peer: Peer, gate| {
        let _: ClientHello = peer.recv();
        peer.send_bytes(&header_bytes(2, 0, 0, 40)[..5]);
        gate.wait();
    });
    let result = Client::handshake(stream, TENANT, &signing_key(), 1..=1, timeouts(SHORT));
    assert!(
        matches!(result, Err(Error::Timeout { .. })),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn handshake_reports_a_random_source_failure_before_sending() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| peer.expect_eof());
    let result = Client::handshake_with(
        stream,
        TENANT,
        &signing_key(),
        1..=1,
        timeouts(LONG),
        |_| Err(getrandom::Error::new_custom(7)),
    );
    assert!(
        matches!(result, Err(Error::Random { .. })),
        "got {result:?}"
    );
    drop(result);
    script.finish();
}

// --- malicious server frames during the handshake ------------------------

/// Runs a handshake against a server that answers the hello with `bytes`
/// and then closes.
fn hello_answered_with(bytes: Vec<u8>) -> Result<Client, Error> {
    let (stream, script) = peer::spawn(move |mut peer: Peer, _| {
        let _: ClientHello = peer.recv();
        peer.send_bytes(&bytes);
    });
    let result = connect(stream);
    script.finish();
    result
}

#[test]
fn handshake_rejects_malformed_server_headers() {
    let mut bad_magic = header_bytes(2, 0, 0, 0).to_vec();
    bad_magic[0] = b'X';
    let result = hello_answered_with(bad_magic);
    assert!(
        matches!(result, Err(Error::BadMagic { found, .. }) if &found == b"XPT1"),
        "bad magic: got {result:?}"
    );

    let result = hello_answered_with(header_bytes(9, 0, 0, 0).to_vec());
    assert!(
        matches!(result, Err(Error::UnknownFrameKind { kind: 9, .. })),
        "unknown kind: got {result:?}"
    );

    for flags in [0x01, 0x80] {
        let result = hello_answered_with(header_bytes(2, flags, 0, 0).to_vec());
        assert!(
            matches!(result, Err(Error::UnknownFlags { flags: f, .. }) if f == flags),
            "flag {flags:#x}: got {result:?}"
        );
    }

    let result = hello_answered_with(header_bytes(2, 0, 1, 0).to_vec());
    assert!(
        matches!(result, Err(Error::NonzeroReserved { reserved: 1, .. })),
        "reserved: got {result:?}"
    );
}

#[test]
fn handshake_rejects_an_oversize_server_hello_from_the_header_alone() {
    // Only the header is sent: the client must refuse it without waiting
    // for, or allocating, a 4 KiB + 1 body.
    let result = hello_answered_with(header_bytes(2, 0, 0, PRE_AUTH_MAX_BODY + 1).to_vec());
    assert!(
        matches!(
            result,
            Err(Error::FrameTooLarge {
                len: 4097,
                cap: 4096,
                ..
            })
        ),
        "got {result:?}"
    );
}

#[test]
fn handshake_reports_close_at_a_frame_boundary() {
    let result = hello_answered_with(Vec::new());
    assert!(
        matches!(result, Err(Error::Closed { .. })),
        "got {result:?}"
    );
}

#[test]
fn handshake_reports_truncated_header_and_body() {
    let result = hello_answered_with(header_bytes(2, 0, 0, 40)[..7].to_vec());
    assert!(
        matches!(
            result,
            Err(Error::Truncated {
                expected: 12,
                received: 7,
                ..
            })
        ),
        "header: got {result:?}"
    );

    let mut partial = header_bytes(2, 0, 0, 40).to_vec();
    partial.extend_from_slice(&[0; 10]);
    let result = hello_answered_with(partial);
    assert!(
        matches!(
            result,
            Err(Error::Truncated {
                expected: 40,
                received: 10,
                ..
            })
        ),
        "body: got {result:?}"
    );
}

#[test]
fn handshake_rejects_a_corrupt_server_hello_body() {
    let mut frame = header_bytes(2, 0, 0, 3).to_vec();
    frame.extend_from_slice(&[0xff; 3]);
    let result = hello_answered_with(frame);
    assert!(
        matches!(
            result,
            Err(Error::Contract {
                source: syntheke::Error::InvalidArchive { .. },
                ..
            })
        ),
        "got {result:?}"
    );
}

// --- admitted connection -------------------------------------------------

#[test]
fn call_sends_the_request_and_returns_its_response() {
    let request = read_request(9);
    let expected = request.clone();
    let (stream, script) = peer::spawn(move |mut peer: Peer, _| {
        peer.admit(MAX);
        let got: Request = peer.recv();
        peer.send(&reply(got.request_id, ResponseBody::InProgress));
        got
    });
    let mut client = connect(stream).expect("admitted");
    let response = client.call(&request).expect("response");
    assert_eq!(response, reply(9, ResponseBody::InProgress), "response");
    assert_eq!(script.finish(), expected, "request reached the peer intact");
}

#[test]
fn pipelined_requests_and_cancel_reach_the_peer_in_order() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        peer.admit(MAX);
        let first: Request = peer.recv();
        let cancel: syntheke::Cancel = peer.recv();
        peer.send(&reply(
            first.request_id,
            ResponseBody::Failed(Failure::Cancelled),
        ));
        cancel.request_id
    });
    let mut client = connect(stream).expect("admitted");
    client.send_request(&read_request(4)).expect("send");
    client.cancel(4).expect("cancel");
    let response = client.recv_response().expect("response");
    assert_eq!(
        response,
        reply(4, ResponseBody::Failed(Failure::Cancelled)),
        "cancelled outcome"
    );
    assert_eq!(script.finish(), 4, "cancel named the request");
}

#[test]
fn call_rejects_a_response_to_another_request_and_breaks() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        peer.admit(MAX);
        let _: Request = peer.recv();
        peer.send(&reply(99, ResponseBody::InProgress));
    });
    let mut client = connect(stream).expect("admitted");
    let result = client.call(&read_request(1));
    assert!(
        matches!(
            result,
            Err(Error::UnexpectedResponse {
                expected: 1,
                found: 99,
                ..
            })
        ),
        "got {result:?}"
    );
    let next = client.call(&read_request(2));
    assert!(matches!(next, Err(Error::Broken { .. })), "got {next:?}");
    let cancel = client.cancel(2);
    assert!(
        matches!(cancel, Err(Error::Broken { .. })),
        "got {cancel:?}"
    );
    script.finish();
}

#[test]
fn send_request_refuses_locally_and_stays_usable() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        peer.admit(PRE_AUTH_MAX_BODY);
        let got: Request = peer.recv();
        peer.send(&reply(got.request_id, ResponseBody::InProgress));
    });
    let mut client = connect(stream).expect("admitted");

    let key = IdempotencyKey::from_slice(b"tool-call-000000000001").expect("key");
    let big = capture_request(1, "a".repeat(5_000), Some(key));
    let result = client.send_request(&big);
    assert!(
        matches!(result, Err(Error::FrameTooLarge { cap: 4096, .. })),
        "oversize: got {result:?}"
    );

    let unkeyed = capture_request(2, "https://example.com/".to_owned(), None);
    let result = client.send_request(&unkeyed);
    assert!(
        matches!(
            result,
            Err(Error::Contract {
                source: syntheke::Error::MissingIdempotencyKey { .. },
                ..
            })
        ),
        "missing key: got {result:?}"
    );

    let response = client.call(&read_request(3)).expect("still usable");
    assert_eq!(response.request_id, 3, "response after local refusals");
    script.finish();
}

#[test]
fn recv_response_reports_a_fault_then_breaks() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        peer.admit(MAX);
        peer.send(&Fault {
            failure: Failure::ProtocolError,
        });
    });
    let mut client = connect(stream).expect("admitted");
    let result = client.recv_response();
    assert!(
        matches!(
            result,
            Err(Error::Fault {
                failure: Failure::ProtocolError,
                ..
            })
        ),
        "got {result:?}"
    );
    let next = client.recv_response();
    assert!(matches!(next, Err(Error::Broken { .. })), "got {next:?}");
    script.finish();
}

#[test]
fn recv_response_enforces_the_negotiated_bound() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        peer.admit(PRE_AUTH_MAX_BODY);
        peer.send_bytes(&header_bytes(7, 0, 0, PRE_AUTH_MAX_BODY + 1));
    });
    let mut client = connect(stream).expect("admitted");
    let result = client.recv_response();
    assert!(
        matches!(
            result,
            Err(Error::FrameTooLarge {
                len: 4097,
                cap: 4096,
                ..
            })
        ),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn recv_response_rejects_a_client_kind_from_the_server() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        peer.admit(MAX);
        peer.send(&syntheke::Cancel { request_id: 1 });
    });
    let mut client = connect(stream).expect("admitted");
    let result = client.recv_response();
    assert!(
        matches!(
            result,
            Err(Error::UnexpectedFrame {
                expected: FrameKind::Response,
                found: FrameKind::Cancel,
                ..
            })
        ),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn recv_response_times_out_and_breaks() {
    let (stream, script) = peer::spawn(|mut peer: Peer, gate| {
        peer.admit(MAX);
        gate.wait();
    });
    let mut client = connect(stream).expect("admitted");
    client.timeouts.frame = SHORT;
    let result = client.recv_response();
    assert!(
        matches!(result, Err(Error::Timeout { .. })),
        "got {result:?}"
    );
    let next = client.recv_response();
    assert!(matches!(next, Err(Error::Broken { .. })), "got {next:?}");
    script.finish();
}

#[test]
fn into_raw_hands_over_the_admitted_connection() {
    let (stream, script) = peer::spawn(|mut peer: Peer, _| {
        peer.admit(MAX);
        let (header, body) = peer.recv_raw();
        (header.kind(), body)
    });
    let client = connect(stream).expect("admitted");
    let mut raw = client.into_raw();
    raw.send_frame(&header_bytes(6, 0, 0, 2), &[1, 2])
        .expect("raw send");
    let (kind, body) = script.finish();
    assert_eq!(kind, FrameKind::Cancel, "raw header kind");
    assert_eq!(body, vec![1, 2], "raw body unchanged");
}

#[test]
fn supported_versions_is_the_wire_version() {
    assert_eq!(supported_versions(), 1..=1, "wire version 1 only");
    assert_eq!(
        Timeouts::default().handshake,
        Duration::from_secs(5),
        "contract handshake bound"
    );
}
