//! Requests, cancels, and responses on an admitted connection.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests abort loudly on a failed setup step"
)]

use syntheke::{Failure, Fault, FrameKind, PRE_AUTH_MAX_BODY, ReadChunk};

use super::*;
use crate::frame::{WireMessage as _, header_bytes};
use crate::test_support::{self as support, MAX, Peer, SHORT};

#[test]
fn call_sends_the_request_and_returns_its_response() {
    let request = read_request(9);
    let expected = request.clone();
    let (stream, script) = support::spawn(move |mut peer: Peer, _| {
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
fn admitted_connection_uses_the_negotiated_bound_both_ways() {
    // Both frames exceed the 4 KiB pre-auth bound and fit the 1 MiB one.
    let key = IdempotencyKey::from_slice(b"tool-call-000000000002").expect("key");
    let request = capture_request(5, "a".repeat(8_000), Some(key));
    let expected = request.clone();
    let chunk = ResponseBody::Chunk(ReadChunk {
        offset: 0,
        bytes: vec![0xab; 8_192],
        total_len: 8_192,
    });
    let sent = chunk.clone();
    let (stream, script) = support::spawn(move |mut peer: Peer, _| {
        peer.admit(MAX);
        let (header, body) = peer.recv_raw();
        peer.send(&reply(5, sent));
        (
            header.len(),
            Request::decode_body(&body, MAX).expect("decode"),
        )
    });
    let mut client = connect(stream).expect("admitted");
    let response = client.call(&request).expect("large response accepted");
    assert_eq!(response, reply(5, chunk), "response");
    let (len, received) = script.finish();
    assert!(len > PRE_AUTH_MAX_BODY, "request body was {len} bytes");
    assert_eq!(received, expected, "large request reached the peer intact");
}

#[test]
fn pipelined_requests_and_cancel_reach_the_peer_in_order() {
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
fn recv_response_rejects_a_fault_with_a_request_level_failure() {
    // WHY patch bytes: syntheke refuses to encode such a fault. The two
    // valid faults differ only in the failure tag byte; that byte is set to
    // the tag of `Cancelled` (declaration index 9), a unit variant.
    let protocol = Fault {
        failure: Failure::ProtocolError,
    }
    .encode_body()
    .expect("encode");
    let auth = Fault {
        failure: Failure::AuthFailed,
    }
    .encode_body()
    .expect("encode");
    let differing: Vec<usize> = (0..protocol.len())
        .filter(|&at| protocol[at] != auth[at])
        .collect();
    assert_eq!(differing.len(), 1, "faults differ in one tag byte");
    let mut body = protocol;
    body[differing[0]] = 9;
    let len = u32::try_from(body.len()).expect("len");
    let (stream, script) = support::spawn(move |mut peer: Peer, _| {
        peer.admit(MAX);
        peer.send_bytes(&header_bytes(8, 0, 0, len));
        peer.send_bytes(&body);
    });
    let mut client = connect(stream).expect("admitted");
    let result = client.recv_response();
    assert!(
        matches!(
            result,
            Err(Error::Contract {
                source: syntheke::Error::FaultNotConnectionLevel {
                    kind: syntheke::OutcomeKind::Cancelled,
                    ..
                },
                ..
            })
        ),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn recv_response_reports_a_fault_then_breaks() {
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, gate| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
