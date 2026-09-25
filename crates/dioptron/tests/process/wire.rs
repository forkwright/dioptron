//! Frame corruption, oversize, incompatible version, and partial
//! connections against the daemon binary (contract § Wire protocol).
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use std::time::Duration;

use syntheke::{
    ClientHello, Failure, Fault, FrameKind, HARD_MAX_BODY, MAGIC, Nonce, PRE_AUTH_MAX_BODY,
    ServerHello, VersionChoice, WIRE_VERSION,
};
use xenos::{RawConn, header_bytes};

use crate::test_support::{Harness, operator};

const TIMEOUT: Duration = Duration::from_secs(15);

/// Reads the one fault a violation earns and checks the close after it.
fn protocol_error(conn: &mut RawConn, cap: u32, case: &str) {
    let fault: Fault = conn.read_message(cap).expect("a fault frame");
    assert_eq!(
        fault.failure,
        Failure::ProtocolError,
        "{case}: ProtocolError"
    );
    conn.expect_close()
        .expect("the daemon closes after the fault");
}

#[test]
fn incompatible_version_range_is_answered_before_authentication() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut conn = RawConn::connect(harness.socket(), TIMEOUT).expect("connect");
    let hello = ClientHello {
        version_min: WIRE_VERSION.saturating_add(1),
        version_max: WIRE_VERSION.saturating_add(3),
        tenant: operator().id,
        client_nonce: Nonce::from_bytes([1; 16]),
    };

    conn.send_message(&hello, PRE_AUTH_MAX_BODY).expect("hello");
    let reply: ServerHello = conn.read_message(PRE_AUTH_MAX_BODY).expect("server hello");

    assert_eq!(
        reply.version,
        VersionChoice::Incompatible,
        "no common version"
    );
    assert!(
        (PRE_AUTH_MAX_BODY..=HARD_MAX_BODY).contains(&reply.max_frame),
        "the refusal still carries a valid frame bound"
    );
    conn.expect_close().expect("the handshake ends");
    daemon.stop();
}

#[test]
fn corrupt_and_oversized_frames_before_admission_get_one_protocol_error() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut bad_magic = header_bytes(1, 0, 0, 4);
    bad_magic[..4].copy_from_slice(b"XPT1");
    let cases: [(&str, [u8; 12]); 5] = [
        ("bad magic", bad_magic),
        ("unknown kind", header_bytes(9, 0, 0, 4)),
        ("unknown flag", header_bytes(1, 0x80, 0, 4)),
        ("nonzero reserved", header_bytes(1, 0, 1, 4)),
        (
            "over the pre-auth cap",
            header_bytes(1, 0, 0, PRE_AUTH_MAX_BODY.saturating_add(1)),
        ),
    ];

    for (case, header) in cases {
        let mut conn = RawConn::connect(harness.socket(), TIMEOUT).expect("connect");
        // NOTE: the header alone is sent: an oversized length must be
        // refused before the daemon waits for, or allocates, the body.
        conn.send_bytes(&header).expect("header");
        protocol_error(&mut conn, PRE_AUTH_MAX_BODY, case);
    }
    assert_eq!(&MAGIC, b"DPT1", "the magic the valid frames carry");
    daemon.stop();
}

#[test]
fn corrupt_and_oversized_frames_after_admission_get_one_protocol_error() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let cases: [(&str, Vec<u8>); 3] = [
        ("over the negotiated bound", Vec::new()),
        ("over the hard maximum", Vec::new()),
        ("corrupt request body", vec![0xa5; 64]),
    ];

    for (case, body) in cases {
        let client = harness.connect(&operator());
        let bound = client.max_frame();
        let mut conn = client.into_raw();
        let len = match case {
            "over the negotiated bound" => bound.saturating_add(1),
            "over the hard maximum" => HARD_MAX_BODY.saturating_add(1),
            _ => u32::try_from(body.len()).expect("len"),
        };
        let mut frame = header_bytes(FrameKind::Request.to_u8(), 0, 0, len).to_vec();
        frame.extend_from_slice(&body);
        conn.send_bytes(&frame).expect("frame");
        protocol_error(&mut conn, bound, case);
    }
    let mut healthy = harness.connect(&operator());
    let request = harness.request(
        crate::test_support::ROOT,
        None,
        syntheke::Mode::DryRun,
        syntheke::RequestBody::SessionCreate,
    );
    assert!(
        healthy.call(&request).is_ok(),
        "the daemon keeps serving after refusing bad frames"
    );
    drop(healthy);
    daemon.stop();
}

#[test]
fn partial_connections_close_without_disturbing_the_daemon() {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let header = header_bytes(FrameKind::ClientHello.to_u8(), 0, 0, 40);

    let mut abandoned = RawConn::connect(harness.socket(), TIMEOUT).expect("connect");
    abandoned.send_bytes(&header[..5]).expect("partial header");
    abandoned.shutdown_write().expect("half close");
    let closed = abandoned.read_frame(PRE_AUTH_MAX_BODY);
    let mut stalled = RawConn::connect(harness.socket(), TIMEOUT).expect("connect");
    stalled.send_bytes(&header[..7]).expect("partial header");
    let mut client = harness.connect(&operator());
    let request = harness.request(
        crate::test_support::ROOT,
        None,
        syntheke::Mode::DryRun,
        syntheke::RequestBody::SessionCreate,
    );
    let served = client.call(&request);

    assert!(closed.is_err(), "a peer that closes mid-frame is dropped");
    assert!(
        served.is_ok(),
        "other clients are served meanwhile: {served:?}"
    );
    // NOTE: the stalled peer is cut off by the contract's 5 s handshake
    // bound with a single ProtocolError.
    protocol_error(&mut stalled, PRE_AUTH_MAX_BODY, "partial frame");
    drop(client);
    daemon.stop();
}
