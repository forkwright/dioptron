//! The handshake, including a hostile or slow server during it.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests abort loudly on a failed setup step"
)]

use std::os::unix::net::UnixListener;

use ed25519_dalek::{Signature, Signer as _};
use syntheke::{
    AUTH_LABEL, Admitted, Auth, ClientHello, Failure, Fault, FrameKind, PRE_AUTH_MAX_BODY,
    ServerHello, VersionChoice, auth_transcript,
};

use super::*;
use crate::frame::{WireMessage as _, header_bytes};
use crate::test_support::{self as support, MAX, Peer, SERVER_NONCE, SHORT};

#[test]
fn handshake_admits_and_signs_the_syntheke_transcript() {
    let (stream, script) = support::spawn(|mut peer: Peer, _| peer.admit(MAX));
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
        let (stream, script) = support::spawn(|mut peer: Peer, _| peer.admit(MAX));
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
    // Above, then below, the offered range; the client sends no auth.
    for (offered, chosen) in [((1, 1), 2), ((2, 3), 1)] {
        let (stream, script) = support::spawn(move |mut peer: Peer, _| {
            let _: ClientHello = peer.recv();
            peer.send(&ServerHello {
                version: VersionChoice::Chosen(chosen),
                server_nonce: SERVER_NONCE,
                max_frame: MAX,
            });
            peer.expect_eof();
        });
        let (min, max) = offered;
        let result = Client::handshake(stream, TENANT, &signing_key(), min..=max, timeouts(LONG));
        assert!(
            matches!(
                result,
                Err(Error::VersionOutOfRange { chosen: c, min: lo, max: hi, .. })
                    if (c, lo, hi) == (chosen, min, max)
            ),
            "offered {min}..={max}, chosen {chosen}: got {result:?}"
        );
        drop(result);
        script.finish();
    }
}

#[test]
fn handshake_rejects_an_empty_version_range_before_sending() {
    let (stream, script) = support::spawn(|mut peer: Peer, _| peer.expect_eof());
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| {
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
    // An `Incompatible` hello must carry a valid bound too.
    const SENTINEL: u32 = 0x0012_3456;
    for version in [VersionChoice::Chosen(1), VersionChoice::Incompatible] {
        let valid = ServerHello {
            version,
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
                "{version:?} max_frame {max_frame}: got {result:?}"
            );
        }
    }
}

#[test]
fn handshake_deadline_bounds_the_whole_handshake() {
    // The peer holds each of its two frames for 60 % of the handshake
    // bound. Every frame arrives within its own share of the bound, so only
    // a deadline over the whole handshake fires; the frame bound is long.
    // WHY the sleeps: they pace the peer, and slowing the host only delays
    // the frames further, so the expected outcome cannot flip.
    let hold = SHORT * 3 / 5;
    let (stream, script) = support::spawn(move |mut peer: Peer, _| {
        let _: ClientHello = peer.recv();
        std::thread::sleep(hold);
        peer.send(&ServerHello {
            version: VersionChoice::Chosen(1),
            server_nonce: SERVER_NONCE,
            max_frame: MAX,
        });
        if peer.try_recv_raw().is_some() {
            std::thread::sleep(hold);
            let frame = syntheke::encode_frame(&Admitted, PRE_AUTH_MAX_BODY).expect("encode");
            // NOTE: the client may already have closed.
            let _ = peer.try_send_bytes(&frame);
        }
    });
    let bounds = Timeouts {
        handshake: SHORT,
        frame: LONG,
    };
    let result = Client::handshake(stream, TENANT, &signing_key(), 1..=1, bounds);
    assert!(
        matches!(result, Err(Error::Timeout { .. })),
        "got {result:?}"
    );
    drop(result);
    script.finish();
}

#[test]
fn handshake_restores_blocking_mode_on_a_nonblocking_stream() {
    let (stream, script) = support::spawn(|mut peer: Peer, _| peer.admit(MAX));
    stream.set_nonblocking(true).expect("nonblocking");
    let client = connect(stream).expect("admitted despite the nonblocking stream");
    assert_eq!(client.version(), 1, "negotiated version");
    script.finish();
}

#[test]
fn handshake_times_out_on_a_silent_server() {
    let (stream, script) = support::spawn(|mut peer: Peer, gate| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, gate| {
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
    let (stream, script) = support::spawn(|mut peer: Peer, _| peer.expect_eof());
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

/// Runs a handshake against a server that answers the hello with `bytes`
/// and then closes.
fn hello_answered_with(bytes: Vec<u8>) -> Result<Client, Error> {
    let (stream, script) = support::spawn(move |mut peer: Peer, _| {
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
fn handshake_holds_admitted_and_fault_to_the_pre_auth_bound() {
    // The hello negotiated 1 MiB, but that bound starts only after
    // `Admitted`; until then every frame is capped at 4 KiB.
    for kind in [FrameKind::Admitted, FrameKind::Fault] {
        let (stream, script) = support::spawn(move |mut peer: Peer, _| {
            let _: ClientHello = peer.recv();
            peer.send(&ServerHello {
                version: VersionChoice::Chosen(1),
                server_nonce: SERVER_NONCE,
                max_frame: MAX,
            });
            let _: Auth = peer.recv();
            peer.send_bytes(&header_bytes(kind.to_u8(), 0, 0, PRE_AUTH_MAX_BODY + 1));
        });
        let result = connect(stream);
        assert!(
            matches!(
                result,
                Err(Error::FrameTooLarge {
                    len: 4097,
                    cap: 4096,
                    ..
                })
            ),
            "{kind:?}: got {result:?}"
        );
        drop(result);
        script.finish();
    }
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
