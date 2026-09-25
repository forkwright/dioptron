#![expect(
    clippy::expect_used,
    reason = "tests abort loudly on a failed setup step"
)]

use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use syntheke::{
    Admitted, Cancel, DEFAULT_MAX_BODY, Failure, Fault, FrameKind, PRE_AUTH_MAX_BODY, ServerHello,
    VersionChoice,
};

use super::*;
use crate::frame::header_bytes;
use crate::test_support::{self as support, LONG, Peer, SERVER_NONCE, SHORT};

fn raw_pair<T, F>(script: F) -> (RawConn, support::Scripted<T>)
where
    T: Send + 'static,
    F: FnOnce(Peer, support::Gate) -> T + Send + 'static,
{
    let (stream, scripted) = support::spawn(script);
    (RawConn::from_stream(stream, LONG), scripted)
}

#[test]
fn raw_send_bytes_delivers_arbitrary_bytes() {
    let (mut raw, script) = raw_pair(|mut peer: Peer, _| {
        let (header, body) = peer.recv_raw();
        (header.kind(), body)
    });
    // A request-kind frame before any handshake: the raw connection keeps
    // no protocol state and sends it.
    raw.send_bytes(&header_bytes(5, 0, 0, 3)[..4])
        .expect("first half");
    raw.send_bytes(&header_bytes(5, 0, 0, 3)[4..])
        .expect("second half");
    raw.send_bytes(&[9, 8, 7]).expect("body");
    let (kind, body) = script.finish();
    assert_eq!(kind, FrameKind::Request, "kind reassembled from pieces");
    assert_eq!(body, vec![9, 8, 7], "body");
}

#[test]
fn raw_send_message_and_read_message_round_trip() {
    let (mut raw, script) = raw_pair(|mut peer: Peer, _| {
        let cancel: Cancel = peer.recv();
        peer.send(&ServerHello {
            version: VersionChoice::Chosen(1),
            server_nonce: SERVER_NONCE,
            max_frame: PRE_AUTH_MAX_BODY,
        });
        cancel
    });
    raw.send_message(&Cancel { request_id: 3 }, PRE_AUTH_MAX_BODY)
        .expect("send");
    let hello: ServerHello = raw.read_message(PRE_AUTH_MAX_BODY).expect("read");
    assert_eq!(hello.server_nonce, SERVER_NONCE, "server nonce");
    assert_eq!(script.finish().request_id, 3, "cancel id");
}

#[test]
fn raw_read_message_maps_a_fault_frame() {
    let (mut raw, script) = raw_pair(|mut peer: Peer, _| {
        peer.send(&Fault {
            failure: Failure::AuthFailed,
        });
    });
    let result = raw.read_message::<Admitted>(PRE_AUTH_MAX_BODY);
    assert!(
        matches!(result, Err(Error::AuthFailed { .. })),
        "got {result:?}"
    );
    raw.expect_close().expect("peer closed after the fault");
    script.finish();
}

#[test]
fn raw_expect_close_reports_data_and_timeout() {
    let (mut raw, script) = raw_pair(|mut peer: Peer, gate| {
        peer.send_bytes(&[1]);
        gate.wait();
    });
    let result = raw.expect_close();
    assert!(
        matches!(result, Err(Error::NotClosed { .. })),
        "got {result:?}"
    );
    raw.set_timeout(SHORT);
    assert_eq!(raw.timeout(), SHORT, "timeout accessor");
    let result = raw.expect_close();
    assert!(
        matches!(result, Err(Error::Timeout { .. })),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn raw_read_frame_times_out_on_a_stalled_body() {
    let (mut raw, script) = raw_pair(|mut peer: Peer, gate| {
        peer.send_bytes(&header_bytes(7, 0, 0, 8));
        peer.send_bytes(&[0; 3]);
        gate.wait();
    });
    raw.set_timeout(SHORT);
    let result = raw.read_frame(DEFAULT_MAX_BODY);
    assert!(
        matches!(result, Err(Error::Timeout { .. })),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn raw_read_deadline_bounds_the_whole_frame_against_a_trickling_peer() {
    // The peer sends one byte every TRICKLE_GAP, far below the timeout, and
    // needs about 4096 gaps to finish the frame. Only a deadline over the
    // whole frame fires while bytes are still arriving.
    let (mut raw, script) = raw_pair(|mut peer: Peer, _| {
        let mut frame = header_bytes(7, 0, 0, 4096).to_vec();
        frame.resize(12 + 4096, 0);
        peer.trickle(&frame)
    });
    raw.set_timeout(SHORT);
    let result = raw.read_frame(DEFAULT_MAX_BODY).map(|frame| frame.kind());
    assert!(
        matches!(result, Err(Error::Timeout { .. })),
        "got {result:?}"
    );
    drop(raw);
    assert!(
        script.finish(),
        "the client gave up while the peer was still trickling"
    );
}

#[test]
fn raw_send_deadline_bounds_the_whole_write_against_a_slow_reader() {
    // The peer drains 16 KiB per TRICKLE_GAP, so a timeout on each write
    // call would never fire and 32 MiB would finish in seconds. The
    // deadline over the whole send fires first.
    let (mut raw, script) = raw_pair(|mut peer: Peer, _| peer.drain_slowly(16 * 1024));
    raw.set_timeout(SHORT);
    let bytes = vec![0_u8; 32 * 1024 * 1024];
    let result = raw.send_bytes(&bytes);
    assert!(
        matches!(result, Err(Error::Timeout { .. })),
        "got {result:?}"
    );
    drop(raw);
    let drained = script.finish();
    assert!(
        drained < bytes.len(),
        "peer read {drained} of {} bytes",
        bytes.len()
    );
}

#[test]
fn raw_zero_timeout_fails_closed() {
    let (mut raw, script) = raw_pair(|mut peer: Peer, _| peer.expect_eof());
    raw.set_timeout(Duration::ZERO);
    let send = raw.send_bytes(&[1]);
    assert!(
        matches!(send, Err(Error::Timeout { .. })),
        "send: got {send:?}"
    );
    let read = raw.read_frame(PRE_AUTH_MAX_BODY);
    assert!(
        matches!(read, Err(Error::Timeout { .. })),
        "read: got {read:?}"
    );
    drop(raw);
    script.finish();
}

#[test]
fn raw_send_after_shutdown_is_an_io_error() {
    let (mut raw, script) = raw_pair(|mut peer: Peer, _| peer.expect_eof());
    raw.shutdown_write().expect("shutdown");
    let result = raw.send_bytes(&[1]);
    assert!(
        matches!(&result, Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::BrokenPipe),
        "got {result:?}"
    );
    script.finish();
}

#[test]
fn raw_connect_reaches_a_listener_and_reports_a_missing_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raw.sock");
    let missing = RawConn::connect(&path, LONG);
    assert!(
        matches!(&missing, Err(Error::Connect { path: p, .. }) if *p == path),
        "got {missing:?}"
    );

    let listener = UnixListener::bind(&path).expect("bind");
    let raw = RawConn::connect(&path, LONG).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    drop(server);
    let mut raw = RawConn::from_stream(raw.into_stream(), LONG);
    raw.expect_close().expect("server closed");
    let result = raw.read_frame(PRE_AUTH_MAX_BODY);
    assert!(
        matches!(result, Err(Error::Closed { .. })),
        "got {result:?}"
    );
    let _: &UnixStream = raw.stream();
}
