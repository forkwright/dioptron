//! Framing after admission: header validation, bounds checked before
//! allocation, body validation, and partial-frame timeouts.

use std::time::Duration;

use syntheke::{
    CaptureLimits, CaptureRequest, EgressPolicy, Failure, FrameHeader, FrameKind, HEADER_LEN,
    IdempotencyKey, Mode, RequestBody, SessionId, encode,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::Instant;

use super::super::frame::{ReadFail, read_frame};
use super::super::test_support::{
    Harness, SHORT, TestResult, assert_fired, header, immediate, kind, limits, request,
};

/// Sends `bytes` on an admitted connection and expects one
/// `Fault(ProtocolError)`, then close.
async fn rejected(bytes: &[u8]) -> TestResult {
    let harness = Harness::start(limits(), immediate)?;
    let mut client = harness.admitted().await?;
    client.send_raw(bytes).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "a single protocol fault");
    Ok(())
}

#[tokio::test]
async fn bad_magic_is_a_protocol_error() -> TestResult {
    rejected(&[b'D', b'P', b'T', b'2', kind::REQUEST, 0, 0, 0, 0, 0, 0, 0]).await
}

#[tokio::test]
async fn unknown_flag_bits_are_a_protocol_error() -> TestResult {
    rejected(&[
        b'D',
        b'P',
        b'T',
        b'1',
        kind::REQUEST,
        0x01,
        0,
        0,
        0,
        0,
        0,
        0,
    ])
    .await
}

#[tokio::test]
async fn nonzero_reserved_field_is_a_protocol_error() -> TestResult {
    rejected(&[b'D', b'P', b'T', b'1', kind::REQUEST, 0, 0, 1, 0, 0, 0, 0]).await
}

#[tokio::test]
async fn unknown_kind_is_a_protocol_error() -> TestResult {
    rejected(&header(9, 0)).await
}

#[tokio::test]
async fn handshake_kinds_after_admission_are_protocol_errors() -> TestResult {
    rejected(&header(kind::CLIENT_HELLO, 0)).await?;
    rejected(&header(kind::ADMITTED, 0)).await
}

#[tokio::test]
async fn corrupted_request_body_is_a_protocol_error() -> TestResult {
    let mut frame = header(kind::REQUEST, 64).to_vec();
    frame.extend_from_slice(&[0xa5; 64]);
    rejected(&frame).await
}

#[tokio::test]
async fn truncated_request_archive_is_a_protocol_error() -> TestResult {
    let body = encode(&request(1, 1_000))?;
    let short = body
        .get(..body.len().saturating_sub(8))
        .ok_or("short body")?;
    let mut frame = header(kind::REQUEST, u32::try_from(short.len())?).to_vec();
    frame.extend_from_slice(short);
    rejected(&frame).await
}

#[tokio::test]
async fn executed_state_change_without_idempotency_key_is_a_protocol_error() -> TestResult {
    let mut executed = request(1, 1_000);
    executed.mode = Mode::Execute;
    assert!(
        encode(&executed).is_err(),
        "the contract encoder refuses it"
    );
    // A valid archive that fails the contract check after validation.
    let body = rkyv::to_bytes::<rkyv::rancor::Error>(&executed)?;
    let mut frame = header(kind::REQUEST, u32::try_from(body.len())?).to_vec();
    frame.extend_from_slice(&body);
    rejected(&frame).await?;

    executed.idempotency_key = Some(IdempotencyKey::new(vec![7; 16])?);
    let harness = Harness::start(limits(), immediate)?;
    let mut client = harness.admitted().await?;
    client.request(&executed).await?;
    assert_eq!(
        client.response().await?.request_id,
        1,
        "a keyed request passes"
    );
    Ok(())
}

#[tokio::test]
async fn admitted_connection_accepts_frames_above_the_pre_auth_cap() -> TestResult {
    let mut capture = request(3, 1_000);
    capture.body = RequestBody::Capture(CaptureRequest {
        session: SessionId::from_bytes([0x51; 16]),
        target: "https://example.com/article".to_owned(),
        limits: CaptureLimits::default(),
        egress_policy: Some(EgressPolicy {
            bytes: vec![0x5a; 6000],
        }),
    });
    let body = encode(&capture)?;
    assert!(body.len() > 4096, "the body is above the pre-auth cap");
    let harness = Harness::start(limits(), immediate)?;
    let mut client = harness.admitted().await?;
    client.send(kind::REQUEST, &body).await?;
    assert_eq!(
        client.response().await?.request_id,
        3,
        "the negotiated bound applies after Admitted"
    );
    Ok(())
}

#[tokio::test]
async fn oversized_length_is_refused_without_waiting_for_the_body() -> TestResult {
    let mut small = limits();
    small.max_frame = 8192;
    small.frame_timeout = Duration::from_secs(30);
    small.idle_timeout = Duration::from_mins(1);
    for declared in [8193, 4 * 1024 * 1024 + 1, u32::MAX] {
        let harness = Harness::start(small, immediate)?;
        let mut client = harness.admitted().await?;
        let start = Instant::now();
        client.send_raw(&header(kind::REQUEST, declared)).await?;
        let (_, failure) = client.fault_then_close().await?;
        assert_eq!(failure, Failure::ProtocolError, "{declared} bytes refused");
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "refused from the header alone, before the 30 s frame bound"
        );
    }
    Ok(())
}

#[tokio::test]
async fn partial_header_times_out() -> TestResult {
    let mut short = limits();
    short.frame_timeout = SHORT;
    let harness = Harness::start(short, immediate)?;
    let mut client = harness.admitted().await?;
    let start = Instant::now();
    client.send_raw(b"DPT1\x05\x00").await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "partial header");
    assert_fired(start.elapsed(), SHORT, "the frame bound");
    Ok(())
}

#[tokio::test]
async fn partial_body_times_out() -> TestResult {
    let mut short = limits();
    short.frame_timeout = SHORT;
    let harness = Harness::start(short, immediate)?;
    let mut client = harness.admitted().await?;
    let start = Instant::now();
    client.send_raw(&header(kind::REQUEST, 100)).await?;
    client.send_raw(&[0; 10]).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "partial body");
    assert_fired(start.elapsed(), SHORT, "the frame bound");
    Ok(())
}

#[tokio::test]
async fn read_frame_checks_the_length_before_reading_the_body() -> TestResult {
    let (mut near, mut far) = tokio::io::duplex(64);
    far.write_all(&header(kind::REQUEST, 4097)).await?;
    far.write_all(b"after").await?;
    let result = read_frame(&mut near, 4096, Duration::from_secs(1)).await;
    assert!(
        matches!(
            result,
            Err(ReadFail::Header(syntheke::Error::FrameTooLarge {
                len: 4097,
                cap: 4096,
                ..
            }))
        ),
        "the declared length is refused against the cap"
    );
    // Only the 12 header bytes were consumed: no body read was attempted.
    let mut rest = [0_u8; 5];
    near.read_exact(&mut rest).await?;
    assert_eq!(&rest, b"after", "the bytes after the header are untouched");
    Ok(())
}

#[tokio::test]
async fn read_frame_returns_exactly_the_declared_body() -> TestResult {
    let (mut near, mut far) = tokio::io::duplex(64);
    far.write_all(&header(kind::CANCEL, 3)).await?;
    far.write_all(b"abcdef").await?;
    let frame = read_frame(&mut near, 4096, Duration::from_secs(1))
        .await
        .map_err(|fail| format!("{fail:?}"))?;
    assert_eq!(
        frame.header,
        FrameHeader::decode(&header(kind::CANCEL, 3), 4096)?,
        "the header"
    );
    assert_eq!(frame.header.kind(), FrameKind::Cancel, "the kind");
    assert_eq!(frame.body, b"abc", "the declared body only");
    assert_eq!(HEADER_LEN, 12, "the header size the client spells out");
    drop(far);
    let mut rest = Vec::new();
    near.read_to_end(&mut rest).await?;
    assert_eq!(rest, b"def", "the next frame's bytes remain");
    Ok(())
}

#[tokio::test]
async fn read_frame_reports_a_clean_close_and_a_torn_frame() -> TestResult {
    let (mut near, far) = tokio::io::duplex(64);
    drop(far);
    let closed = read_frame(&mut near, 4096, Duration::from_secs(1)).await;
    assert!(matches!(closed, Err(ReadFail::Closed)), "end at a boundary");

    let (mut near, mut far) = tokio::io::duplex(64);
    far.write_all(b"DPT1").await?;
    drop(far);
    let torn = read_frame(&mut near, 4096, Duration::from_secs(1)).await;
    assert!(matches!(torn, Err(ReadFail::Io(_))), "end inside a header");
    Ok(())
}
