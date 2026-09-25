//! Handshake: admission, version negotiation, identical auth failures,
//! pre-authentication bounds, and the handshake timeout.

use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use syntheke::{Failure, Nonce, ResponseBody, TenantId, VersionChoice, auth_transcript, decode};
use tokio::time::Instant;

use super::super::handshake::Authenticator;
use super::super::test_support::{
    CLIENT_NONCE, Client, Harness, SHORT, STRANGER_KEY, TENANT, TENANT_KEY, TestResult,
    UNBOUND_TENANT, UNKNOWN_TENANT, assert_fired, directory, header, immediate, kind, limits,
    own_uid, request,
};

/// A transcript for `tenant` with fixed nonces.
fn transcript(tenant: TenantId) -> Vec<u8> {
    auth_transcript(1, tenant, &CLIENT_NONCE, &Nonce::from_bytes([0x32; 16])).to_vec()
}

#[tokio::test]
async fn unknown_tenant_is_verified_against_the_dummy_key() -> TestResult {
    let authenticator = Authenticator::new()?;
    let directory = directory()?;
    let signed = transcript(UNKNOWN_TENANT);
    let signature = SigningKey::from_bytes(&STRANGER_KEY)
        .sign(&signed)
        .to_bytes();
    assert!(
        !authenticator.authenticate(&directory, UNKNOWN_TENANT, own_uid()?, &signed, &signature),
        "an unknown tenant never authenticates"
    );
    assert_eq!(
        authenticator.dummy_verifications(),
        1,
        "the unknown tenant cost one verification against the dummy key"
    );
    Ok(())
}

#[tokio::test]
async fn known_tenants_are_verified_against_their_own_key() -> TestResult {
    let authenticator = Authenticator::new()?;
    let directory = directory()?;
    let uid = own_uid()?;
    let cases = [
        (TENANT, TENANT_KEY, true, "a bound tenant with its key"),
        (
            TENANT,
            STRANGER_KEY,
            false,
            "a bound tenant with a wrong key",
        ),
        (
            UNBOUND_TENANT,
            TENANT_KEY,
            false,
            "a valid key from an unbound uid",
        ),
    ];
    for (tenant, key, expected, case) in cases {
        let signed = transcript(tenant);
        let signature = SigningKey::from_bytes(&key).sign(&signed).to_bytes();
        assert_eq!(
            authenticator.authenticate(&directory, tenant, uid, &signed, &signature),
            expected,
            "{case}"
        );
    }
    assert_eq!(
        authenticator.dummy_verifications(),
        0,
        "known tenants never touch the dummy key"
    );
    Ok(())
}

#[tokio::test]
async fn handshake_admits_a_bound_tenant_with_a_valid_signature() -> TestResult {
    let harness = Harness::start(limits(), immediate)?;
    let mut client = harness.connect().await?;
    let (server, _) = client.handshake(TENANT, &TENANT_KEY).await?;
    assert_eq!(server.version, VersionChoice::Chosen(1), "version 1 chosen");
    assert_eq!(
        server.max_frame,
        1024 * 1024,
        "the default bound is offered"
    );

    client.request(&request(7, 1_000)).await?;
    let response = client.response().await?;
    assert_eq!(response.request_id, 7, "the response names the request");
    assert_eq!(
        response.body,
        ResponseBody::InProgress,
        "the dispatcher's body"
    );
    Ok(())
}

#[tokio::test]
async fn handshake_chooses_only_within_the_offered_range() -> TestResult {
    let harness = Harness::start(limits(), immediate)?;
    for (min, max) in [(1, 9), (0, 1), (1, 1)] {
        let mut client = harness.connect().await?;
        let server = client.hello(TENANT, min, max).await?;
        let VersionChoice::Chosen(chosen) = server.version else {
            return Err(format!("{min}..={max} overlaps version 1").into());
        };
        assert!(
            (min..=max).contains(&chosen),
            "chosen {chosen} is inside {min}..={max}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn incompatible_range_gets_a_valid_hello_then_close() -> TestResult {
    let harness = Harness::start(limits(), immediate)?;
    let mut client = harness.connect().await?;
    let server = client.hello(TENANT, 2, 5).await?;
    assert_eq!(server.version, VersionChoice::Incompatible, "no overlap");
    assert!(
        (4096..=4 * 1024 * 1024).contains(&server.max_frame),
        "an incompatible hello still carries a valid max_frame"
    );
    client.expect_closed().await
}

/// Runs one forged handshake and returns the raw fault frame it produced.
async fn forged(harness: &Harness, case: &str, previous: [u8; 64]) -> TestResult<Vec<u8>> {
    let mut client = harness.connect().await?;
    match case {
        "wrong key" => {
            let server = client.hello(TENANT, 1, 1).await?;
            client
                .auth(Client::sign(TENANT, &server, &STRANGER_KEY))
                .await?;
        }
        "replayed signature" => {
            client.hello(TENANT, 1, 1).await?;
            client.auth(previous).await?;
        }
        "uid not bound" => {
            let server = client.hello(UNBOUND_TENANT, 1, 1).await?;
            client
                .auth(Client::sign(UNBOUND_TENANT, &server, &TENANT_KEY))
                .await?;
        }
        "unknown tenant" => {
            let server = client.hello(UNKNOWN_TENANT, 1, 1).await?;
            client
                .auth(Client::sign(UNKNOWN_TENANT, &server, &STRANGER_KEY))
                .await?;
        }
        "request after hello" => {
            client.hello(TENANT, 1, 1).await?;
            client.request(&request(1, 1_000)).await?;
        }
        "request before hello" => client.request(&request(1, 1_000)).await?,
        "cancel before auth" => {
            client.hello(TENANT, 1, 1).await?;
            client.cancel(1).await?;
        }
        other => return Err(format!("unknown case {other}").into()),
    }
    let (raw, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::AuthFailed, "{case} fails authentication");
    Ok(raw)
}

#[tokio::test]
async fn every_forged_identity_gets_identical_auth_failed_bytes() -> TestResult {
    let harness = Harness::start(limits(), immediate)?;
    // A genuine signature from an earlier connection, for the replay case.
    let (_, previous) = harness
        .connect()
        .await?
        .handshake(TENANT, &TENANT_KEY)
        .await?;
    let cases = [
        "wrong key",
        "replayed signature",
        "uid not bound",
        "unknown tenant",
        "request after hello",
        "request before hello",
        "cancel before auth",
    ];
    let mut frames = Vec::new();
    for case in cases {
        frames.push((case, forged(&harness, case, previous).await?));
    }
    let (_, first) = frames.first().ok_or("no cases ran")?;
    for (case, raw) in &frames {
        assert_eq!(raw, first, "{case} is byte-identical to the other failures");
    }
    Ok(())
}

#[tokio::test]
async fn silent_client_times_out_at_the_handshake_bound() -> TestResult {
    let mut short = limits();
    short.handshake_timeout = SHORT;
    let harness = Harness::start(short, immediate)?;
    let mut client = harness.connect().await?;
    let start = Instant::now();
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(
        failure,
        Failure::ProtocolError,
        "a timeout is a bound violation"
    );
    assert_fired(start.elapsed(), SHORT, "handshake bound");
    Ok(())
}

#[tokio::test]
async fn stalled_auth_times_out_at_the_handshake_bound() -> TestResult {
    let mut short = limits();
    short.handshake_timeout = SHORT;
    let harness = Harness::start(short, immediate)?;
    let mut client = harness.connect().await?;
    let start = Instant::now();
    client.hello(TENANT, 1, 1).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "no auth frame in time");
    assert_fired(start.elapsed(), SHORT, "the whole handshake is bounded");
    Ok(())
}

#[tokio::test]
async fn partial_hello_header_times_out_at_the_frame_bound() -> TestResult {
    let mut short = limits();
    short.frame_timeout = SHORT;
    let harness = Harness::start(short, immediate)?;
    let mut client = harness.connect().await?;
    let start = Instant::now();
    client.send_raw(b"DPT1\x01").await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "partial header");
    let elapsed = start.elapsed();
    assert!(elapsed >= SHORT, "the frame bound fired");
    assert!(
        elapsed < Duration::from_secs(5),
        "before the handshake bound"
    );
    Ok(())
}

#[tokio::test]
async fn pre_auth_frames_above_4_kib_are_refused_from_the_header() -> TestResult {
    let harness = Harness::start(limits(), immediate)?;

    // No body follows either header: a server that waited to read or
    // allocate the declared body would time out instead of answering now.
    let mut client = harness.connect().await?;
    let start = Instant::now();
    client.send_raw(&header(kind::CLIENT_HELLO, 4097)).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "oversized hello");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "refused before the handshake bound could fire"
    );

    let mut client = harness.connect().await?;
    client.hello(TENANT, 1, 1).await?;
    // The negotiated 1 MiB bound does not apply before Admitted.
    client.send_raw(&header(kind::AUTH, 4097)).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "oversized auth");
    Ok(())
}

#[tokio::test]
async fn invalid_hello_bodies_are_protocol_errors() -> TestResult {
    let harness = Harness::start(limits(), immediate)?;

    let mut client = harness.connect().await?;
    // Every 36-byte pattern is a valid hello archive, so a short body is
    // the corruption the validator must catch.
    client.send(kind::CLIENT_HELLO, &[0xff; 10]).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "truncated hello body");

    let mut client = harness.connect().await?;
    // The contract encoder refuses an inverted range; serialize it raw.
    let body = rkyv::to_bytes::<rkyv::rancor::Error>(&syntheke::ClientHello {
        version_min: 3,
        version_max: 1,
        tenant: TENANT,
        client_nonce: CLIENT_NONCE,
    })?;
    assert!(
        matches!(
            decode::<syntheke::ClientHello>(&body, 4096),
            Err(syntheke::Error::InvalidVersionRange { min: 3, max: 1, .. })
        ),
        "the body is a valid archive with an inverted range"
    );
    client.send(kind::CLIENT_HELLO, &body).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "inverted version range");

    let mut client = harness.connect().await?;
    client.send(kind::SERVER_HELLO, &[]).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "a server-only kind first");
    Ok(())
}
