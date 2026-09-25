//! Forged peer identity: every authentication failure answers the same
//! `AuthFailed` bytes (contract § Handshake and version negotiation).
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use syntheke::{
    Auth, ClientHello, FrameKind, Mode, Nonce, PRE_AUTH_MAX_BODY, RequestBody, ServerHello,
    TenantId, VersionChoice, WIRE_VERSION, auth_transcript,
};
use xenos::{Frame, RawConn};

use crate::test_support::{Harness, Tenant, agent, operator, own_uid, stranger};

const TIMEOUT: Duration = Duration::from_secs(10);

/// A tenant bound to the uid after this process's.
fn unbound() -> Tenant {
    Tenant::new(0x0d)
}

/// Sends a hello as `tenant` with `client_nonce`, then the signature
/// `sign` returns for the server's reply, and returns the server's answer
/// and the signature sent.
fn handshake(
    harness: &Harness,
    tenant: TenantId,
    client_nonce: Nonce,
    sign: impl FnOnce(&ServerHello) -> [u8; 64],
) -> (Frame, [u8; 64]) {
    let mut conn = RawConn::connect(harness.socket(), TIMEOUT).expect("connect");
    let hello = ClientHello {
        version_min: WIRE_VERSION,
        version_max: WIRE_VERSION,
        tenant,
        client_nonce,
    };
    conn.send_message(&hello, PRE_AUTH_MAX_BODY).expect("hello");
    let reply: ServerHello = conn.read_message(PRE_AUTH_MAX_BODY).expect("server hello");
    let signature = sign(&reply);
    conn.send_message(&Auth { signature }, PRE_AUTH_MAX_BODY)
        .expect("auth");
    let answer = conn.read_frame(PRE_AUTH_MAX_BODY).expect("answer");
    (answer, signature)
}

/// The honest signature of `key` for `tenant` over the server's reply.
fn signer(
    key: &SigningKey,
    tenant: TenantId,
    client_nonce: Nonce,
) -> impl FnOnce(&ServerHello) -> [u8; 64] + '_ {
    move |reply| {
        let VersionChoice::Chosen(version) = reply.version else {
            panic!("no common version");
        };
        let transcript = auth_transcript(version, tenant, &client_nonce, &reply.server_nonce);
        key.sign(&transcript).to_bytes()
    }
}

#[test]
fn every_forged_identity_gets_the_same_auth_failed_bytes() {
    let harness = Harness::with_cast();
    harness.add_tenant(
        &unbound(),
        "agent",
        own_uid().checked_add(1).expect("uid"),
        &operator(),
    );
    let daemon = harness.start();
    let nonce = Nonce::from_bytes([0x5a; 16]);
    let agent = agent();

    let (honest, captured) = handshake(
        &harness,
        agent.id,
        nonce,
        signer(&agent.key, agent.id, nonce),
    );
    let (wrong_key, _) = handshake(
        &harness,
        agent.id,
        nonce,
        signer(&stranger().key, agent.id, nonce),
    );
    let (replayed, _) = handshake(&harness, agent.id, nonce, |_| captured);
    let (uid_not_bound, _) = handshake(
        &harness,
        unbound().id,
        nonce,
        signer(&unbound().key, unbound().id, nonce),
    );
    let ghost = Tenant::new(0x77);
    let (unknown_tenant, _) = handshake(
        &harness,
        ghost.id,
        nonce,
        signer(&ghost.key, ghost.id, nonce),
    );
    let pre_auth = {
        let mut conn = RawConn::connect(harness.socket(), TIMEOUT).expect("connect");
        let request = harness.request(
            crate::test_support::ROOT,
            None,
            Mode::Execute,
            RequestBody::SessionCreate,
        );
        let mut dry = request;
        dry.mode = Mode::DryRun;
        conn.send_message(&dry, PRE_AUTH_MAX_BODY).expect("request");
        let fault = conn.read_frame(PRE_AUTH_MAX_BODY).expect("fault");
        conn.expect_close().expect("closed after the fault");
        fault
    };

    assert_eq!(
        honest.kind(),
        FrameKind::Admitted,
        "the honest peer is admitted"
    );
    let failures = [
        ("wrong key", wrong_key),
        ("replayed signature", replayed),
        ("uid not bound", uid_not_bound),
        ("unknown tenant", unknown_tenant),
        ("pre-auth request", pre_auth),
    ];
    for (cause, frame) in &failures {
        assert_eq!(frame.kind(), FrameKind::Fault, "{cause} is refused");
        assert_eq!(
            (frame.kind(), frame.body()),
            (failures[0].1.kind(), failures[0].1.body()),
            "{cause} answers the same bytes as a wrong key"
        );
    }
    let fault: syntheke::Fault = failures[0].1.decode(PRE_AUTH_MAX_BODY).expect("fault body");
    assert_eq!(
        fault.failure,
        syntheke::Failure::AuthFailed,
        "one kind for every cause"
    );
    daemon.stop();
}
