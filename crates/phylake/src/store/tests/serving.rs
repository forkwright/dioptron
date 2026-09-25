//! Idempotency claims, standalone audit entries, and the logical digest.

use syntheke::{
    AuditScope, AuditSeq, Capability, Failure, GrantId, InvocationState, OutcomeKind, SessionId,
    TenantId,
};

use crate::Error;
use crate::store::test_support::{AGENT, Fixture, G_AGENT, OTHER, S_AGENT, idem, invocation};
use crate::store::{AuditNote, AuditOutcome, Claimed, IdemClaim};

const DIGEST_A: [u8; 32] = [0x11; 32];
const DIGEST_B: [u8; 32] = [0x22; 32];
const UNKNOWN: TenantId = TenantId::from_bytes(*b"TENANT-UNKNOWN-9");
const OTHER_GRANT: GrantId = GrantId::from_bytes([0xc0; 16]);

fn claim_of(
    key: &syntheke::IdempotencyKey,
    tenant: TenantId,
    grant: GrantId,
    digest: [u8; 32],
    byte: u8,
) -> IdemClaim<'_> {
    IdemClaim::new(
        tenant,
        grant,
        Capability::SessionCreate,
        key,
        digest,
        invocation(byte),
    )
}

#[test]
fn claim_binds_fresh_key_then_replays_same_request() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = idem(0x42);

    let first = store
        .claim(&claim_of(&key, AGENT, G_AGENT, DIGEST_A, 0x01))
        .expect("claim");
    let again = store
        .claim(&claim_of(&key, AGENT, G_AGENT, DIGEST_A, 0x02))
        .expect("claim");

    assert_eq!(first, Claimed::Fresh(invocation(0x01)), "unbound key binds");
    assert_eq!(
        again,
        Claimed::Replay(invocation(0x01)),
        "a replay returns the first attempt's invocation, not the new id"
    );
}

#[test]
fn claim_conflicts_on_other_digest_or_grant_and_writes_nothing() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = idem(0x42);
    store
        .claim(&claim_of(&key, AGENT, G_AGENT, DIGEST_A, 0x01))
        .expect("claim");
    let before = store.logical_digest().expect("digest");

    let digest = store
        .claim(&claim_of(&key, AGENT, G_AGENT, DIGEST_B, 0x03))
        .expect("claim");
    let grant = store
        .claim(&claim_of(&key, AGENT, OTHER_GRANT, DIGEST_A, 0x04))
        .expect("claim");

    assert_eq!(digest, Claimed::Conflict, "another digest conflicts");
    assert_eq!(
        grant,
        Claimed::Conflict,
        "another designated grant conflicts"
    );
    assert_eq!(
        store.logical_digest().expect("digest"),
        before,
        "a conflict writes nothing"
    );
}

#[test]
fn claim_keys_are_per_tenant() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = idem(0x42);
    store
        .claim(&claim_of(&key, AGENT, G_AGENT, DIGEST_A, 0x01))
        .expect("claim");

    let other = store
        .claim(&claim_of(&key, OTHER, G_AGENT, DIGEST_B, 0x04))
        .expect("claim");

    assert_eq!(
        other,
        Claimed::Fresh(invocation(0x04)),
        "the same key under another tenant is unbound"
    );
}

#[test]
fn claimed_reads_the_binding_without_writing() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = idem(0x42);
    let unbound = store
        .claimed(&claim_of(&key, AGENT, G_AGENT, DIGEST_A, 0x01))
        .expect("peek");
    let before = store.logical_digest().expect("digest");
    assert_eq!(unbound, None, "an unbound key reads as None");
    assert_eq!(
        store.logical_digest().expect("digest"),
        before,
        "a peek writes nothing"
    );
    store
        .claim(&claim_of(&key, AGENT, G_AGENT, DIGEST_A, 0x01))
        .expect("claim");

    let same = store
        .claimed(&claim_of(&key, AGENT, G_AGENT, DIGEST_A, 0x09))
        .expect("peek");
    let other = store
        .claimed(&claim_of(&key, AGENT, G_AGENT, DIGEST_B, 0x09))
        .expect("peek");

    assert_eq!(
        same,
        Some(Claimed::Replay(invocation(0x01))),
        "same request"
    );
    assert_eq!(other, Some(Claimed::Conflict), "different request");
}

#[test]
fn claim_refuses_unknown_tenant() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = idem(0x42);

    let claim = store
        .claim(&claim_of(&key, UNKNOWN, G_AGENT, DIGEST_A, 0x01))
        .expect_err("unknown tenant");
    let peek = store
        .claimed(&claim_of(&key, UNKNOWN, G_AGENT, DIGEST_A, 0x01))
        .expect_err("unknown tenant");

    assert!(
        matches!(claim, Error::TenantMissing { .. }),
        "an unknown tenant has no keys: {claim:?}"
    );
    assert!(
        matches!(peek, Error::TenantMissing { .. }),
        "an unknown tenant has no keys: {peek:?}"
    );
}

#[test]
fn record_audit_appends_refusals_and_completions_in_sequence() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let mut refused = AuditNote::new(
        AGENT,
        invocation(0x05),
        Capability::Read,
        AuditOutcome::Refused(Failure::NotFoundOrDenied),
    );
    refused.session = Some(S_AGENT);
    refused.grant = Some(G_AGENT);
    let mut completed = AuditNote::new(
        AGENT,
        invocation(0x06),
        Capability::AuditQuery,
        AuditOutcome::Completed(None),
    );
    completed.grant = Some(OTHER_GRANT);
    completed.audit_scope = Some(AuditScope::OwnAndOwnedSessions);

    let first = store.record_audit(&refused).expect("audit");
    let second = store.record_audit(&completed).expect("audit");

    assert_eq!(
        second.get(),
        first.get().saturating_add(1),
        "each call appends exactly one entry"
    );
    let own = store
        .audit_records(
            AGENT,
            Some(AuditSeq::new(first.get().saturating_sub(1))),
            10,
        )
        .expect("records");
    let shape: Vec<_> = own
        .iter()
        .map(|event| {
            (
                event.record.state,
                event.record.outcome,
                event.record.session,
                event.grant,
                event.audit_scope,
            )
        })
        .collect();
    assert_eq!(
        shape,
        vec![
            (
                InvocationState::Denied,
                OutcomeKind::NotFoundOrDenied,
                Some(S_AGENT),
                Some(G_AGENT),
                None,
            ),
            (
                InvocationState::Settled,
                OutcomeKind::Success,
                None,
                Some(OTHER_GRANT),
                Some(AuditScope::OwnAndOwnedSessions),
            ),
        ],
        "a refusal is Denied with its failure; a completion is Settled; each \
         keeps the grant it named and an audit read the scope it applied"
    );
}

#[test]
fn record_audit_refuses_unknown_tenant() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let note = AuditNote::new(
        UNKNOWN,
        invocation(0x06),
        Capability::Read,
        AuditOutcome::Refused(Failure::NotFoundOrDenied),
    );

    let error = store.record_audit(&note).expect_err("unknown tenant");

    assert!(
        matches!(error, Error::TenantMissing { .. }),
        "an unknown tenant has no partition: {error:?}"
    );
}

#[test]
fn logical_digest_is_stable_across_reads_and_reopen() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let before = store.logical_digest().expect("digest");
    let _unknown = store
        .session_artifacts(SessionId::from_bytes([0x99; 16]), None, 10)
        .expect("read");
    drop(store);

    let reopened = fixture.reopen();

    assert_eq!(
        reopened.logical_digest().expect("digest"),
        before,
        "reads and a reopen change no record"
    );
}

#[test]
fn logical_digest_changes_with_any_write() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let before = store.logical_digest().expect("digest");
    let key = idem(0x42);

    store
        .claim(&claim_of(&key, AGENT, G_AGENT, DIGEST_A, 0x01))
        .expect("claim");

    assert_ne!(
        store.logical_digest().expect("digest"),
        before,
        "a claim is a durable write"
    );
}
