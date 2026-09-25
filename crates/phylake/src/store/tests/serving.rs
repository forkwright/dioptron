//! Idempotency claims, standalone audit entries, scoped audit reads, and
//! the logical digest.

use syntheke::{
    AuditScope, AuditSeq, Capability, InvocationState, OutcomeKind, SessionId, TenantId,
};

use crate::Error;
use crate::store::test_support::{AGENT, Fixture, OPERATOR, OTHER, S_AGENT, idem, invocation};
use crate::store::{AuditEntry, AuditQuery, Claimed, IdemClaim};

const DIGEST_A: [u8; 32] = [0x11; 32];
const DIGEST_B: [u8; 32] = [0x22; 32];
const UNKNOWN: TenantId = TenantId::from_bytes(*b"TENANT-UNKNOWN-9");

fn claim(tenant: TenantId, digest: [u8; 32], byte: u8) -> IdemClaim<'static> {
    // WHY leak: the claim borrows its key; a test key living for the whole
    // process keeps the helper signature simple.
    let key = Box::leak(Box::new(idem(0x42)));
    IdemClaim::new(
        tenant,
        Capability::SessionCreate,
        key,
        digest,
        invocation(byte),
    )
}

#[test]
fn claim_binds_fresh_key_then_replays_same_digest() {
    let fixture = Fixture::new();
    let store = fixture.seeded();

    let first = store.claim(&claim(AGENT, DIGEST_A, 0x01)).expect("claim");
    let again = store.claim(&claim(AGENT, DIGEST_A, 0x02)).expect("claim");

    assert_eq!(first, Claimed::Fresh(invocation(0x01)), "unbound key binds");
    assert_eq!(
        again,
        Claimed::Replay(invocation(0x01)),
        "a replay returns the first attempt's invocation, not the new id"
    );
}

#[test]
fn claim_reports_conflict_for_other_digest_and_writes_nothing() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    store.claim(&claim(AGENT, DIGEST_A, 0x01)).expect("claim");
    let before = store.logical_digest().expect("digest");

    let conflict = store.claim(&claim(AGENT, DIGEST_B, 0x03)).expect("claim");

    assert_eq!(conflict, Claimed::Conflict, "another digest conflicts");
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
    store.claim(&claim(AGENT, DIGEST_A, 0x01)).expect("claim");

    let other = store.claim(&claim(OTHER, DIGEST_B, 0x04)).expect("claim");

    assert_eq!(
        other,
        Claimed::Fresh(invocation(0x04)),
        "the same key under another tenant is unbound"
    );
}

#[test]
fn claim_refuses_unknown_tenant() {
    let fixture = Fixture::new();
    let store = fixture.seeded();

    let error = store
        .claim(&claim(UNKNOWN, DIGEST_A, 0x01))
        .expect_err("unknown tenant");

    assert!(
        matches!(error, Error::TenantMissing { .. }),
        "an unknown tenant has no keys: {error:?}"
    );
}

#[test]
fn record_audit_appends_one_entry_in_sequence() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let entry = AuditEntry::new(
        AGENT,
        invocation(0x05),
        Capability::Read,
        InvocationState::Denied,
        OutcomeKind::NotFoundOrDenied,
    );

    let first = store.record_audit(entry).expect("audit");
    let second = store.record_audit(entry).expect("audit");

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
    assert_eq!(own.len(), 2, "both entries are in the tenant's partition");
}

#[test]
fn record_audit_refuses_unknown_tenant() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let entry = AuditEntry::new(
        UNKNOWN,
        invocation(0x06),
        Capability::Read,
        InvocationState::Denied,
        OutcomeKind::Denied,
    );

    let error = store.record_audit(entry).expect_err("unknown tenant");

    assert!(
        matches!(error, Error::TenantMissing { .. }),
        "an unknown tenant has no partition: {error:?}"
    );
}

/// Seeds entries for the scope tests: the other agent acts once in the
/// agent's session and once in no session.
fn seed_other_entries(store: &crate::Store) {
    let in_session = AuditEntry::new(
        OTHER,
        invocation(0x07),
        Capability::Read,
        InvocationState::Denied,
        OutcomeKind::Denied,
    )
    .in_session(Some(S_AGENT));
    store.record_audit(in_session).expect("audit");
    let outside = AuditEntry::new(
        OTHER,
        invocation(0x08),
        Capability::Query,
        InvocationState::Denied,
        OutcomeKind::Denied,
    );
    store.record_audit(outside).expect("audit");
}

fn invocations(query: &AuditQuery, store: &crate::Store) -> Vec<u8> {
    store
        .audit_query(query)
        .expect("audit query")
        .records
        .iter()
        .map(|record| record.invocation.to_bytes()[0])
        .collect()
}

#[test]
fn audit_query_own_scope_adds_entries_in_owned_sessions_only() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    seed_other_entries(&store);

    let seen = invocations(
        &AuditQuery::new(AGENT, AuditScope::OwnAndOwnedSessions, 100),
        &store,
    );

    assert_eq!(
        seen,
        vec![0xe0, 0x07],
        "own session create plus the other agent's entry in the owned session"
    );
}

#[test]
fn audit_query_all_scope_reads_every_partition_in_sequence() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    seed_other_entries(&store);

    let seen = invocations(&AuditQuery::new(OPERATOR, AuditScope::All, 100), &store);

    assert_eq!(
        seen,
        vec![0xe1, 0xe0, 0x07, 0x08],
        "grant issue, session create, and both of the other agent's entries"
    );
}

#[test]
fn audit_query_filters_session_and_pages() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    seed_other_entries(&store);
    let mut query = AuditQuery::new(OPERATOR, AuditScope::All, 1);
    query.session = Some(S_AGENT);

    let first = store.audit_query(&query).expect("page");
    query.after = first.records.last().map(|record| record.seq);
    let second = store.audit_query(&query).expect("page");

    let ids = |page: &crate::store::AuditRead| {
        page.records
            .iter()
            .map(|record| record.invocation.to_bytes()[0])
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&first), vec![0xe0], "first page holds one entry");
    assert!(first.more, "a second entry remains");
    assert_eq!(ids(&second), vec![0x07], "second page continues after");
    assert!(!second.more, "nothing remains");
}

#[test]
fn audit_query_unknown_session_filter_matches_nothing() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let mut query = AuditQuery::new(OPERATOR, AuditScope::All, 10);
    query.session = Some(SessionId::from_bytes([0x99; 16]));

    let read = store.audit_query(&query).expect("audit query");

    assert!(read.records.is_empty(), "no entry names that session");
}

#[test]
fn audit_query_refuses_unknown_tenant() {
    let fixture = Fixture::new();
    let store = fixture.seeded();

    let error = store
        .audit_query(&AuditQuery::new(UNKNOWN, AuditScope::All, 10))
        .expect_err("unknown tenant");

    assert!(
        matches!(error, Error::TenantMissing { .. }),
        "an unknown acting tenant has no partition: {error:?}"
    );
}

#[test]
fn logical_digest_is_stable_across_reads_and_reopen() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let before = store.logical_digest().expect("digest");
    let _plan = store.snapshot();
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

    store.claim(&claim(AGENT, DIGEST_A, 0x01)).expect("claim");

    assert_ne!(
        store.logical_digest().expect("digest"),
        before,
        "a claim is a durable write"
    );
}
