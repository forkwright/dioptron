//! Scoped audit reads across tenant partitions.

use syntheke::{AuditScope, AuditSeq, Capability, InvocationId, SessionId, TenantId};

use crate::store::test_support::{
    ACTUAL, AGENT, ENVELOPE, Fixture, G_AGENT, G_ROOT, OPERATOR, OTHER, S_AGENT, capture, idem,
    invocation, source,
};
use crate::store::{AuditQuery, Begin, Intent, NewSession, SettleOutcome, Store, Transfer};

/// The other agent's own session.
const S_OTHER: SessionId = SessionId::from_bytes(*b"SESSION-OTHER-01");

/// A capture by `tenant` under `grant` into the agent's session, driven
/// to `Settled`.
fn settled_capture(store: &Store, tenant: TenantId, grant: syntheke::GrantId, byte: u8) {
    let key = idem(byte);
    let request = epitrope::AuthzRequest {
        tenant,
        grant,
        ..capture(G_AGENT)
    };
    let begin = store
        .begin(&Intent::new(invocation(byte), request, &key, [0xd9; 32]))
        .expect("B1");
    assert!(matches!(begin, Begin::Persisted(_)), "{begin:?}");
    store.dispatch(invocation(byte)).expect("B2");
    store
        .complete_transfer(invocation(byte), &Transfer::new(ENVELOPE, source(), ACTUAL))
        .expect("B3");
    store.publish(invocation(byte)).expect("B4");
    store
        .settle(invocation(byte), SettleOutcome::Success)
        .expect("B5");
}

/// The seeded cast plus: the operator's capture in the agent's session
/// (invocation 6), the agent's own capture (invocation 7), and the other
/// agent's session (invocation 0xe2).
fn scenario(fixture: &Fixture) -> Store {
    let store = fixture.seeded();
    settled_capture(&store, OPERATOR, G_ROOT, 6);
    settled_capture(&store, AGENT, G_AGENT, 7);
    store
        .create_session(&NewSession::new(S_OTHER, OTHER, invocation(0xe2)))
        .expect("other session");
    store
}

/// The invocations `query` returns, in order.
fn invocations(store: &Store, query: &AuditQuery) -> Vec<InvocationId> {
    store
        .audit_query(query)
        .expect("audit query")
        .into_iter()
        .map(|event| event.record.invocation)
        .collect()
}

#[test]
fn all_scope_merges_every_partition_in_sequence_order() {
    let fixture = Fixture::new();
    let store = scenario(&fixture);
    let events = store
        .audit_query(&AuditQuery::new(OPERATOR, AuditScope::All, 100))
        .expect("audit query");
    let seqs: Vec<u64> = events.iter().map(|event| event.record.seq.get()).collect();
    assert_eq!(seqs, [1, 2, 3, 4, 5], "every record once, in global order");
    let by_invocation: Vec<InvocationId> =
        events.iter().map(|event| event.record.invocation).collect();
    assert_eq!(
        by_invocation,
        [
            invocation(0xe1),
            invocation(0xe0),
            invocation(6),
            invocation(7),
            invocation(0xe2),
        ],
        "agent grant issue, agent session, operator capture, agent capture, other session"
    );
}

#[test]
fn own_and_owned_sessions_adds_other_tenants_records_in_owned_sessions() {
    let fixture = Fixture::new();
    let store = scenario(&fixture);
    let query = AuditQuery::new(AGENT, AuditScope::OwnAndOwnedSessions, 100);
    assert_eq!(
        invocations(&store, &query),
        [invocation(0xe0), invocation(6), invocation(7)],
        "the agent's own records plus the operator's capture in its session"
    );
    let other = AuditQuery::new(OTHER, AuditScope::OwnAndOwnedSessions, 100);
    assert_eq!(
        invocations(&store, &other),
        [invocation(0xe2)],
        "the other agent sees only its own session record"
    );
    let operator = AuditQuery::new(OPERATOR, AuditScope::OwnAndOwnedSessions, 100);
    assert_eq!(
        invocations(&store, &operator),
        [invocation(0xe1), invocation(6)],
        "the operator's own records only: it owns no session"
    );
}

#[test]
fn session_narrows_and_after_and_limit_page_across_partitions() {
    let fixture = Fixture::new();
    let store = scenario(&fixture);
    let mut query = AuditQuery::new(OPERATOR, AuditScope::All, 100);
    query.session = Some(S_AGENT);
    assert_eq!(
        invocations(&store, &query),
        [invocation(0xe0), invocation(6), invocation(7)],
        "only the agent session's records"
    );
    query.limit = 2;
    let first = store.audit_query(&query).expect("first page");
    assert_eq!(
        first
            .iter()
            .map(|event| event.record.invocation)
            .collect::<Vec<_>>(),
        [invocation(0xe0), invocation(6)],
        "first page spans two partitions"
    );
    query.after = first.last().map(|event| event.record.seq);
    assert_eq!(invocations(&store, &query), [invocation(7)], "second page");
    query.after = Some(AuditSeq::new(u64::MAX));
    assert!(
        invocations(&store, &query).is_empty(),
        "nothing follows the last sequence"
    );
}

#[test]
fn audit_query_reads_what_each_record_committed() {
    let fixture = Fixture::new();
    let store = scenario(&fixture);
    let events = store
        .audit_query(&AuditQuery::new(
            AGENT,
            AuditScope::OwnAndOwnedSessions,
            100,
        ))
        .expect("audit query");
    let operator_capture = events
        .iter()
        .find(|event| event.record.invocation == invocation(6))
        .expect("the operator's capture");
    assert_eq!(operator_capture.record.tenant, OPERATOR, "acting tenant");
    assert_eq!(
        operator_capture.record.capability,
        Capability::Capture,
        "capability"
    );
    assert_eq!(operator_capture.record.session, Some(S_AGENT), "session");
    assert_eq!(operator_capture.release_reason, None, "not a release");
}
