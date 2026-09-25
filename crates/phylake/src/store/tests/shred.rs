//! Crypto-shredding and the compaction that completes it: the wrapped key
//! bytes leave the disk, audit stubs survive, and the tenant's sealed
//! records stop opening.

use std::num::NonZeroUsize;

use syntheke::{
    AuditScope, Capability, Failure, GrantId, IdempotencyKey, SessionScope, TenantClass, Timestamp,
};

use crate::Error;
use crate::crypto::{KeyId, Keyspace};
use crate::store::codec::StoredRecord as _;
use crate::store::record_key::store as keys;
use crate::store::records::AuditStubRecord;
use crate::store::test_support::{
    AGENT, Fixture, G_AGENT, OPERATOR, OTHER, S_AGENT, capture, count, disk_hits, dump, invocation,
    publish_capture, raw,
};
use crate::store::{AuditQuery, Begin, Intent, RootGrant, Store, TenantRegistration, slot};

const ENVELOPE_A: &[u8] = b"<p>SHRED-ENVELOPE-A example.com</p>";
const ENVELOPE_B: &[u8] = b"<p>SHRED-ENVELOPE-B example.com</p>";

/// Every wrapped key of the agent: its first data key (read before the
/// rotation retires it), its current one, and its addressing subkeys.
fn agent_wrapped_keys(store: &Store) -> Vec<Vec<u8>> {
    let index = store.keys.index();
    [
        keys::data_key(index, AGENT, KeyId::new(1)).expect("key 1"),
        keys::data_key(index, AGENT, KeyId::new(2)).expect("key 2"),
        keys::address_keys(index, AGENT).expect("address"),
    ]
    .iter()
    .filter_map(|key| raw(store, Keyspace::Keys, key))
    .collect()
}

/// Every audit stub, opened.
fn stubs(store: &Store) -> Vec<AuditStubRecord> {
    let snapshot = store.db.read_tx();
    store
        .entries(&snapshot, Keyspace::AuditStub)
        .expect("stubs")
        .iter()
        .map(|(key, sealed)| {
            let plain = Store::open_bytes(&[store.keys.meta()], slot::AUDIT_STUB, key, sealed)
                .expect("a stub opens");
            AuditStubRecord::decode(&plain, "audit_stub").expect("decode")
        })
        .collect()
}

#[test]
fn shred_then_compact_removes_every_wrapped_key_from_disk() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let first = publish_capture(&store, 1, ENVELOPE_A);
    let mut wrapped = agent_wrapped_keys(&store);
    store
        .rekey_tenant(AGENT, NonZeroUsize::MIN)
        .expect("rotate, retiring key 1");
    let second = publish_capture(&store, 2, ENVELOPE_B);
    wrapped.extend(agent_wrapped_keys(&store));
    assert_eq!(wrapped.len(), 3, "key 1, key 2, and the addressing subkeys");
    let stubs_before = stubs(&store);
    let other_audit = store.audit_records(OTHER, None, 100).expect("other");

    store.shred_tenant(AGENT).expect("shred");
    assert!(
        !store
            .tenant_keys
            .lock()
            .expect("cache")
            .contains_key(&AGENT),
        "the shred evicts the cached keyring"
    );
    assert_eq!(agent_wrapped_keys(&store), Vec::<Vec<u8>>::new(), "deleted");
    let lingering: usize = wrapped
        .iter()
        .map(|bytes| disk_hits(&fixture.path, bytes))
        .sum();
    assert!(
        lingering > 0,
        "before compaction the deleted wrapped keys are still on disk"
    );

    let store = store.compact().expect("compact");
    for (n, bytes) in wrapped.iter().enumerate() {
        assert_eq!(
            disk_hits(&fixture.path, bytes),
            0,
            "wrapped key {n} left the disk"
        );
    }
    assert_eq!(stubs(&store), stubs_before, "audit stubs survive");
    for artifact in [first, second] {
        assert_eq!(store.artifact(artifact).expect("read"), None, "unreadable");
        assert_eq!(store.read_artifact(artifact, 0, 64).expect("read"), None);
    }
    assert_eq!(
        store.session_artifacts(S_AGENT, None, 10).expect("session"),
        None
    );
    let error = store.audit_records(AGENT, None, 10).expect_err("shredded");
    assert!(matches!(error, Error::TenantShredded { .. }), "{error:?}");
    assert_eq!(
        store.audit_records(OTHER, None, 100).expect("other"),
        other_audit,
        "another tenant keeps its records"
    );
    assert!(
        count(&dump(&store), "blobs") >= 2,
        "the sealed blobs remain, now without a key"
    );
    drop(store);
    let store = fixture.reopen();
    assert_eq!(stubs(&store), stubs_before, "stubs after reopen");
}

#[test]
fn audit_query_skips_a_shredded_tenants_partition() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    publish_capture(&store, 1, ENVELOPE_A);
    let all = AuditQuery::new(OPERATOR, AuditScope::All, 1000);
    let before = store.audit_query(&all).expect("query");
    assert!(
        before.iter().any(|event| event.record.tenant == AGENT),
        "the agent's partition is read before the shred"
    );
    let expected: Vec<_> = before
        .into_iter()
        .filter(|event| event.record.tenant != AGENT)
        .collect();
    assert!(!expected.is_empty(), "other partitions hold records");

    store.shred_tenant(AGENT).expect("shred");
    assert_eq!(
        store.audit_query(&all).expect("query after shred"),
        expected,
        "every other partition, and none of the shredded one"
    );
    let own = AuditQuery::new(OPERATOR, AuditScope::OwnAndOwnedSessions, 1000);
    store.audit_query(&own).expect("scoped query after shred");
    let store = store.compact().expect("compact");
    assert_eq!(store.audit_query(&all).expect("after compaction"), expected);
}

#[test]
fn shredded_tenant_cannot_act_or_register_again() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    store.shred_tenant(AGENT).expect("shred");
    let before = dump(&store);
    store
        .shred_tenant(AGENT)
        .expect("a second shred is a no-op");
    assert_eq!(dump(&store), before, "the second shred writes nothing");

    let key = IdempotencyKey::new(vec![7; 24]).expect("key");
    let error = store
        .begin(&Intent::new(invocation(7), capture(G_AGENT), &key, [7; 32]))
        .expect_err("no keys");
    assert!(matches!(error, Error::TenantShredded { .. }), "{error:?}");
    let error = store.begin_rekey(AGENT).expect_err("no keys");
    assert!(matches!(error, Error::TenantShredded { .. }), "{error:?}");
    let registration = TenantRegistration::new(AGENT, TenantClass::Agent, [0x77; 32]);
    let error = store.register_tenant(&registration).expect_err("reserved");
    assert!(matches!(error, Error::TenantShredded { .. }), "{error:?}");
}

#[test]
fn shred_mid_rotation_deletes_both_keys() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    publish_capture(&store, 1, ENVELOPE_A);
    store.begin_rekey(AGENT).expect("begin");
    store.shred_tenant(AGENT).expect("shred");
    assert_eq!(
        agent_wrapped_keys(&store),
        Vec::<Vec<u8>>::new(),
        "all deleted"
    );
    assert!(
        store.rekeys_in_progress().expect("list").is_empty(),
        "no rotation left"
    );
    assert_eq!(
        store.rekey_status(AGENT).expect("status"),
        None,
        "record deleted"
    );
}

#[test]
fn shred_refuses_a_tenant_with_an_open_invocation() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = IdempotencyKey::new(vec![3; 24]).expect("key");
    let begin = store
        .begin(&Intent::new(invocation(3), capture(G_AGENT), &key, [3; 32]))
        .expect("B1");
    assert!(matches!(begin, Begin::Persisted(_)), "{begin:?}");
    let before = dump(&store);
    let error = store.shred_tenant(AGENT).expect_err("busy");
    assert!(
        matches!(error, Error::TenantBusy { tenant, .. } if tenant == AGENT),
        "{error:?}"
    );
    assert_eq!(dump(&store), before, "nothing changed");
    assert_eq!(
        store.recover().expect("recover").released,
        1,
        "the open invocation is released"
    );
    store.shred_tenant(AGENT).expect("shred once terminal");
}

#[test]
fn capture_into_a_shredded_owners_session_is_refused() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let granted = GrantId::from_bytes([0xc0; 16]);
    let mut root = RootGrant::new(
        granted,
        OPERATOR,
        Capability::ALL.iter().copied().collect(),
        vec!["*".to_owned()],
        (
            Timestamp::from_unix_millis(0),
            Timestamp::from_unix_millis(9_000_000),
        ),
        4,
    );
    root.session_scope = SessionScope::Sessions(vec![S_AGENT]);
    store
        .install_root_grant(&root)
        .expect("grant on the agent's session");
    let mut request = capture(granted);
    request.tenant = OPERATOR;
    let key = IdempotencyKey::new(vec![5; 24]).expect("key");
    let plan = store.plan(&request).expect("plan");
    assert_eq!(
        plan.refusal, None,
        "the operator may capture into the agent's session: {plan:?}"
    );

    store.shred_tenant(AGENT).expect("shred");
    let begin = store
        .begin(&Intent::new(invocation(5), request, &key, [5; 32]))
        .expect("B1");
    assert!(
        matches!(
            begin,
            Begin::Refused {
                failure: Failure::NotFoundOrDenied,
                ..
            }
        ),
        "{begin:?}"
    );
    assert_eq!(
        store.invocation(invocation(5)).expect("read"),
        None,
        "no intent"
    );
    assert!(
        store.recover().expect("recover").is_empty(),
        "nothing to recover"
    );
}

#[test]
fn shred_of_an_unknown_tenant_is_missing() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let stranger = syntheke::TenantId::from_bytes(*b"TENANT-STRANGER2");
    let error = store.shred_tenant(stranger).expect_err("unknown");
    assert!(matches!(error, Error::TenantMissing { .. }), "{error:?}");
}
