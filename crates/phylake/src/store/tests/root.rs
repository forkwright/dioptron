//! Root key rotation: one transaction moves every store-sealed record and
//! wrapped key to the new root key, and the old key no longer opens the
//! store.

use std::sync::Arc;

use syntheke::{TenantClass, TenantId};

use crate::Error;
use crate::crypto::{KeyId, Keyspace, sealed_key_id};
use crate::keyfile::RootKey;
use crate::store::record_key::store as keys;
use crate::store::records::LedgerRef;
use crate::store::test_support::{
    AGENT, CrashAt, Dump, Fixture, G_AGENT, NEXT_ROOT_BYTES, OPERATOR, OTHER, ROOT_BYTES, capture,
    dump, invocation, ledger_usage, publish_capture, reads,
};
use crate::store::{Boundary, Phase, Store, TenantRegistration};

/// A tenant registered and then shredded, so a tombstone exists.
const SHREDDED: TenantId = TenantId::from_bytes(*b"TENANT-SHREDDED1");

const ROOT_2: KeyId = KeyId::new(2);

fn root() -> RootKey {
    RootKey::from_bytes(ROOT_BYTES)
}

fn next_root() -> RootKey {
    RootKey::from_bytes(NEXT_ROOT_BYTES)
}

/// Keyspaces holding only store-sealed records.
const STORE_SEALED: [&str; 8] = [
    "tenants",
    "grants",
    "revocations",
    "sessions",
    "invocations",
    "ledgers",
    "audit_stub",
    "rekey",
];

/// A store with captures, a tenant mid-rotation, and a shredded tenant.
fn populated(fixture: &Fixture) -> (Store, Vec<syntheke::ArtifactRef>) {
    let store = fixture.seeded();
    let artifacts = vec![
        publish_capture(&store, 1, b"<p>ROOT-ENVELOPE-ONE example.com</p>"),
        publish_capture(&store, 2, b"<p>ROOT-ENVELOPE-TWO example.com</p>"),
    ];
    let mut registration = TenantRegistration::new(SHREDDED, TenantClass::Agent, [0x78; 32]);
    registration.parent = Some(OPERATOR);
    store.register_tenant(&registration).expect("register");
    store.shred_tenant(SHREDDED).expect("shred");
    store.begin_rekey(OTHER).expect("begin a rotation");
    (store, artifacts)
}

fn entries<'a>(dump: &'a Dump, keyspace: &str) -> &'a [(Vec<u8>, Vec<u8>)] {
    dump.iter()
        .find(|(name, _)| *name == keyspace)
        .map_or(&[], |(_, entries)| entries.as_slice())
}

/// The key id in a wrapped key's header (after the 2-byte version).
fn kek_id(wrapped: &[u8]) -> KeyId {
    sealed_key_id(wrapped).expect("header")
}

#[test]
fn root_rotation_moves_every_record_and_locks_out_the_old_key() {
    let fixture = Fixture::new();
    let (mut store, artifacts) = populated(&fixture);
    let before_reads = reads(&store, &artifacts);
    let before_ledgers = ledger_usage(&store);
    let before_status = store.invocation(invocation(1)).expect("status");
    let before = dump(&store);

    let id = store.rotate_root(&root(), &next_root()).expect("rotate");
    assert_eq!(id, ROOT_2, "the root key id advances");
    let after = dump(&store);
    for keyspace in STORE_SEALED {
        let (old, new) = (entries(&before, keyspace), entries(&after, keyspace));
        assert_eq!(old.len(), new.len(), "{keyspace}: every record moved");
        assert!(
            new.iter()
                .all(|(_, value)| sealed_key_id(value) == Some(ROOT_2)),
            "{keyspace}: sealed under the new root key"
        );
        if keyspace != "audit_stub" {
            assert!(
                new.iter().all(|(key, _)| old.iter().all(|(k, _)| k != key)),
                "{keyspace}: every record key is rehashed"
            );
        }
    }
    let wrapped = entries(&after, "keys");
    // WHY 5: the operator and the agent hold one data key each; the other
    // tenant, mid-rotation, holds its retiring key, its new key, and its
    // addressing subkeys; the shredded tenant holds none.
    assert_eq!(wrapped.len(), 5, "{wrapped:?}");
    assert!(
        wrapped.iter().all(|(_, value)| kek_id(value) == ROOT_2),
        "every wrapped key is under the new key-encryption subkey"
    );
    let meta = entries(&after, "meta");
    for field in ["kdf_salt", "key_check", "active_root_key_id"] {
        let value = |dump: &Dump| {
            entries(dump, "meta")
                .iter()
                .find(|(key, _)| key.as_slice() == field.as_bytes())
                .map(|(_, value)| value.clone())
        };
        assert_ne!(value(&before), value(&after), "{field} changes: {meta:?}");
    }
    assert_eq!(reads(&store, &artifacts), before_reads, "reads unchanged");
    assert_eq!(ledger_usage(&store), before_ledgers, "ledgers unchanged");
    store
        .plan(&capture(G_AGENT))
        .expect("authorization reads the moved grants");
    drop(store);

    let error = fixture.options().open(&root()).expect_err("old key");
    assert!(matches!(error, Error::StoreLocked { .. }), "{error:?}");
    let store = fixture.options().open(&next_root()).expect("new key");
    assert_eq!(
        reads(&store, &artifacts),
        before_reads,
        "reads after reopen"
    );
    assert_eq!(
        store.invocation(invocation(1)).expect("status"),
        before_status
    );
    let status = store
        .rekey_tenant(OTHER, std::num::NonZeroUsize::MIN)
        .expect("the rotation in progress resumes");
    assert_eq!(status.to_key_id, KeyId::new(2), "{status:?}");
    let again = TenantRegistration::new(SHREDDED, TenantClass::Agent, [0x78; 32]);
    let error = store.register_tenant(&again).expect_err("tombstone moved");
    assert!(matches!(error, Error::TenantShredded { .. }), "{error:?}");
    publish_capture(&store, 3, b"<p>ROOT-AFTER example.com</p>");
}

#[test]
fn rotation_with_the_wrong_current_key_is_locked_and_changes_nothing() {
    let fixture = Fixture::new();
    let (mut store, _) = populated(&fixture);
    let before = dump(&store);
    let error = store
        .rotate_root(&next_root(), &RootKey::from_bytes([0x11; 32]))
        .expect_err("wrong current key");
    assert!(matches!(error, Error::StoreLocked { .. }), "{error:?}");
    assert_eq!(dump(&store), before, "nothing changed");
}

#[test]
fn crash_before_or_after_the_rotation_commit_leaves_one_working_key() {
    for phase in Phase::ALL {
        let fixture = Fixture::new();
        let (store, artifacts) = populated(&fixture);
        let expected = reads(&store, &artifacts);
        drop(store);
        let mut store = fixture.reopen_with(Arc::new(CrashAt {
            boundary: Boundary::RootRotation,
            phase,
        }));
        let error = store.rotate_root(&root(), &next_root()).expect_err("crash");
        assert!(matches!(error, Error::InjectedCrash { .. }), "{error:?}");
        drop(store);
        let (works, locked) = match phase {
            Phase::BeforeCommit => (root(), next_root()),
            _ => (next_root(), root()),
        };
        let error = fixture.options().open(&locked).expect_err("locked");
        assert!(
            matches!(error, Error::StoreLocked { .. }),
            "{phase}: {error:?}"
        );
        let store = fixture.options().open(&works).expect("opens");
        assert_eq!(reads(&store, &artifacts), expected, "{phase}: reads");
    }
}

/// Plants an inconsistency with `plant`, then checks that rotation fails
/// as inconsistent and writes nothing.
fn refuses(plant: impl FnOnce(&Store)) {
    let fixture = Fixture::new();
    let (mut store, _) = populated(&fixture);
    plant(&store);
    let before = dump(&store);
    let error = store
        .rotate_root(&root(), &next_root())
        .expect_err("refused");
    assert!(matches!(error, Error::Inconsistent { .. }), "{error:?}");
    assert_eq!(dump(&store), before, "nothing changed");
    drop(store);
    fixture
        .options()
        .open(&root())
        .expect("the old key still opens");
}

#[test]
fn rotation_refuses_a_ledger_with_no_owner() {
    refuses(|store| {
        let orphan = LedgerRef::Grant(syntheke::GrantId::from_bytes([0xee; 16]));
        let mut tx = store.write_tx();
        store
            .put_ledger(&mut tx, orphan, syntheke::Cost::default())
            .expect("stage");
        tx.commit().expect("plant");
    });
}

#[test]
fn rotation_refuses_a_wrapped_key_with_no_tenant() {
    refuses(|store| {
        let key = keys::data_key(store.keys.index(), AGENT, KeyId::new(9)).expect("key");
        let mut tx = store.write_tx();
        tx.insert(
            store.ks.get(Keyspace::Keys).expect("keys"),
            key,
            vec![0_u8; 82],
        );
        tx.commit().expect("plant");
    });
}

#[test]
fn rotation_refuses_a_store_record_that_does_not_open() {
    refuses(|store| {
        let mut tx = store.write_tx();
        tx.insert(
            store.ks.get(Keyspace::Grants).expect("grants"),
            [0x42_u8; 32],
            // A record version 1 header naming root key 1, then bytes
            // that fail authentication.
            [&[1_u8, 0, 1, 0, 0, 0][..], &[0x33; 56]].concat(),
        );
        tx.commit().expect("plant");
    });
}
