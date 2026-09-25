//! Create, reopen, locked start, and schema version refusal.

use std::sync::Arc;

use epitrope::Clock;
use fjall::{KeyspaceCreateOptions, PersistMode, SingleWriterTxDatabase};
use syntheke::TenantClass;

use crate::Error;
use crate::keyfile::RootKey;
use crate::store::meta::field;
use crate::store::test_support::{AGENT, Fixture, OPERATOR, ROOT_BYTES, TestClock, dump};
use crate::store::{
    SCHEMA_VERSION, StoreOptions, TenantDirectory as _, TenantEntry, TenantRegistration,
};

/// Rewrites one plaintext `meta` field of a closed store.
fn set_meta(fixture: &Fixture, name: &str, value: Vec<u8>) {
    let db = SingleWriterTxDatabase::builder(&fixture.path)
        .open()
        .expect("open raw database");
    let meta = db
        .keyspace("meta", KeyspaceCreateOptions::default)
        .expect("meta keyspace");
    meta.insert(name, value).expect("write field");
    db.persist(PersistMode::SyncAll).expect("persist");
}

#[test]
fn create_reopen_and_read_round_trip() {
    let fixture = Fixture::new();
    let store = fixture.create();
    let mut registration = TenantRegistration::new(OPERATOR, TenantClass::Operator, [0x42; 32]);
    registration.bound_uids = vec![1000, 1001];
    store.register_tenant(&registration).expect("register");
    drop(store);

    let store = fixture.reopen();
    let entry = store.tenant(OPERATOR).expect("read").expect("registered");
    assert_eq!(
        entry,
        TenantEntry {
            id: OPERATOR,
            class: TenantClass::Operator,
            verifying_key: [0x42; 32],
            bound_uids: vec![1000, 1001],
            parent: None,
        },
        "the tenant survives a reopen"
    );
    assert_eq!(
        store.tenant(AGENT).expect("read"),
        None,
        "an unknown tenant reads as absent"
    );
}

#[test]
fn register_tenant_is_idempotent_and_refuses_a_different_identity() {
    let fixture = Fixture::new();
    let store = fixture.create();
    let registration = TenantRegistration::new(OPERATOR, TenantClass::Operator, [0x42; 32]);
    store.register_tenant(&registration).expect("first");
    let before = dump(&store);
    store.register_tenant(&registration).expect("repeat");
    assert_eq!(dump(&store), before, "a repeat writes nothing");

    let other = TenantRegistration::new(OPERATOR, TenantClass::Agent, [0x42; 32]);
    let error = store.register_tenant(&other).expect_err("conflict");
    assert!(
        matches!(error, Error::Conflict { what: "tenant", .. }),
        "{error:?}"
    );

    let mut orphan = TenantRegistration::new(AGENT, TenantClass::Agent, [0x43; 32]);
    orphan.parent = Some(crate::store::test_support::OTHER);
    let error = store.register_tenant(&orphan).expect_err("missing parent");
    assert!(matches!(error, Error::TenantMissing { .. }), "{error:?}");
}

#[test]
fn open_with_wrong_key_is_locked_and_writes_nothing() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let before = dump(&store);
    drop(store);

    let error = fixture
        .options()
        .open(&RootKey::from_bytes([0x5b; 32]))
        .expect_err("wrong key");
    assert!(matches!(error, Error::StoreLocked { .. }), "{error:?}");

    let store = fixture.reopen();
    assert_eq!(
        dump(&store),
        before,
        "a locked open leaves every keyspace as it was"
    );
}

#[test]
fn open_refuses_a_newer_schema_version() {
    let fixture = Fixture::new();
    drop(fixture.create());
    let newer = SCHEMA_VERSION.get().checked_add(1).expect("next version");
    set_meta(
        &fixture,
        field::SCHEMA_VERSION,
        newer.to_le_bytes().to_vec(),
    );

    let error = fixture
        .options()
        .open(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("newer schema");
    assert!(
        matches!(error, Error::SchemaTooNew { found, supported, .. } if found == newer && supported == SCHEMA_VERSION.get()),
        "{error:?}"
    );
}

#[test]
fn open_requires_migration_for_an_older_schema_version() {
    let fixture = Fixture::new();
    drop(fixture.create());
    set_meta(
        &fixture,
        field::SCHEMA_VERSION,
        0_u32.to_le_bytes().to_vec(),
    );

    let error = fixture
        .options()
        .open(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("older schema");
    assert!(
        matches!(error, Error::MigrationRequired { found: 0, .. }),
        "{error:?}"
    );
}

#[test]
fn open_refuses_malformed_metadata() {
    let fixture = Fixture::new();
    drop(fixture.create());
    set_meta(&fixture, "format", b"another-format".to_vec());
    let error = fixture
        .options()
        .open(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("format");
    assert!(
        matches!(
            error,
            Error::MetaMalformed {
                field: "format",
                ..
            }
        ),
        "{error:?}"
    );

    let fixture = Fixture::new();
    drop(fixture.create());
    set_meta(&fixture, "kdf_salt", vec![1, 2, 3]);
    let error = fixture
        .options()
        .open(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("short salt");
    assert!(
        matches!(
            error,
            Error::MetaMalformed {
                field: "kdf_salt",
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn open_without_a_store_fails_and_creates_nothing() {
    let fixture = Fixture::new();
    let error = fixture
        .options()
        .open(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("missing");
    assert!(
        matches!(
            error,
            Error::StoreMissing {
                missing: "database",
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!fixture.path.exists(), "open never creates a store");
}

#[test]
fn open_of_a_database_without_keyspaces_is_missing() {
    let fixture = Fixture::new();
    drop(
        SingleWriterTxDatabase::builder(&fixture.path)
            .open()
            .expect("raw database"),
    );
    let error = fixture
        .options()
        .open(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("no keyspaces");
    assert!(
        matches!(
            error,
            Error::StoreMissing {
                missing: "meta",
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn create_refuses_a_non_empty_path() {
    let fixture = Fixture::new();
    std::fs::create_dir(&fixture.path).expect("dir");
    std::fs::write(fixture.path.join("unrelated"), b"x").expect("file");
    let error = fixture
        .options()
        .create(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("non-empty");
    assert!(matches!(error, Error::StoreExists { .. }), "{error:?}");

    let fixture = Fixture::new();
    std::fs::write(&fixture.path, b"a file").expect("file");
    let error = fixture
        .options()
        .create(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("a file");
    assert!(matches!(error, Error::StoreExists { .. }), "{error:?}");
}

#[test]
fn create_under_a_missing_parent_is_an_io_error() {
    let fixture = Fixture::new();
    let clock: Arc<dyn Clock + Send + Sync> = TestClock::new();
    let error = StoreOptions::new(fixture.path.join("absent/store"), clock)
        .create(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("missing parent");
    assert!(matches!(error, Error::StoreIo { .. }), "{error:?}");
}

#[test]
fn second_open_of_a_live_store_is_a_database_error() {
    let fixture = Fixture::new();
    let _store = fixture.create();
    let error = fixture
        .options()
        .open(&RootKey::from_bytes(ROOT_BYTES))
        .expect_err("locked by the first handle");
    assert!(matches!(error, Error::Database { .. }), "{error:?}");
}

#[test]
fn new_store_directory_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new();
    let _store = fixture.create();
    let mode = std::fs::metadata(&fixture.path)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "group and other have no access: {mode:o}");
}
