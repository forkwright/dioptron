//! Backup by directory copy, restore verification, and compaction by
//! rewrite.

use std::path::Path;

use crate::Error;
use crate::crypto::KeyId;
use crate::keyfile::RootKey;
use crate::store::compact::staging_path;
use crate::store::test_support::{
    Fixture, ROOT_BYTES, TestClock, copy_tree, dump, publish_capture, reads,
};
use crate::store::{RestoredStore, SCHEMA_VERSION, StoreOptions, verify_restored};

fn root() -> RootKey {
    RootKey::from_bytes(ROOT_BYTES)
}

fn options(path: &Path) -> StoreOptions {
    let clock: std::sync::Arc<dyn epitrope::Clock + Send + Sync> = TestClock::new();
    StoreOptions::new(path, clock)
}

#[test]
fn a_directory_copy_restores_the_same_artifacts() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let artifacts = vec![
        publish_capture(&store, 1, b"<p>BACKUP-ENVELOPE-ONE example.com</p>"),
        publish_capture(&store, 2, b"<p>BACKUP-ENVELOPE-TWO example.com</p>"),
    ];
    let expected = reads(&store, &artifacts);
    drop(store);

    let copy = fixture.path.with_file_name("restored");
    copy_tree(&fixture.path, &copy);
    let verified = verify_restored(&copy, &root()).expect("verify");
    assert_eq!(
        verified,
        RestoredStore {
            schema_version: SCHEMA_VERSION,
            root_key_id: KeyId::new(1),
        },
        "the copy's schema version and root key id"
    );
    let restored = options(&copy).open(&root()).expect("open the copy");
    assert_eq!(reads(&restored, &artifacts), expected, "the same artifacts");
    drop(restored);

    let wrong = RootKey::from_bytes([0x5b; 32]);
    let error = verify_restored(&copy, &wrong).expect_err("wrong key");
    assert!(matches!(error, Error::StoreLocked { .. }), "{error:?}");
    let error = options(&copy).open(&wrong).expect_err("wrong key");
    assert!(matches!(error, Error::StoreLocked { .. }), "{error:?}");
}

#[test]
fn verify_restored_refuses_an_incomplete_copy() {
    let fixture = Fixture::new();
    std::fs::create_dir(&fixture.path).expect("empty directory");
    let error = verify_restored(&fixture.path, &root()).expect_err("no store");
    assert!(matches!(error, Error::StoreMissing { .. }), "{error:?}");
}

#[test]
fn verify_restored_refuses_a_newer_schema() {
    let fixture = Fixture::new();
    drop(fixture.create());
    {
        let db = fjall::SingleWriterTxDatabase::builder(&fixture.path)
            .open()
            .expect("raw open");
        let meta = db
            .keyspace("meta", fjall::KeyspaceCreateOptions::default)
            .expect("meta");
        let newer = SCHEMA_VERSION.get().saturating_add(1);
        meta.insert("schema_version", newer.to_le_bytes().to_vec())
            .expect("write");
        db.persist(fjall::PersistMode::SyncAll).expect("persist");
    }
    let error = verify_restored(&fixture.path, &root()).expect_err("newer");
    assert!(matches!(error, Error::SchemaTooNew { .. }), "{error:?}");
}

#[test]
fn compact_keeps_every_live_record() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let artifacts = vec![publish_capture(
        &store,
        1,
        b"<p>COMPACT-ENVELOPE example.com</p>",
    )];
    let before = dump(&store);
    let expected = reads(&store, &artifacts);
    let store = store.compact().expect("compact");
    assert_eq!(dump(&store), before, "every live entry is copied verbatim");
    assert_eq!(reads(&store, &artifacts), expected, "reads unchanged");
    assert!(
        !staging_path(&fixture.path).expect("staging").exists(),
        "the replaced store is removed"
    );
    let store = store.compact().expect("compact again");
    assert_eq!(dump(&store), before, "a second compaction changes nothing");
    publish_capture(&store, 2, b"<p>COMPACT-AFTER example.com</p>");
    drop(store);
    fixture.reopen();
}

#[test]
fn open_removes_a_leftover_staging_directory() {
    let fixture = Fixture::new();
    drop(fixture.seeded());
    let staging = staging_path(&fixture.path).expect("staging");
    std::fs::create_dir(&staging).expect("leftover");
    std::fs::write(staging.join("0.jnl"), b"LEFTOVER-JOURNAL").expect("file");
    drop(fixture.reopen());
    assert!(!staging.exists(), "the leftover is removed at open");
}

#[test]
fn a_path_without_a_name_has_no_staging_directory() {
    let error = staging_path(Path::new("/")).expect_err("no name");
    assert!(matches!(error, Error::StorePathUnnamed { .. }), "{error:?}");
}
