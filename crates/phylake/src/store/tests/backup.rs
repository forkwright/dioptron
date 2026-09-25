//! Backup by directory copy, restore verification, and compaction by
//! rewrite.

use std::path::Path;

use rustix::io::Errno;

use crate::Error;
use crate::crypto::KeyId;
use crate::keyfile::RootKey;
use crate::store::compact::{exchange_error, staging_path, swap_in};
use crate::store::open_database;
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

#[test]
fn swap_refuses_a_directory_another_handle_holds_open() {
    let fixture = Fixture::new();
    let before = dump(&fixture.seeded());
    let staging = staging_path(&fixture.path).expect("staging");
    let other = open_database(&staging).expect("a database holding the staging lock");
    let error = swap_in(&fixture.path, &staging).expect_err("staging is in use");
    assert!(
        matches!(&error, Error::StoreInUse { path, .. } if *path == staging),
        "{error:?}"
    );
    drop(other);
    assert!(staging.exists(), "the held directory is not removed");
    assert_eq!(dump(&fixture.reopen()), before, "the store is not swapped");
}

#[test]
fn swap_exchanges_the_directories_and_removes_the_old_store() {
    let fixture = Fixture::new();
    drop(fixture.seeded());
    let staging = staging_path(&fixture.path).expect("staging");
    drop(open_database(&staging).expect("an empty database"));
    std::fs::write(staging.join("COPY-MARKER"), b"copy").expect("marker");
    swap_in(&fixture.path, &staging).expect("swap");
    assert!(
        fixture.path.join("COPY-MARKER").exists(),
        "the copy is at the store path"
    );
    assert!(!staging.exists(), "the replaced store is removed");
}

#[test]
fn exchange_failures_name_an_unsupported_filesystem() {
    let path = Path::new("/store");
    for errno in [Errno::INVAL, Errno::NOSYS, Errno::OPNOTSUPP] {
        let error = exchange_error(errno, path);
        assert!(
            matches!(error, Error::ExchangeUnsupported { .. }),
            "{errno:?}: {error:?}"
        );
    }
    let error = exchange_error(Errno::ACCESS, path);
    assert!(matches!(error, Error::StoreIo { .. }), "{error:?}");
}
