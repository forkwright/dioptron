#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::crypto::test_support::{FailingEntropy, PATTERN_32_HEX, PatternEntropy, unhex};

const FIXTURE_KEY: [u8; ROOT_KEY_LEN] = [0x5a; ROOT_KEY_LEN];

fn write_key(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write fixture key file");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
    path
}

#[test]
fn load_accepts_owner_only_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_key(dir.path(), "root.key", &FIXTURE_KEY, 0o600);
    let key = RootKey::load(&path).expect("0600 key file loads");
    assert_eq!(key.expose(), &FIXTURE_KEY, "loaded bytes match the file");
}

#[test]
fn load_accepts_owner_read_only_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_key(dir.path(), "root.key", &FIXTURE_KEY, 0o400);
    assert!(RootKey::load(&path).is_ok(), "0400 has no group/other bits");
}

#[test]
fn load_refuses_group_or_other_bits() {
    let dir = tempfile::tempdir().expect("tempdir");
    for mode in [0o640, 0o604, 0o644, 0o610, 0o601, 0o620, 0o602] {
        let path = write_key(dir.path(), &format!("k{mode:o}"), &FIXTURE_KEY, mode);
        let err = RootKey::load(&path).expect_err("loose mode must be refused");
        assert!(
            matches!(err, Error::RootKeyPermissions { mode: m, .. } if m == mode),
            "mode {mode:o} refused with RootKeyPermissions, got {err:?}"
        );
    }
}

#[test]
fn load_refuses_wrong_length() {
    let dir = tempfile::tempdir().expect("tempdir");
    for len in [0_usize, 31, 33, 64] {
        let path = write_key(dir.path(), &format!("k{len}"), &vec![7_u8; len], 0o600);
        let err = RootKey::load(&path).expect_err("wrong length must be refused");
        assert!(
            matches!(err, Error::RootKeyLength { found, expected: 32, .. } if usize::try_from(found) == Ok(len)),
            "length {len} refused with RootKeyLength, got {err:?}"
        );
    }
}

#[test]
fn load_refuses_missing_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = RootKey::load(&dir.path().join("absent.key")).expect_err("missing refused");
    assert!(matches!(err, Error::RootKeyMissing { .. }), "got {err:?}");
}

#[test]
fn load_refuses_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sub = dir.path().join("keydir");
    fs::create_dir(&sub).expect("mkdir");
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).expect("chmod");
    let err = RootKey::load(&sub).expect_err("directory refused");
    assert!(matches!(err, Error::RootKeyNotFile { .. }), "got {err:?}");
}

#[test]
fn load_reports_io_failure_for_non_directory_parent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = write_key(dir.path(), "plain", b"x", 0o600);
    let err = RootKey::load(&file.join("root.key")).expect_err("ENOTDIR refused");
    assert!(matches!(err, Error::RootKeyIo { .. }), "got {err:?}");
}

#[test]
fn load_refuses_symlink_to_valid_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = write_key(dir.path(), "real.key", &FIXTURE_KEY, 0o600);
    assert!(RootKey::load(&target).is_ok(), "the target itself loads");
    let link = dir.path().join("root.key");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let err = RootKey::load(&link).expect_err("symlink refused");
    assert!(matches!(err, Error::RootKeySymlink { .. }), "got {err:?}");
}

#[test]
fn load_refuses_fifo_without_blocking() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("root.key");
    rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::from_raw_mode(0o600)).expect("mkfifo");
    // WHY a thread and a bound: a blocking open would hang the test
    // forever; the bound turns that regression into a failure. It is a
    // ceiling, not a sleep the result depends on.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        drop(tx.send(RootKey::load(&fifo).map(drop)));
    });
    let result = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("load on a FIFO returned instead of blocking");
    let err = result.expect_err("FIFO refused");
    assert!(matches!(err, Error::RootKeyNotFile { .. }), "got {err:?}");
}

#[test]
fn load_refuses_unix_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("root.key");
    let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
    let err = RootKey::load(&path).expect_err("socket refused");
    assert!(matches!(err, Error::RootKeyNotFile { .. }), "got {err:?}");
}

#[test]
fn check_owner_refuses_foreign_uid() {
    let euid = rustix::process::geteuid().as_raw();
    let other = euid.checked_add(1).expect("euid below u32::MAX");
    let path = Path::new("root.key");
    let err = check_owner(path, other, euid).expect_err("foreign owner refused");
    assert!(
        matches!(err, Error::RootKeyOwner { owner, euid: e, .. } if owner == other && e == euid),
        "got {err:?}"
    );
    assert!(check_owner(path, euid, euid).is_ok(), "own file accepted");
}

#[test]
fn generate_refuses_symlink_at_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("elsewhere.key");
    let link = dir.path().join("root.key");
    std::os::unix::fs::symlink(&target, &link).expect("dangling symlink");
    let err = RootKey::generate(&link).expect_err("symlink refused");
    assert!(matches!(err, Error::RootKeyExists { .. }), "got {err:?}");
    assert!(!target.exists(), "nothing written through the link");
}

#[test]
fn generate_writes_owner_only_key_that_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("root.key");
    let generated = RootKey::generate(&path).expect("generate");
    let meta = fs::metadata(&path).expect("stat");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600, "created 0600");
    assert_eq!(meta.len(), 32, "32 raw bytes");
    assert_eq!(
        meta.uid(),
        rustix::process::geteuid().as_raw(),
        "owned by the effective uid"
    );
    let loaded = RootKey::load(&path).expect("generated key loads");
    assert_eq!(generated.expose(), loaded.expose(), "round trip");
    assert_ne!(generated.expose(), &[0_u8; 32], "not the zero buffer");
}

#[test]
fn generate_refuses_existing_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_key(dir.path(), "root.key", &FIXTURE_KEY, 0o600);
    let err = RootKey::generate(&path).expect_err("existing file refused");
    assert!(matches!(err, Error::RootKeyExists { .. }), "got {err:?}");
    assert_eq!(
        fs::read(&path).expect("read"),
        FIXTURE_KEY,
        "file untouched"
    );
}

#[test]
fn generate_reports_io_failure_for_missing_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = RootKey::generate(&dir.path().join("no/such/root.key")).expect_err("refused");
    assert!(matches!(err, Error::RootKeyIo { .. }), "got {err:?}");
}

#[test]
fn generate_writes_exactly_the_drawn_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("root.key");
    let generated = RootKey::generate_with(&path, &mut PatternEntropy).expect("generate");
    let expected = unhex(PATTERN_32_HEX);
    assert_eq!(generated.expose().as_slice(), expected, "in-memory key");
    assert_eq!(fs::read(&path).expect("read"), expected, "file contents");
}

#[test]
fn generate_creates_no_file_when_entropy_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("root.key");
    let err = RootKey::generate_with(&path, &mut FailingEntropy).expect_err("refused");
    assert!(matches!(err, Error::Entropy { .. }), "got {err:?}");
    assert!(!path.exists(), "no file left behind");
}

#[test]
fn debug_redacts_root_key() {
    let key = RootKey::from_bytes(FIXTURE_KEY);
    let shown = format!("{key:?}");
    assert_eq!(shown, "RootKey([REDACTED])", "debug is redacted");
    assert!(!shown.contains("90"), "no decimal key byte (0x5a = 90)");
}
