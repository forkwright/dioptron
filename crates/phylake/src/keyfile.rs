//! The operator-held root key file.
//!
//! The root key is 32 raw bytes in a file kept apart from the store
//! directory. Loading fails closed: a missing file, a symbolic link at the
//! key path, anything other than a regular file, a file owned by another
//! user, any group or other permission bit, or any length other than 32
//! bytes refuses the open. The key lives in a [`SecretBox`] that zeroes on
//! drop.
//!
//! The file is opened with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_NOCTTY`
//! and every check runs on the opened descriptor (`fstat`), never on a
//! second path lookup, so the checks apply to the file actually read.
//! `O_NOFOLLOW` covers only the final path component: symbolic links in
//! parent directories are followed, and the directory holding the key is
//! the operator's to protect. `O_NONBLOCK` keeps a FIFO or device node at the
//! key path from blocking the open; such a node is then refused as not a
//! regular file before any read. Non-blocking mode has no effect on reads
//! from a regular file. A device node's driver still sees the open call
//! before the refusal; `O_NOCTTY` keeps a terminal from becoming the
//! process's controlling terminal.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use snafu::{IntoError, ResultExt, ensure};
use zeroize::ZeroizeOnDrop;

use crate::crypto::{Entropy, OsEntropy};
use crate::error::{
    RootKeyExistsSnafu, RootKeyIoSnafu, RootKeyLengthSnafu, RootKeyMissingSnafu,
    RootKeyNotFileSnafu, RootKeyOwnerSnafu, RootKeyPermissionsSnafu, RootKeySymlinkSnafu,
};
use crate::{Error, Result};

/// Length of the root key in bytes.
pub const ROOT_KEY_LEN: usize = 32;

/// Permission bits for group and other; any of them set refuses the key file.
const GROUP_OTHER_BITS: u32 = 0o077;

/// [`ROOT_KEY_LEN`] as a file length.
const ROOT_KEY_LEN_U64: u64 = 32;

/// Mode for a newly generated key file: owner read and write only.
const NEW_KEY_MODE: u32 = 0o600;

/// The store's root key, zeroed on drop.
pub struct RootKey {
    bytes: SecretBox<[u8; ROOT_KEY_LEN]>,
}

impl RootKey {
    /// Load the root key from `path`.
    ///
    /// # Errors
    ///
    /// - [`Error::RootKeyMissing`] when the file does not exist.
    /// - [`Error::RootKeySymlink`] when the final path component is a
    ///   symbolic link.
    /// - [`Error::RootKeyNotFile`] when the path is not a regular file (a
    ///   directory, FIFO, socket, or device node).
    /// - [`Error::RootKeyOwner`] when the file's owner is not the effective uid.
    /// - [`Error::RootKeyPermissions`] when any group or other bit is set.
    /// - [`Error::RootKeyLength`] when the file is not exactly 32 bytes.
    /// - [`Error::RootKeyIo`] for any other I/O failure.
    pub fn load(path: &Path) -> Result<Self> {
        let mut file = open_key_file(path)?;
        let meta = file.metadata().context(RootKeyIoSnafu { path })?;
        ensure!(meta.is_file(), RootKeyNotFileSnafu { path });
        check_owner(path, meta.uid(), rustix::process::geteuid().as_raw())?;
        let mode = meta.permissions().mode();
        ensure!(
            mode & GROUP_OTHER_BITS == 0,
            RootKeyPermissionsSnafu {
                path,
                mode: mode & 0o7777,
            }
        );
        ensure!(
            meta.len() == ROOT_KEY_LEN_U64,
            RootKeyLengthSnafu {
                path,
                found: meta.len(),
                expected: ROOT_KEY_LEN,
            }
        );
        let mut bytes = SecretBox::new(Box::new([0_u8; ROOT_KEY_LEN]));
        file.read_exact(bytes.expose_secret_mut())
            .map_err(|error| short_read_error(path, &file, error))?;
        // WHY: the length check above used metadata; a file that grew between
        // fstat and read is rejected rather than truncated to 32 bytes.
        let mut probe = [0_u8; 1];
        let extra = file.read(&mut probe).context(RootKeyIoSnafu { path })?;
        ensure!(
            extra == 0,
            RootKeyLengthSnafu {
                path,
                found: current_len(&file).max(33),
                expected: ROOT_KEY_LEN,
            }
        );
        Ok(Self { bytes })
    }

    /// Generate a new root key from the operating system random source and
    /// write it to `path` with mode 0600.
    ///
    /// The file is created with `O_CREAT | O_EXCL | O_NOFOLLOW` and its mode
    /// set at creation, so no window exists where it is readable by group or
    /// other, and neither an existing file nor a symbolic link at `path` is
    /// ever written through.
    ///
    /// # Errors
    ///
    /// - [`Error::Entropy`] when the random source fails; no file is created.
    /// - [`Error::RootKeyExists`] when `path` already exists, including as a
    ///   symbolic link.
    /// - [`Error::RootKeyIo`] when creating, writing, or syncing fails.
    pub fn generate(path: &Path) -> Result<Self> {
        Self::generate_with(path, &mut OsEntropy)
    }

    pub(crate) fn generate_with(path: &Path, entropy: &mut impl Entropy) -> Result<Self> {
        let mut bytes = SecretBox::new(Box::new([0_u8; ROOT_KEY_LEN]));
        entropy.fill(bytes.expose_secret_mut())?;
        let mut file = create_key_file(path)?;
        let written = file
            .write_all(bytes.expose_secret())
            .and_then(|()| file.sync_all());
        if let Err(error) = written {
            // NOTE: best-effort cleanup of a partial file; the write error is
            // what the caller needs, and a leftover short file is refused by
            // `load` on length anyway.
            drop(std::fs::remove_file(path));
            return Err(error).context(RootKeyIoSnafu { path });
        }
        sync_parent(path)?;
        Ok(Self { bytes })
    }

    pub(crate) fn expose(&self) -> &[u8; ROOT_KEY_LEN] {
        self.bytes.expose_secret()
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; ROOT_KEY_LEN]) -> Self {
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
        }
    }
}

impl ZeroizeOnDrop for RootKey {}

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootKey([REDACTED])")
    }
}

/// Open the key file read-only without following a final symbolic link and
/// without blocking on a FIFO or device node.
fn open_key_file(path: &Path) -> Result<File> {
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY;
    rustix::fs::open(path, flags, Mode::empty())
        .map(File::from)
        .map_err(|errno| open_error(path, errno))
}

/// Create the key file exclusively with mode 0600.
fn create_key_file(path: &Path) -> Result<File> {
    // WHY O_NOFOLLOW beside O_EXCL: O_EXCL already fails on any existing
    // entry, a dangling symbolic link included; O_NOFOLLOW states the intent
    // and keeps it if the flags are ever changed.
    let flags = OFlags::WRONLY
        | OFlags::CREATE
        | OFlags::EXCL
        | OFlags::NOFOLLOW
        | OFlags::CLOEXEC
        | OFlags::NOCTTY;
    rustix::fs::open(path, flags, Mode::from_raw_mode(NEW_KEY_MODE))
        .map(File::from)
        .map_err(|errno| create_error(path, errno))
}

/// Refuse a key file whose owner is not the effective uid.
///
/// WHY: permission bits alone do not show who can rewrite the file. A key
/// file owned by another user (or by root while the daemon runs unprivileged)
/// can be replaced or read by that user regardless of its group and other
/// bits, so the key would not be in the operator's sole custody.
fn check_owner(path: &Path, owner: u32, euid: u32) -> Result<()> {
    ensure!(owner == euid, RootKeyOwnerSnafu { path, owner, euid });
    Ok(())
}

fn open_error(path: &Path, errno: rustix::io::Errno) -> Error {
    match errno {
        rustix::io::Errno::NOENT => RootKeyMissingSnafu { path }.into_error(errno.into()),
        // WHY: with O_NOFOLLOW, Linux reports a symbolic link in the final
        // component as ELOOP.
        rustix::io::Errno::LOOP => RootKeySymlinkSnafu { path }.into_error(errno.into()),
        // WHY: open(2) reports ENXIO for a Unix domain socket and for a
        // device node with no driver; neither is a regular file.
        rustix::io::Errno::NXIO => RootKeyNotFileSnafu { path }.build(),
        _ => RootKeyIoSnafu { path }.into_error(errno.into()),
    }
}

fn short_read_error(path: &Path, file: &File, error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        // WHY: the file shrank between fstat and read; report its length now.
        RootKeyLengthSnafu {
            path,
            found: current_len(file),
            expected: ROOT_KEY_LEN,
        }
        .build()
    } else {
        RootKeyIoSnafu { path }.into_error(error)
    }
}

/// The open file's current length, or 0 when `fstat` fails. Used only to
/// describe a length error that has already been detected.
fn current_len(file: &File) -> u64 {
    file.metadata().map_or(0, |meta| meta.len())
}

fn create_error(path: &Path, errno: rustix::io::Errno) -> Error {
    if errno == rustix::io::Errno::EXIST {
        RootKeyExistsSnafu { path }.build()
    } else {
        RootKeyIoSnafu { path }.into_error(errno.into())
    }
}

/// Sync the directory holding `path` so the new directory entry is durable.
fn sync_parent(path: &Path) -> Result<()> {
    let parent: PathBuf = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    File::open(&parent)
        .and_then(|dir| dir.sync_all())
        .context(RootKeyIoSnafu { path: parent })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::crypto::test_support::FailingEntropy;

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
}
