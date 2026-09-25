//! The operator-held root key file.
//!
//! The root key is 32 raw bytes in a file kept apart from the store
//! directory. Loading fails closed: a missing file, a file that is not a
//! regular file, any group or other permission bit, or any length other than
//! 32 bytes refuses the open. The key lives in a [`SecretBox`] that zeroes on
//! drop.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use snafu::{IntoError, ResultExt, ensure};
use zeroize::ZeroizeOnDrop;

use crate::crypto::{Entropy, OsEntropy};
use crate::error::{
    RootKeyExistsSnafu, RootKeyIoSnafu, RootKeyLengthSnafu, RootKeyMissingSnafu,
    RootKeyNotFileSnafu, RootKeyPermissionsSnafu,
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
    /// - [`Error::RootKeyNotFile`] when the path is not a regular file.
    /// - [`Error::RootKeyPermissions`] when any group or other bit is set.
    /// - [`Error::RootKeyLength`] when the file is not exactly 32 bytes.
    /// - [`Error::RootKeyIo`] for any other I/O failure.
    pub fn load(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(|source| open_error(path, source))?;
        // WHY: metadata comes from the open descriptor (fstat), not a second
        // path lookup, so the checks apply to the file actually read.
        let meta = file.metadata().context(RootKeyIoSnafu { path })?;
        ensure!(meta.is_file(), RootKeyNotFileSnafu { path });
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
            .map_err(|source| short_read_error(path, source))?;
        // WHY: the length check above used metadata; a file that grew between
        // fstat and read is rejected rather than truncated to 32 bytes.
        let mut probe = [0_u8; 1];
        let extra = file.read(&mut probe).context(RootKeyIoSnafu { path })?;
        ensure!(
            extra == 0,
            RootKeyLengthSnafu {
                path,
                found: 33_u64,
                expected: ROOT_KEY_LEN,
            }
        );
        Ok(Self { bytes })
    }

    /// Generate a new root key from the operating system random source and
    /// write it to `path` with mode 0600.
    ///
    /// The file is created with `O_CREAT | O_EXCL` and its mode set at
    /// creation, so no window exists where it is readable by group or other,
    /// and an existing file is never overwritten.
    ///
    /// # Errors
    ///
    /// - [`Error::Entropy`] when the random source fails; no file is created.
    /// - [`Error::RootKeyExists`] when `path` already exists.
    /// - [`Error::RootKeyIo`] when creating, writing, or syncing fails.
    pub fn generate(path: &Path) -> Result<Self> {
        Self::generate_with(path, &mut OsEntropy)
    }

    pub(crate) fn generate_with(path: &Path, entropy: &mut impl Entropy) -> Result<Self> {
        let mut bytes = SecretBox::new(Box::new([0_u8; ROOT_KEY_LEN]));
        entropy.fill(bytes.expose_secret_mut())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(NEW_KEY_MODE)
            .open(path)
            .map_err(|source| create_error(path, source))?;
        let written = file
            .write_all(bytes.expose_secret())
            .and_then(|()| file.sync_all());
        if let Err(source) = written {
            // NOTE: best-effort cleanup of a partial file; the write error is
            // what the caller needs, and a leftover short file is refused by
            // `load` on length anyway.
            drop(std::fs::remove_file(path));
            return Err(source).context(RootKeyIoSnafu { path });
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

fn open_error(path: &Path, source: io::Error) -> Error {
    if source.kind() == io::ErrorKind::NotFound {
        RootKeyMissingSnafu { path }.into_error(source)
    } else {
        RootKeyIoSnafu { path }.into_error(source)
    }
}

fn short_read_error(path: &Path, source: io::Error) -> Error {
    if source.kind() == io::ErrorKind::UnexpectedEof {
        // WHY: the file shrank between fstat and read.
        RootKeyLengthSnafu {
            path,
            found: 0_u64,
            expected: ROOT_KEY_LEN,
        }
        .build()
    } else {
        RootKeyIoSnafu { path }.into_error(source)
    }
}

fn create_error(path: &Path, source: io::Error) -> Error {
    if source.kind() == io::ErrorKind::AlreadyExists {
        RootKeyExistsSnafu { path }.build()
    } else {
        RootKeyIoSnafu { path }.into_error(source)
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
    fn generate_writes_owner_only_key_that_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("root.key");
        let generated = RootKey::generate(&path).expect("generate");
        let meta = fs::metadata(&path).expect("stat");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "created 0600");
        assert_eq!(meta.len(), 32, "32 raw bytes");
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
