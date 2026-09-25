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

use crate::crypto::{Entropy, OsEntropy, random_secret_array};
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
        let drawn = random_secret_array::<ROOT_KEY_LEN>(entropy)?;
        let bytes =
            SecretBox::init_with_mut(|key: &mut [u8; ROOT_KEY_LEN]| key.copy_from_slice(&*drawn));
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
mod test_support;
#[cfg(test)]
mod tests;
