//! Binding the listening socket safely.
//!
//! The socket lives in a directory the daemon owns with mode 0700. Because
//! no other user can traverse that directory, the socket is unreachable to
//! them from the moment `bind` creates it, and it is restricted to mode
//! 0600 before the first accept. Changing the process umask instead would
//! race other threads, so the directory carries the guarantee.
//!
//! Before touching the socket path, the daemon takes an exclusive advisory
//! lock on the directory and holds it until it stops serving. One daemon
//! serves per socket directory. A second daemon started at the same instant
//! finds the lock held and refuses startup, so it can never judge the first
//! daemon's fresh socket stale and unlink it between the probe and the
//! removal.
//!
//! An existing path is replaced only when it is provably a stale socket: a
//! socket file owned by the directory's owner that refuses connections.
//! Anything else (a regular file, a symlink, a socket owned by someone
//! else, a socket with a live listener) refuses startup.
//!
//! NOTE: the directory's owner is compared with the daemon's own uid only
//! after `bind` (through the fresh socket's owner). Until then, only that
//! owner can change the directory's entries, so the checks before it race
//! nobody but the directory's owner.

use std::fs::{self, DirBuilder, File, Permissions, TryLockError};
use std::io;
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use snafu::{OptionExt as _, ResultExt as _, ensure};
use tracing::info;

use crate::error::{
    BindSnafu, Error, InsecureSocketDirSnafu, InspectSocketSnafu, NoSocketParentSnafu,
    SocketDirSnafu, SocketInUseSnafu, SocketPathOccupiedSnafu,
};

/// Mode of the socket's parent directory when the daemon creates it.
const DIR_MODE: u32 = 0o700;
/// Mode of the socket file.
const SOCKET_MODE: u32 = 0o600;
/// Permission bits that must be clear on the parent directory.
const GROUP_OTHER_BITS: u32 = 0o077;

/// A bound listener and the directory lock that must outlive it.
#[derive(Debug)]
pub(super) struct Bound {
    /// The non-blocking listener.
    pub(super) listener: UnixListener,
    /// The held directory lock; dropping it releases the lock.
    pub(super) lock: File,
}

/// Binds a non-blocking listener at `path` (see the module docs for the
/// checks).
pub(super) fn bind(path: &Path) -> Result<Bound, Error> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context(NoSocketParentSnafu { path })?;
    let dir_meta = prepare_dir(dir)?;
    let lock = lock_dir(dir, &dir_meta, path)?;
    clear_stale(path, dir_meta.uid())?;
    let listener = UnixListener::bind(path).context(BindSnafu { path })?;
    if let Err(error) = restrict(path, &listener, dir, &dir_meta) {
        // WHY best effort: the bind failed its checks; leave no socket
        // behind for a later start to judge.
        let _removed = fs::remove_file(path);
        return Err(error);
    }
    info!("socket bound");
    Ok(Bound { listener, lock })
}

/// Opens the checked directory and takes an exclusive lock on it without
/// waiting. A lock held by another daemon is [`Error::SocketInUse`].
fn lock_dir(dir: &Path, dir_meta: &fs::Metadata, path: &Path) -> Result<File, Error> {
    let handle = File::open(dir).context(SocketDirSnafu { path: dir })?;
    let opened = handle.metadata().context(SocketDirSnafu { path: dir })?;
    // WHY compare device and inode: the path was checked, the handle is
    // what gets locked; they must be the same directory.
    ensure!(
        opened.is_dir() && opened.dev() == dir_meta.dev() && opened.ino() == dir_meta.ino(),
        InsecureSocketDirSnafu {
            path: dir,
            mode: opened.mode(),
            owner: opened.uid(),
        }
    );
    match handle.try_lock() {
        Ok(()) => Ok(handle),
        Err(TryLockError::WouldBlock) => SocketInUseSnafu { path }.fail(),
        Err(TryLockError::Error(error)) => Err(error).context(SocketDirSnafu { path: dir }),
    }
}

/// Creates the parent directory with mode 0700 when missing, then checks
/// it is a real directory with no group or other bits. Returns its
/// metadata.
fn prepare_dir(dir: &Path) -> Result<fs::Metadata, Error> {
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => DirBuilder::new()
            .mode(DIR_MODE)
            .create(dir)
            .context(SocketDirSnafu { path: dir })?,
        Err(error) => return Err(error).context(SocketDirSnafu { path: dir }),
        Ok(_) => {}
    }
    let meta = fs::symlink_metadata(dir).context(SocketDirSnafu { path: dir })?;
    ensure!(
        meta.file_type().is_dir() && meta.mode() & GROUP_OTHER_BITS == 0,
        InsecureSocketDirSnafu {
            path: dir,
            mode: meta.mode(),
            owner: meta.uid(),
        }
    );
    Ok(meta)
}

/// Removes a provably stale socket at `path`; refuses anything else.
fn clear_stale(path: &Path, dir_owner: u32) -> Result<(), Error> {
    let meta = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context(InspectSocketSnafu { path }),
        Ok(meta) => meta,
    };
    ensure!(
        meta.file_type().is_socket() && meta.uid() == dir_owner,
        SocketPathOccupiedSnafu { path }
    );
    match UnixStream::connect(path) {
        Ok(_live) => SocketInUseSnafu { path }.fail(),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            info!("removing stale socket");
            fs::remove_file(path).context(InspectSocketSnafu { path })
        }
        Err(error) => Err(error).context(InspectSocketSnafu { path }),
    }
}

/// Sets mode 0600, proves the daemon owns the directory (the fresh socket
/// is owned by the daemon's effective uid), and makes the listener
/// non-blocking.
fn restrict(
    path: &Path,
    listener: &UnixListener,
    dir: &Path,
    dir_meta: &fs::Metadata,
) -> Result<(), Error> {
    fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE)).context(BindSnafu { path })?;
    let meta = fs::symlink_metadata(path).context(BindSnafu { path })?;
    ensure!(
        meta.uid() == dir_meta.uid(),
        InsecureSocketDirSnafu {
            path: dir,
            mode: dir_meta.mode(),
            owner: dir_meta.uid(),
        }
    );
    listener.set_nonblocking(true).context(BindSnafu { path })
}
