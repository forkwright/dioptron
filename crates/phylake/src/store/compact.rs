//! Compaction by rewrite: the step that completes a crypto-shred
//! (`docs/design/custody-store.md`, "Crypto-shredding").
//!
//! WHY a rewrite and not fjall's compaction: fjall 3.1 removes a deleted
//! value from its table files on major compaction
//! (`Keyspace::major_compact`, which fjall marks `#[doc(hidden)]`), but the
//! value also sits in the write-ahead journal, and fjall seals and deletes
//! a journal only once it has grown past 64 MB (`worker_pool.rs`, checked
//! against the 3.1.10 source); no public call rotates it. A deleted
//! wrapped key therefore stays on disk after flush, major compaction, and
//! reopen. Copying the live entries into a fresh database and swapping the
//! directories leaves no file that ever held a deleted value.
//!
//! The swap is one `renameat2(RENAME_EXCHANGE)` of the store directory and
//! a sibling staging directory, `<store>.compact`, so the store path holds
//! a complete store at every instant: before the exchange the original,
//! after it the copy. The staging directory then holds either an
//! incomplete copy or the old store; either is removed, here or by the
//! next [`crate::StoreOptions::open`], and the name is reserved.
//!
//! NOTE: removal unlinks files; it does not overwrite the storage blocks
//! they used. Erasure below the filesystem is out of scope for Phase 01.

use std::collections::HashMap;
use std::fs::TryLockError;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use fjall::{PersistMode, Readable as _};
use rustix::fs::{CWD, RenameFlags};
use rustix::io::Errno;
use snafu::{IntoError as _, OptionExt as _, ResultExt as _};

use super::{ALL_KEYSPACES, Keyspaces, Store, open_database, prepare_empty_dir};
use crate::Result;
use crate::error::{
    DatabaseSnafu, ExchangeUnsupportedSnafu, StoreInUseSnafu, StoreIoSnafu, StorePathUnnamedSnafu,
};

/// Entries copied per transaction.
const COPY_BATCH: usize = 1024;

/// The lock file fjall 3 keeps in a database directory and holds an
/// advisory lock on while the database is open (verified in the fjall
/// 3.1 source, `file::LOCK_FILE`).
const FJALL_LOCK_FILE: &str = "lock";

/// Attempts to take a closed database's lock, as fjall's open makes.
const LOCK_ATTEMPTS: u32 = 3;

/// The wait between lock attempts.
const LOCK_RETRY: Duration = Duration::from_millis(100);

impl Store {
    /// Rewrites the store into a fresh database and swaps it in, so no
    /// file keeps a value that was deleted or overwritten: a shredded
    /// tenant's wrapped keys, retired data keys, and values sealed under a
    /// rotated-out root key. Returns the store reopened on the rewritten
    /// database.
    ///
    /// The store must not be shared while this runs: it takes the handle
    /// by value and closes the database before the swap.
    ///
    /// # Errors
    ///
    /// [`crate::Error::StorePathUnnamed`] for a path with no final
    /// component, [`crate::Error::ExchangeUnsupported`] when the kernel or
    /// filesystem has no `RENAME_EXCHANGE`, [`crate::Error::StoreInUse`]
    /// when another process opened either directory before the swap,
    /// [`crate::Error::StoreIo`] when the copy directory, the exchange, or
    /// the removal fails, or [`crate::Error::Database`]. On an error the
    /// store path still holds a complete store; reopen it.
    pub fn compact(self) -> Result<Self> {
        let staging = staging_path(&self.path)?;
        remove_leftover(&self.path)?;
        prepare_empty_dir(&staging)?;
        self.copy_into(&staging)?;
        let Self {
            path,
            db,
            ks,
            keys,
            clock,
            failpoint,
            entropy,
            tenant_keys: _,
        } = self;
        drop(ks);
        drop(db);
        swap_in(&path, &staging)?;
        let db = open_database(&path)?;
        let ks = Keyspaces::open(&db)?;
        Ok(Self {
            path,
            db,
            ks,
            keys,
            clock,
            failpoint,
            entropy,
            tenant_keys: Mutex::new(HashMap::new()),
        })
    }

    /// Copies every live entry of every keyspace into a new database at
    /// `dest`, durably.
    fn copy_into(&self, dest: &Path) -> Result<()> {
        let target = open_database(dest)?;
        let target_ks = Keyspaces::open(&target)?;
        let snapshot = self.db.read_tx();
        for &keyspace in &ALL_KEYSPACES {
            let to = target_ks.get(keyspace)?;
            let mut chunk = Vec::with_capacity(COPY_BATCH);
            let mut entries = snapshot.iter(self.ks.get(keyspace)?).peekable();
            while let Some(guard) = entries.next() {
                chunk.push(guard.into_inner().context(DatabaseSnafu)?);
                if chunk.len() == COPY_BATCH || entries.peek().is_none() {
                    let mut tx = target.write_tx().durability(Some(PersistMode::SyncAll));
                    for (key, value) in chunk.drain(..) {
                        tx.insert(to, key, value);
                    }
                    tx.commit().context(DatabaseSnafu)?;
                }
            }
        }
        target.persist(PersistMode::SyncAll).context(DatabaseSnafu)
    }
}

/// The staging directory beside the store at `path`.
pub(super) fn staging_path(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().context(StorePathUnnamedSnafu { path })?;
    let mut staging = name.to_os_string();
    staging.push(".compact");
    Ok(path.with_file_name(staging))
}

/// Removes the staging directory beside the store at `path`, if one is
/// left: an incomplete copy or a store a compaction replaced.
pub(super) fn remove_leftover(path: &Path) -> Result<()> {
    let staging = staging_path(path)?;
    match std::fs::remove_dir_all(&staging) {
        Ok(()) => sync_parent(&staging),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context(StoreIoSnafu { path: staging }),
    }
}

/// Swaps the copy at `staging` in for the store at `path` and removes the
/// replaced store.
///
/// Both databases are closed, so their fjall lock files are free. This
/// takes both locks before the exchange and holds them until the replaced
/// store is removed: another process that opened either directory in the
/// meantime makes the swap fail with [`crate::Error::StoreInUse`] rather
/// than have its open database renamed away and deleted, and no open
/// removes the staging directory while the swap still uses it. The locks
/// follow the directories through the exchange.
pub(super) fn swap_in(path: &Path, staging: &Path) -> Result<()> {
    let store_lock = lock_database(path)?;
    let staging_lock = lock_database(staging)?;
    exchange(path, staging)?;
    remove_leftover(path)?;
    drop((store_lock, staging_lock));
    Ok(())
}

/// Takes the fjall lock of the closed database at `dir`, the same
/// advisory file lock fjall takes at open.
fn lock_database(dir: &Path) -> Result<std::fs::File> {
    let lock_path = dir.join(FJALL_LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .context(StoreIoSnafu { path: &lock_path })?;
    for attempt in 1..=LOCK_ATTEMPTS {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if attempt < LOCK_ATTEMPTS => {
                // WHY: fjall releases its lock when the last handle of the
                // closed database drops; allow it the retry fjall's own
                // open allows.
                std::thread::sleep(LOCK_RETRY);
            }
            Err(TryLockError::WouldBlock) => break,
            Err(TryLockError::Error(error)) => {
                return Err(error).context(StoreIoSnafu { path: lock_path });
            }
        }
    }
    StoreInUseSnafu { path: dir }.fail()
}

/// Atomically exchanges the directories at `path` and `staging`.
///
/// WARNING: there is no fallback. Two plain renames would leave an
/// instant with no store at `path`, so a filesystem without the exchange
/// fails the compaction with [`crate::Error::ExchangeUnsupported`].
fn exchange(path: &Path, staging: &Path) -> Result<()> {
    rustix::fs::renameat_with(CWD, path, CWD, staging, RenameFlags::EXCHANGE)
        .map_err(|errno| exchange_error(errno, path))?;
    sync_parent(path)
}

/// The error for a failed exchange: unsupported, or any other I/O failure.
pub(super) fn exchange_error(errno: Errno, path: &Path) -> crate::Error {
    if [Errno::INVAL, Errno::NOSYS, Errno::OPNOTSUPP].contains(&errno) {
        ExchangeUnsupportedSnafu { path }.build()
    } else {
        StoreIoSnafu { path }.into_error(std::io::Error::from(errno))
    }
}

/// Flushes the directory holding `path`, so a rename or removal in it is
/// durable.
fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .context(StoreIoSnafu { path: parent })
}
