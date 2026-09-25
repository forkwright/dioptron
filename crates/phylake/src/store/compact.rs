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
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fjall::{PersistMode, Readable as _};
use rustix::fs::{CWD, RenameFlags};
use snafu::{OptionExt as _, ResultExt as _};

use super::{ALL_KEYSPACES, Keyspaces, Store, open_database, prepare_empty_dir};
use crate::Result;
use crate::error::{DatabaseSnafu, StoreIoSnafu, StorePathUnnamedSnafu};

/// Entries copied per transaction.
const COPY_BATCH: usize = 1024;

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
    /// component, [`crate::Error::StoreIo`] when the copy directory, the
    /// exchange, or the removal fails (the kernel and filesystem must
    /// support `RENAME_EXCHANGE`), or [`crate::Error::Database`]. On an
    /// error the store path still holds a complete store; reopen it.
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
        exchange(&path, &staging)?;
        remove_leftover(&path)?;
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

/// Atomically exchanges the directories at `path` and `staging`.
fn exchange(path: &Path, staging: &Path) -> Result<()> {
    rustix::fs::renameat_with(CWD, path, CWD, staging, RenameFlags::EXCHANGE)
        .map_err(std::io::Error::from)
        .context(StoreIoSnafu { path })?;
    sync_parent(path)
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
