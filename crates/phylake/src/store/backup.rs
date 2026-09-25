//! Backup and restore (`docs/design/custody-store.md`, "Backup and
//! restore").
//!
//! A backup is a copy of the store directory taken while no process has
//! the store open; the root key file is kept in separate custody and is
//! never part of the copy. Before a restored copy is used,
//! [`verify_restored`] checks it: every keyspace is present, the schema
//! version is one this build opens, and the presented root key matches
//! the stored key check. A copy that fails any check is refused rather
//! than opened.

use std::path::Path;

use super::{SCHEMA_VERSION, open_unlocked};
use crate::Result;
use crate::crypto::{KeyId, SchemaVersion};
use crate::keyfile::RootKey;

/// What [`verify_restored`] found in a restored store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RestoredStore {
    /// The store's schema version.
    pub schema_version: SchemaVersion,
    /// The id of the root key the store is sealed under.
    pub root_key_id: KeyId,
}

/// Checks the restored store at `path` against `root` and closes it again.
///
/// Opening the database runs its journal recovery, as any open does; no
/// store record is written.
///
/// # Errors
///
/// As [`crate::StoreOptions::open`]: [`crate::Error::StoreMissing`] for
/// an incomplete copy, [`crate::Error::SchemaTooNew`] or
/// [`crate::Error::MigrationRequired`] for a schema version this build
/// does not open, [`crate::Error::StoreLocked`] for a root key that does
/// not match.
pub fn verify_restored(path: &Path, root: &RootKey) -> Result<RestoredStore> {
    let (_db, _ks, keys) = open_unlocked(path, root)?;
    Ok(RestoredStore {
        schema_version: SCHEMA_VERSION,
        root_key_id: keys.root_key_id(),
    })
}
