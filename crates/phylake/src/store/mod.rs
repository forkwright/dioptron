//! The custody store (`docs/design/custody-store.md`).
//!
//! One fjall single-writer transactional database holds the fifteen
//! keyspaces of the design. Every transaction commits with
//! `PersistMode::SyncAll`, and every value outside `meta` is sealed with
//! [`crate::crypto::seal`], binding it to its schema version, record kind,
//! key id, keyspace, and record key.
//!
//! Two sealing scopes exist:
//!
//! - store-sealed (root-derived keys): tenants, grants, revocations,
//!   sessions, invocations, ledgers, artifact locators, and audit stubs.
//!   Authorization walks grant chains across tenants and recovery scans
//!   every invocation, so these must open without knowing a tenant first.
//!   They carry identifiers and amounts, not acquired content.
//! - tenant-sealed (the tenant's data key): blobs, artifact side records,
//!   session index entries, idempotency entries, and audit entries. Their
//!   record keys hash the tenant id in, which is what binds them to the
//!   tenant.
//!
//! The store exposes typed operations and makes no authorization decision
//! for reads: the caller (the daemon's lifecycle) authorizes, then reads.
//! Missing records read as `None`, never as a distinct error, so a read
//! cannot distinguish absence from a record the caller may not see.

mod audit;
mod codec;
mod directory;
mod failpoint;
mod invocation;
mod meta;
mod read;
mod record_key;
mod records;
mod recovery;
mod transition;
mod view;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use epitrope::Clock;
use fjall::{
    KeyspaceCreateOptions, PersistMode, Readable, SingleWriterTxDatabase, SingleWriterTxKeyspace,
    SingleWriterWriteTx,
};
use snafu::{OptionExt as _, ResultExt as _, ensure};
use syntheke::TenantId;
use zeroize::Zeroize as _;

use self::codec::StoredRecord;
use self::records::TenantRecord;
use crate::Result;
use crate::crypto::{
    Entropy, KeyId, Keyspace, OsEntropy, RecordKind, SealContext, SealingKey, StoreKeys, StoreSalt,
    TenantKeys, open, seal_with,
};
use crate::error::{
    DatabaseSnafu, InconsistentSnafu, InjectedCrashSnafu, StoreExistsSnafu, StoreIoSnafu,
    StoreMissingSnafu, TenantMissingSnafu,
};
use crate::keyfile::RootKey;

pub use self::audit::AuditEntry;
pub use self::directory::{
    GrantIssue, IssueOutcome, NewSession, RevokeGrant, RootGrant, TenantRegistration,
};
pub use self::failpoint::{Boundary, Crash, Failpoint, NoFailpoints, Phase};
pub use self::invocation::{Begin, Intent, InvocationStatus, SettleOutcome, Transfer};
pub use self::meta::SCHEMA_VERSION;
pub use self::read::ArtifactInfo;
pub use self::recovery::RecoveryReport;
pub use self::view::{StoreSnapshot, TenantDirectory, TenantEntry};

/// The id of the root key a new store is created under.
const INITIAL_ROOT_KEY_ID: KeyId = KeyId::new(1);

/// The id of a tenant's first data key.
const INITIAL_DATA_KEY_ID: KeyId = KeyId::new(1);

/// The file fjall 3 writes last when it creates a database (verified in
/// the fjall 3.1 source, `file::VERSION_MARKER`). Its presence is what
/// separates an existing database from a directory fjall would initialize.
const FJALL_VERSION_MARKER: &str = "version";

/// Every keyspace, in the order of the design's table.
const ALL_KEYSPACES: [Keyspace; 15] = [
    Keyspace::Meta,
    Keyspace::Keys,
    Keyspace::Tenants,
    Keyspace::Grants,
    Keyspace::Revocations,
    Keyspace::Sessions,
    Keyspace::Invocations,
    Keyspace::Idem,
    Keyspace::Ledgers,
    Keyspace::Artifacts,
    Keyspace::Blobs,
    Keyspace::SessionIndex,
    Keyspace::Audit,
    Keyspace::AuditStub,
    Keyspace::Rekey,
];

/// A write transaction on the store.
type WriteTx<'a> = SingleWriterWriteTx<'a>;

/// Where a record lives: its keyspace and record kind.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Slot {
    keyspace: Keyspace,
    kind: RecordKind,
}

/// The record slots.
pub(crate) mod slot {
    use super::Slot;
    use super::records::kind;
    use crate::crypto::Keyspace;

    macro_rules! slots {
        ($($name:ident => $keyspace:ident, $kind:ident;)+) => {
            $(pub(crate) const $name: Slot = Slot {
                keyspace: Keyspace::$keyspace,
                kind: kind::$kind,
            };)+
        };
    }

    slots! {
        TENANT => Tenants, TENANT;
        GRANT => Grants, GRANT;
        REVOCATION => Revocations, REVOCATION;
        SESSION => Sessions, SESSION;
        INVOCATION => Invocations, INVOCATION;
        IDEM => Idem, IDEM;
        LEDGER => Ledgers, LEDGER;
        ARTIFACT => Artifacts, ARTIFACT;
        PENDING_ARTIFACT => Artifacts, PENDING_ARTIFACT;
        LOCATOR => Artifacts, LOCATOR;
        BLOB => Blobs, BLOB;
        SESSION_INDEX => SessionIndex, SESSION_INDEX;
        AUDIT => Audit, AUDIT;
        AUDIT_STUB => AuditStub, AUDIT_STUB;
    }
}

/// Handles to every keyspace.
struct Keyspaces {
    handles: Vec<(Keyspace, SingleWriterTxKeyspace)>,
}

impl Keyspaces {
    /// Opens (creating when absent) every keyspace.
    fn open(db: &SingleWriterTxDatabase) -> Result<Self> {
        let handles = ALL_KEYSPACES
            .iter()
            .map(|&keyspace| {
                db.keyspace(keyspace.name(), KeyspaceCreateOptions::default)
                    .map(|handle| (keyspace, handle))
                    .context(DatabaseSnafu)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { handles })
    }

    /// The handle of `keyspace`.
    fn get(&self, keyspace: Keyspace) -> Result<&SingleWriterTxKeyspace> {
        self.handles
            .iter()
            .find_map(|(name, handle)| (*name == keyspace).then_some(handle))
            .context(InconsistentSnafu {
                what: "keyspace handle not opened",
            })
    }
}

/// How to open or create a store.
pub struct StoreOptions {
    path: PathBuf,
    clock: Arc<dyn Clock + Send + Sync>,
    failpoint: Arc<dyn Failpoint>,
    entropy: Box<dyn Entropy + Send>,
}

impl fmt::Debug for StoreOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreOptions")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl StoreOptions {
    /// Options for the store at `path`, reading time from `clock`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, clock: Arc<dyn Clock + Send + Sync>) -> Self {
        Self {
            path: path.into(),
            clock,
            failpoint: Arc::new(NoFailpoints),
            entropy: Box::new(OsEntropy),
        }
    }

    /// Installs a failpoint implementation (tests and the daemon's
    /// failpoints build).
    #[must_use]
    pub fn failpoint(mut self, failpoint: Arc<dyn Failpoint>) -> Self {
        self.failpoint = failpoint;
        self
    }

    /// Replaces the random source, so tests are reproducible.
    #[cfg(test)]
    pub(crate) fn entropy(mut self, entropy: Box<dyn Entropy + Send>) -> Self {
        self.entropy = entropy;
        self
    }

    /// Creates a new store under `root`.
    ///
    /// The path must be absent or an empty directory; it is created with
    /// mode 0700 when absent. The store gets a fresh key-derivation salt,
    /// root key id 1, and schema version [`SCHEMA_VERSION`].
    ///
    /// # Errors
    ///
    /// [`crate::Error::StoreExists`] for a non-empty path,
    /// [`crate::Error::StoreIo`] or [`crate::Error::Database`] when the
    /// filesystem or database fails, [`crate::Error::Entropy`] when the
    /// salt cannot be drawn.
    pub fn create(mut self, root: &RootKey) -> Result<Store> {
        prepare_empty_dir(&self.path)?;
        let salt = StoreSalt::generate_with(&mut self.entropy)?;
        let keys = StoreKeys::derive(root, INITIAL_ROOT_KEY_ID, &salt)?;
        let check = keys.key_check()?;
        let db = open_database(&self.path)?;
        let ks = Keyspaces::open(&db)?;
        let store = self.into_store(db, ks, keys);
        let mut tx = store.write_tx();
        meta::write(
            &mut tx,
            store.ks.get(Keyspace::Meta)?,
            &meta::Meta::new(INITIAL_ROOT_KEY_ID, salt, *check.as_bytes()),
        );
        store.commit(tx, None)?;
        Ok(store)
    }

    /// Opens the existing store at `path` under `root`.
    ///
    /// Opening reads the plaintext `meta` fields, refuses an unsupported
    /// schema version, and checks the key before any keyspace is created
    /// or written. Any failure leaves the store as it was.
    ///
    /// # Errors
    ///
    /// [`crate::Error::StoreMissing`] when no complete store exists at the
    /// path, [`crate::Error::MetaMalformed`] for unreadable metadata,
    /// [`crate::Error::SchemaTooNew`] and
    /// [`crate::Error::MigrationRequired`] for a schema version this build
    /// does not open, [`crate::Error::StoreLocked`] for the wrong root key,
    /// [`crate::Error::Database`] when the database fails.
    pub fn open(self, root: &RootKey) -> Result<Store> {
        let marker = self.path.join(FJALL_VERSION_MARKER);
        let exists = marker.try_exists().context(StoreIoSnafu {
            path: self.path.clone(),
        })?;
        ensure!(
            exists,
            StoreMissingSnafu {
                path: &self.path,
                missing: "database",
            }
        );
        let db = open_database(&self.path)?;
        if let Some(missing) = ALL_KEYSPACES
            .iter()
            .find(|keyspace| !db.keyspace_exists(keyspace.name()))
        {
            return StoreMissingSnafu {
                path: &self.path,
                missing: missing.name(),
            }
            .fail();
        }
        let ks = Keyspaces::open(&db)?;
        let stored = meta::read(&db.read_tx(), ks.get(Keyspace::Meta)?, &self.path)?;
        let keys = StoreKeys::unlock(root, stored.root_key_id(), stored.salt(), stored.check())?;
        Ok(self.into_store(db, ks, keys))
    }

    fn into_store(self, db: SingleWriterTxDatabase, ks: Keyspaces, keys: StoreKeys) -> Store {
        Store {
            path: self.path,
            db,
            ks,
            keys,
            clock: self.clock,
            failpoint: self.failpoint,
            entropy: Mutex::new(self.entropy),
            tenant_keys: Mutex::new(HashMap::new()),
        }
    }
}

/// Creates `path` (mode 0700) or checks that it is an empty directory.
fn prepare_empty_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    match std::fs::read_dir(path) {
        Ok(mut entries) => {
            ensure!(
                entries.next().is_none(),
                StoreExistsSnafu {
                    path: path.to_path_buf()
                }
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .context(StoreIoSnafu {
                path: path.to_path_buf(),
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => StoreExistsSnafu {
            path: path.to_path_buf(),
        }
        .fail(),
        Err(error) => Err(error).context(StoreIoSnafu {
            path: path.to_path_buf(),
        }),
    }
}

/// Opens the fjall database at `path`.
fn open_database(path: &Path) -> Result<SingleWriterTxDatabase> {
    SingleWriterTxDatabase::builder(path)
        .open()
        .context(DatabaseSnafu)
}

impl Entropy for Box<dyn Entropy + Send> {
    fn fill<'a>(&mut self, dest: &'a mut [MaybeUninit<u8>]) -> Result<&'a mut [u8]> {
        (**self).fill(dest)
    }
}

/// The custody store. `Send` and `Sync`: writers serialize on the
/// database's single-writer lock, readers use snapshots.
pub struct Store {
    path: PathBuf,
    db: SingleWriterTxDatabase,
    ks: Keyspaces,
    keys: StoreKeys,
    clock: Arc<dyn Clock + Send + Sync>,
    failpoint: Arc<dyn Failpoint>,
    entropy: Mutex<Box<dyn Entropy + Send>>,
    tenant_keys: Mutex<HashMap<TenantId, Arc<TenantKeys>>>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// The store directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A consistent read-only view of the store at this moment.
    #[must_use]
    pub fn snapshot(&self) -> StoreSnapshot<'_> {
        StoreSnapshot::new(self, self.db.read_tx())
    }

    /// Starts a write transaction that commits with `SyncAll`.
    ///
    /// WARNING: fjall's `write_tx` panics if its writer lock is poisoned,
    /// which only a panic inside another write transaction causes. No code
    /// path in this crate panics while holding it.
    fn write_tx(&self) -> WriteTx<'_> {
        self.db.write_tx().durability(Some(PersistMode::SyncAll))
    }

    /// Commits `tx`, running the failpoint hooks for `boundary`.
    fn commit(&self, tx: WriteTx<'_>, boundary: Option<Boundary>) -> Result<()> {
        if let Some(boundary) = boundary
            && self.failpoint.before_commit(boundary).is_err()
        {
            return InjectedCrashSnafu {
                boundary,
                phase: Phase::BeforeCommit,
            }
            .fail();
        }
        tx.commit().context(DatabaseSnafu)?;
        if let Some(boundary) = boundary
            && self.failpoint.after_commit(boundary).is_err()
        {
            return InjectedCrashSnafu {
                boundary,
                phase: Phase::AfterCommit,
            }
            .fail();
        }
        Ok(())
    }

    /// Seals raw bytes for `slot` at `record_key`.
    fn seal_bytes(
        &self,
        key: &SealingKey,
        slot: Slot,
        record_key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let ctx = SealContext::new(SCHEMA_VERSION, slot.keyspace, slot.kind, record_key);
        let mut entropy = self.entropy.lock().unwrap_or_else(PoisonError::into_inner);
        seal_with(key, &ctx, plaintext, &mut *entropy)
    }

    /// Opens raw bytes read from `slot` at `record_key`.
    fn open_bytes(
        keys: &[&SealingKey],
        slot: Slot,
        record_key: &[u8],
        sealed: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let ctx = SealContext::new(SCHEMA_VERSION, slot.keyspace, slot.kind, record_key);
        open(keys, &ctx, sealed)
    }

    /// Reads and opens the record at `record_key` in `slot`.
    fn get<T: StoredRecord, R: Readable>(
        &self,
        reader: &R,
        slot: Slot,
        record_key: &[u8],
        keys: &[&SealingKey],
    ) -> Result<Option<T>> {
        let handle = self.ks.get(slot.keyspace)?;
        let Some(sealed) = reader.get(handle, record_key).context(DatabaseSnafu)? else {
            return Ok(None);
        };
        let plain = Self::open_bytes(keys, slot, record_key, &sealed)?;
        T::decode(&plain, slot.keyspace.name()).map(Some)
    }

    /// Seals `value` and stages it at `record_key` in `slot`.
    fn put<T: StoredRecord>(
        &self,
        tx: &mut WriteTx<'_>,
        slot: Slot,
        record_key: &[u8],
        key: &SealingKey,
        value: &T,
    ) -> Result<()> {
        let mut encoded = value.encode()?;
        let sealed = self.seal_bytes(key, slot, record_key, &encoded);
        let plain: &mut [u8] = &mut encoded;
        plain.zeroize();
        tx.insert(self.ks.get(slot.keyspace)?, record_key, sealed?);
        Ok(())
    }

    /// Reads a store-sealed record.
    fn get_global<T: StoredRecord, R: Readable>(
        &self,
        reader: &R,
        slot: Slot,
        record_key: &[u8],
    ) -> Result<Option<T>> {
        self.get(reader, slot, record_key, &[self.keys.meta()])
    }

    /// Stages a store-sealed record.
    fn put_global<T: StoredRecord>(
        &self,
        tx: &mut WriteTx<'_>,
        slot: Slot,
        record_key: &[u8],
        value: &T,
    ) -> Result<()> {
        self.put(tx, slot, record_key, self.keys.meta(), value)
    }

    /// The tenant record of `tenant`, read through `reader`.
    fn tenant_record<R: Readable>(
        &self,
        reader: &R,
        tenant: TenantId,
    ) -> Result<Option<TenantRecord>> {
        let key = record_key::store::tenant(self.keys.index(), tenant)?;
        self.get_global(reader, slot::TENANT, &key)
    }

    /// The derived keys of `tenant`, unwrapping its data key on first use.
    ///
    /// NOTE: keys are cached only after they are read from a committed
    /// record, so a rolled-back registration never leaves a cached key.
    /// Tenant data-key rotation and crypto-shredding must evict the entry
    /// in the transaction that retires the key.
    fn tenant_keys<R: Readable>(&self, reader: &R, tenant: TenantId) -> Result<Arc<TenantKeys>> {
        let cached = self
            .tenant_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&tenant)
            .cloned();
        if let Some(keys) = cached {
            return Ok(keys);
        }
        let record = self
            .tenant_record(reader, tenant)?
            .context(TenantMissingSnafu { tenant })?;
        let key_id = KeyId::new(record.data_key_id);
        let slot_key = record_key::store::data_key(self.keys.index(), tenant, key_id)?;
        let wrapped = reader
            .get(self.ks.get(Keyspace::Keys)?, slot_key)
            .context(DatabaseSnafu)?
            .context(InconsistentSnafu {
                what: "tenant data key is missing",
            })?;
        let derived = Arc::new(
            self.keys
                .unwrap_tenant_key(&tenant.to_bytes(), &wrapped)?
                .derive()?,
        );
        self.tenant_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tenant, Arc::clone(&derived));
        Ok(derived)
    }

    /// Now, from the injected clock.
    fn now(&self) -> syntheke::Timestamp {
        self.clock.now()
    }
}
