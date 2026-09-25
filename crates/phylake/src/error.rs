//! The custody crate's error type.
//!
//! No variant carries key material, plaintext, or derived secrets: fields are
//! limited to paths, lengths, versions, key ids, and static labels, so an
//! error can be logged or displayed without leaking what it guards.

use std::io;
use std::path::PathBuf;

use snafu::Snafu;

use crate::crypto::KeyId;

/// Errors raised by `phylake`.
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    /// The root key file does not exist.
    #[snafu(display("root key file {} not found", path.display()))]
    RootKeyMissing {
        /// Path that was opened.
        path: PathBuf,
        /// Underlying I/O error (external, so named `error` per kanon RUST.md).
        #[snafu(source)]
        error: io::Error,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Reading, creating, or writing the root key file failed.
    #[snafu(display("root key file {}: I/O failure", path.display()))]
    RootKeyIo {
        /// Path that was accessed.
        path: PathBuf,
        /// Underlying I/O error (external, so named `error` per kanon RUST.md).
        #[snafu(source)]
        error: io::Error,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The root key path's final component is a symbolic link. The key file
    /// is opened with `O_NOFOLLOW`, so a link planted at the key path cannot
    /// redirect the load to another file.
    #[snafu(display("root key path {} is a symbolic link", path.display()))]
    RootKeySymlink {
        /// Path that was opened.
        path: PathBuf,
        /// Underlying I/O error (`ELOOP`).
        #[snafu(source)]
        error: io::Error,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The root key file is owned by a user other than the process's
    /// effective user.
    #[snafu(display(
        "root key file {} is owned by uid {owner}; expected the effective uid {euid}",
        path.display()
    ))]
    RootKeyOwner {
        /// Path that was opened.
        path: PathBuf,
        /// Owner uid of the file.
        owner: u32,
        /// Effective uid of this process.
        euid: u32,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The root key path names something other than a regular file.
    #[snafu(display("root key path {} is not a regular file", path.display()))]
    RootKeyNotFile {
        /// Path that was opened.
        path: PathBuf,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The root key file grants access to group or other.
    #[snafu(display(
        "root key file {} has mode {mode:o}; group and other bits must be clear",
        path.display()
    ))]
    RootKeyPermissions {
        /// Path that was opened.
        path: PathBuf,
        /// Permission bits found on the file.
        mode: u32,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The root key file is not exactly 32 bytes.
    #[snafu(display(
        "root key file {} holds {found} bytes; expected {expected}",
        path.display()
    ))]
    RootKeyLength {
        /// Path that was opened.
        path: PathBuf,
        /// Length found (a lower bound when the file grew during the read).
        found: u64,
        /// Required length.
        expected: usize,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Key generation refused to overwrite an existing file.
    #[snafu(display("root key file {} already exists", path.display()))]
    RootKeyExists {
        /// Path that was requested.
        path: PathBuf,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The operating system random source failed.
    #[snafu(display("operating system random source failed"))]
    Entropy {
        /// Underlying `getrandom` error (external, so named `error`).
        #[snafu(source)]
        error: getrandom::Error,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A key-derivation or cipher-initialisation primitive rejected its input.
    #[snafu(display("cannot initialise key material for {purpose}"))]
    KeyMaterial {
        /// Which primitive failed.
        purpose: &'static str,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A value to seal exceeds the per-record plaintext bound.
    #[snafu(display("plaintext of {len} bytes exceeds the {max}-byte sealing bound"))]
    PlaintextTooLarge {
        /// Plaintext length.
        len: usize,
        /// Bound.
        max: usize,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A length-prefixed additional-data component does not fit its prefix.
    #[snafu(display("{component} of {len} bytes does not fit a u16 length prefix"))]
    AadComponentTooLong {
        /// Which component overflowed.
        component: &'static str,
        /// Component length.
        len: usize,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A sealed value or wrapped key has an impossible length.
    #[snafu(display("{what} of {len} bytes is malformed"))]
    Malformed {
        /// Which encoding was being parsed.
        what: &'static str,
        /// Length found.
        len: usize,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A sealed value or wrapped key carries a record version this build does not read.
    #[snafu(display("unsupported record version {found}"))]
    UnsupportedRecordVersion {
        /// Version found in the header.
        found: u16,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// No presented key carries the key id named in the header.
    #[snafu(display("no key available for key id {found}"))]
    UnknownKeyId {
        /// Key id found in the header.
        found: KeyId,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A sealed value failed authentication: wrong key, wrong place, or tampered bytes.
    #[snafu(display("sealed value in keyspace {keyspace} failed authentication"))]
    Open {
        /// Keyspace the caller expected the value to belong to.
        keyspace: &'static str,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A wrapped tenant data key failed authentication.
    #[snafu(display("wrapped tenant data key failed authentication"))]
    TenantKeyUnwrap {
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The presented root key does not match the store's key-check value; the store stays locked.
    #[snafu(display("store is locked: root key does not match the stored key check"))]
    StoreLocked {
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The custody database failed a read, write, or commit.
    #[snafu(display("custody database operation failed"))]
    Database {
        /// Underlying storage error (external, so named `error`).
        #[snafu(source)]
        error: fjall::Error,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Creating or inspecting the store directory failed.
    #[snafu(display("store directory {}: I/O failure", path.display()))]
    StoreIo {
        /// Directory that was accessed.
        path: PathBuf,
        /// Underlying I/O error (external, so named `error`).
        #[snafu(source)]
        error: io::Error,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Creating a store at a path that is not an empty directory.
    #[snafu(display("store path {} is not an empty directory", path.display()))]
    StoreExists {
        /// Path that was requested.
        path: PathBuf,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Opening a store at a path that holds none, or holds an incomplete one.
    #[snafu(display("no custody store at {} ({missing} is absent)", path.display()))]
    StoreMissing {
        /// Path that was opened.
        path: PathBuf,
        /// The first part found missing.
        missing: &'static str,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A plaintext `meta` field has an impossible value.
    #[snafu(display("store metadata field {field} is malformed"))]
    MetaMalformed {
        /// The field.
        field: &'static str,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The store was written by a newer schema than this build reads. It
    /// is never opened optimistically.
    #[snafu(display("store schema version {found} is newer than supported version {supported}"))]
    SchemaTooNew {
        /// Version recorded in the store.
        found: u32,
        /// Version this build writes.
        supported: u32,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The store was written by an older schema and needs the `migrate`
    /// command before this build opens it.
    #[snafu(display("store schema version {found} requires migration to version {supported}"))]
    MigrationRequired {
        /// Version recorded in the store.
        found: u32,
        /// Version this build writes.
        supported: u32,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A record could not be encoded.
    #[snafu(display("record encoding failed"))]
    Encode {
        /// Underlying serializer error (external, so named `error`).
        #[snafu(source)]
        error: rkyv::rancor::Error,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// An opened record failed archive validation.
    #[snafu(display("record in keyspace {keyspace} failed validation"))]
    Decode {
        /// Keyspace the record was read from.
        keyspace: &'static str,
        /// Underlying validator error (external, so named `error`).
        #[snafu(source)]
        error: rkyv::rancor::Error,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Records that must agree do not: a reference points at nothing, or
    /// a stored key has an impossible shape.
    #[snafu(display("store records are inconsistent: {what}"))]
    Inconsistent {
        /// What was found wrong.
        what: &'static str,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// An authorization decision or ledger computation failed, including a
    /// lifecycle step the transition table forbids.
    #[snafu(display("authorization rule refused the operation"))]
    Authz {
        /// The authorization crate's error.
        #[snafu(source(from(epitrope::Error, Box::new)))]
        source: Box<epitrope::Error>,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A settlement named an outcome that does not fit the invocation's
    /// state: success before publish, or a failure after it.
    #[snafu(display("settlement outcome does not fit invocation state {state}"))]
    SettleMismatch {
        /// The invocation's state.
        state: syntheke::InvocationState,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The named invocation has no record.
    #[snafu(display("invocation {invocation} has no record"))]
    InvocationMissing {
        /// The invocation.
        invocation: syntheke::InvocationId,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The named tenant is not registered.
    #[snafu(display("tenant {tenant} is not registered"))]
    TenantMissing {
        /// The tenant.
        tenant: syntheke::TenantId,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The tenant was crypto-shredded: its data keys are gone and its id
    /// stays reserved.
    #[snafu(display("tenant {tenant} is shredded"))]
    TenantShredded {
        /// The tenant.
        tenant: syntheke::TenantId,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The tenant has invocations that are not terminal; a shred would
    /// leave recovery unable to settle them.
    #[snafu(display("tenant {tenant} has open invocations"))]
    TenantBusy {
        /// The tenant.
        tenant: syntheke::TenantId,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A data-key rotation of the tenant is already in progress; resume it
    /// instead of starting another.
    #[snafu(display("a data-key rotation of tenant {tenant} is in progress"))]
    RekeyInProgress {
        /// The tenant.
        tenant: syntheke::TenantId,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// No data-key rotation of the tenant is in progress.
    #[snafu(display("no data-key rotation of tenant {tenant} is in progress"))]
    RekeyNotInProgress {
        /// The tenant.
        tenant: syntheke::TenantId,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The store path has no final component to name a compaction
    /// directory after.
    #[snafu(display("store path {} has no directory name", path.display()))]
    StorePathUnnamed {
        /// The store path.
        path: PathBuf,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A compaction found another process holding a store directory's
    /// lock at the swap, so it swapped nothing.
    #[snafu(display("store directory {} is in use by another process", path.display()))]
    StoreInUse {
        /// The locked directory.
        path: PathBuf,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The filesystem or kernel does not support the atomic directory
    /// exchange a compaction swaps with; nothing was swapped, and the
    /// store is not compacted by a non-atomic fallback.
    #[snafu(display(
        "the filesystem holding {} does not support an atomic directory exchange \
         (renameat2 RENAME_EXCHANGE); the store was not compacted",
        path.display()
    ))]
    ExchangeUnsupported {
        /// The store path.
        path: PathBuf,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A record with the caller-chosen id already exists with different
    /// content.
    #[snafu(display("a different {what} already exists under that id"))]
    Conflict {
        /// The kind of record.
        what: &'static str,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A failpoint simulated a crash at a lifecycle boundary.
    #[snafu(display("injected crash {phase} {boundary}"))]
    InjectedCrash {
        /// The boundary.
        boundary: crate::store::Boundary,
        /// Before or after the commit.
        phase: crate::store::Phase,
        /// Source location where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },
}

/// Result alias for `phylake` operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;
