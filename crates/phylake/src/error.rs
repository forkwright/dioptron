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
}

/// Result alias for `phylake` operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;
