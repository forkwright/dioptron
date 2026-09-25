//! Durable custody for Dioptron state (layer D5, store).
//!
//! `phylake` will persist tenants, grants, revocations, sessions,
//! invocations, budget ledgers, artifacts, and audit records in
//! transactional keyspaces. Records are sealed at rest with per-tenant keys
//! derived from an operator-held root key, blobs are addressed by a
//! tenant-keyed MAC, and every invocation boundary commits in its own
//! transaction so that restart recovery can settle or release each
//! invocation exactly once.
//!
//! This slice provides the encryption layer (`docs/design/custody-store.md`,
//! "Encryption at rest"): [`keyfile`] loads and creates the root key, and
//! [`crypto`] derives subkeys, seals records, wraps tenant data keys,
//! computes keyed blob addresses, and checks the key-check value that gates
//! a locked start. The keyspaces themselves land in a later slice.
#![deny(missing_docs)]

pub mod crypto;
mod error;
pub mod keyfile;

pub use error::{Error, Result};
