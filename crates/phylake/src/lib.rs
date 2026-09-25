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
//! [`keyfile`] loads and creates the root key; [`crypto`] derives subkeys,
//! seals records, wraps tenant data keys, computes keyed blob addresses,
//! and checks the key-check value that gates a locked start
//! (`docs/design/custody-store.md`, "Encryption at rest"). [`store`] holds
//! the keyspaces, the invocation transactions B1 through B5, failure
//! injection, and restart recovery.
#![deny(missing_docs)]

pub mod crypto;
mod error;
pub mod keyfile;
pub mod store;

pub use error::{Error, Result};
pub use store::{Store, StoreOptions};
