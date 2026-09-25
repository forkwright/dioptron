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
//! This crate is a skeleton until its implementation slices land.
#![deny(missing_docs)]
