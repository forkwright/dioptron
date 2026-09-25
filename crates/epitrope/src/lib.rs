//! Authorization decisions for Dioptron tenants.
//!
//! `epitrope` will decide whether a grant may be issued and whether it is
//! valid now: narrowing on every axis (capabilities, session and target
//! scopes, budget ceilings, expiry, delegation depth), a chain walk against
//! revocation records, budget reservation and settlement arithmetic, the
//! invocation transition table, and a dry-run planner over a read-only
//! snapshot. It performs no IO and reads time only through an injected
//! clock.
//!
//! This crate is a skeleton until its implementation slice lands.
#![deny(missing_docs)]
