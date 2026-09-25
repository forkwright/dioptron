//! Capability contract shared by the Dioptron daemon and its clients.
//!
//! `syntheke` will hold the wire schema (rkyv archives validated before any
//! field access), the 16-byte identifiers, the `Capability` set, the
//! execute and dry-run modes, the outcome and error taxonomy, and the
//! protocol constants. It is the only crate a consumer links, and it takes
//! no dependency on other fleet crates.
//!
//! The contract it implements is specified in `docs/design/`. This crate is
//! a skeleton until its implementation slice lands.
#![deny(missing_docs)]
