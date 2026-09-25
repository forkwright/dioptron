//! Store tests. Every test works in a tempdir with a fixed clock and
//! reproducible entropy.
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

mod crash;
mod directory;
mod disk;
mod lifecycle;
mod open;
