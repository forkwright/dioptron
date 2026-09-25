//! Process-level acceptance tests: the `dioptron` binary in a tempdir,
//! driven only through the independent `xenos` client (and, after the
//! daemon stops, by reopening its store to compare logical digests).
//!
//! Tests that move the daemon's clock need the `test-clock` feature;
//! crash tests need the `failpoints` feature. The gate runs with
//! `--all-features`, so both run there. The `features` tests prove the
//! opposite (the environment alone enables neither) and run in a
//! default-features build.

// NOTE: clippy's tests_outside_test_module (denied workspace-wide) also
// applies to integration test crates, hence the cfg(test) modules.
#[cfg(test)]
mod crash;
#[cfg(test)]
mod dry_run;
#[cfg(test)]
mod features;
#[cfg(test)]
mod flow;
#[cfg(test)]
mod grants;
#[cfg(test)]
mod identity;
#[cfg(test)]
mod isolation;
#[cfg(test)]
mod replay;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod wire;
