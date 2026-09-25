//! The `failpoints` and `test-clock` features are the only way to enable
//! failure injection and the file clock: without them, their environment
//! variables change nothing. These tests run in a default-features build.
#![cfg(not(all(feature = "failpoints", feature = "test-clock")))]
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use syntheke::{Mode, ResponseBody};

use crate::test_support::{Harness, OK, ROOT, capture, open_session, operator};

/// Captures `OK` as the operator on a daemon started with `env`, after
/// `before` prepares the harness, and returns whether it captured; the
/// daemon must then stop cleanly.
fn captures_with(env: &[(&str, &str)], before: impl FnOnce(&Harness)) -> bool {
    let harness = Harness::with_cast();
    before(&harness);
    let daemon = harness.start_with(env);
    let mut client = harness.connect(&operator());
    let session = open_session(&harness, &mut client, ROOT, "op-session");
    let request = harness.request(
        ROOT,
        Some("inert-capture"),
        Mode::Execute,
        capture(session, OK),
    );
    let response = client.call(&request).expect("capture");
    drop(client);
    daemon.stop();
    matches!(response.body, ResponseBody::Captured(_))
}

#[cfg(not(feature = "failpoints"))]
#[test]
fn failpoint_variable_is_inert_without_the_feature() {
    let captured = captures_with(&[("DIOPTRON_FAILPOINT", "before_commit:B1")], |_| {});

    assert!(captured, "the daemon never aborts at a failpoint");
}

#[cfg(not(feature = "test-clock"))]
#[test]
fn clock_variable_is_inert_without_the_feature() {
    // WHY past every grant: with the file clock the root grant would have
    // expired; the system clock is inside its validity.
    let captured = captures_with(&[], |harness| {
        harness.set_clock(crate::test_support::EXPIRES_MS.saturating_add(1));
    });

    assert!(captured, "the daemon reads the system clock");
}
