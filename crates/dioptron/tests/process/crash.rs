//! Crash and reopen at every durability boundary: the daemon, built with
//! the `failpoints` feature, aborts at one commit; a restart recovers and
//! a replay of the same request observes the recovered state
//! (`docs/design/custody-store.md`, "Failure-injection specification").
#![cfg(feature = "failpoints")]
#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use syntheke::{Failure, Mode, ResponseBody};

use crate::test_support::{Harness, OK, ROOT, capture, open_session, operator};

/// What a replay after recovery observes.
#[derive(Clone, Copy, Debug)]
enum Recovered {
    /// The capture completed (rolled forward, or run fresh).
    Captured,
    /// The call failed with this outcome.
    Failed(Failure),
}

/// Aborts the daemon at `failpoint` during a capture, restarts it, and
/// checks the call count at the crash, after recovery, and after a replay.
fn crash_at(failpoint: &str, calls_at_crash: usize, recovered: Recovered, calls_after: usize) {
    let harness = Harness::with_cast();
    let daemon = harness.start();
    let mut client = harness.connect(&operator());
    let session = open_session(&harness, &mut client, ROOT, "op-session");
    drop(client);
    daemon.stop();
    let request = harness.request(
        ROOT,
        Some("crash-capture"),
        Mode::Execute,
        capture(session, OK),
    );

    let daemon = harness.start_with(&[("DIOPTRON_FAILPOINT", failpoint)]);
    let mut client = harness.connect(&operator());
    let lost = client.call(&request);
    daemon.wait_abort();
    let at_crash = harness.calls();
    let daemon = harness.start();
    let after_recovery = harness.calls();
    let mut client = harness.connect(&operator());
    let replay = client.call(&request).expect("replay after restart");

    assert!(
        lost.is_err(),
        "{failpoint}: the aborted daemon sends no reply"
    );
    assert_eq!(
        at_crash, calls_at_crash,
        "{failpoint}: producer calls at the crash"
    );
    assert_eq!(
        after_recovery, at_crash,
        "{failpoint}: recovery never calls the producer"
    );
    match recovered {
        Recovered::Captured => assert!(
            matches!(replay.body, ResponseBody::Captured(_)),
            "{failpoint}: the capture is visible: {replay:?}"
        ),
        Recovered::Failed(failure) => assert_eq!(
            replay.body,
            ResponseBody::Failed(failure),
            "{failpoint}: the recovered terminal"
        ),
    }
    assert_eq!(
        harness.calls(),
        calls_after,
        "{failpoint}: calls after the replay"
    );
    drop(client);
    daemon.stop();
}

#[test]
fn crash_before_b1_commit_leaves_nothing_and_the_replay_runs_fresh() {
    crash_at("before_commit:B1", 0, Recovered::Captured, 1);
}

#[test]
fn crash_after_b1_commit_recovers_released_abandoned() {
    // WHY Cancelled: Released(Abandoned) replays as Cancelled, the
    // contract's outcome for a call that ended before any effect.
    crash_at(
        "after_commit:B1",
        0,
        Recovered::Failed(Failure::Cancelled),
        0,
    );
}

#[test]
fn crash_before_b2_commit_recovers_released_abandoned() {
    crash_at(
        "before_commit:B2",
        0,
        Recovered::Failed(Failure::Cancelled),
        0,
    );
}

#[test]
fn crash_after_b2_commit_recovers_unknown_effect_without_redispatch() {
    crash_at(
        "after_commit:B2",
        0,
        Recovered::Failed(Failure::UnknownEffect),
        0,
    );
}

#[test]
fn crash_before_b3_commit_recovers_unknown_effect_without_redispatch() {
    crash_at(
        "before_commit:B3",
        1,
        Recovered::Failed(Failure::UnknownEffect),
        1,
    );
}

#[test]
fn crash_after_b3_commit_rolls_forward_to_publish() {
    crash_at("after_commit:B3", 1, Recovered::Captured, 1);
}

#[test]
fn crash_before_b4_commit_rolls_forward_to_publish() {
    crash_at("before_commit:B4", 1, Recovered::Captured, 1);
}

#[test]
fn crash_after_b4_commit_rolls_forward_to_settle() {
    crash_at("after_commit:B4", 1, Recovered::Captured, 1);
}

#[test]
fn crash_before_b5_commit_rolls_forward_to_settle() {
    crash_at("before_commit:B5", 1, Recovered::Captured, 1);
}

#[test]
fn crash_after_b5_commit_is_terminal() {
    crash_at("after_commit:B5", 1, Recovered::Captured, 1);
}
