//! The failure-injection table of `docs/design/custody-store.md`: crash
//! before and after each boundary commit, reopen, recover, and check the
//! exact recovered state, the ledgers, the audit trail, and the producer
//! call count.

use std::sync::Arc;

use syntheke::{Cost, InvocationState, ReleaseReason};

use crate::Error;
use crate::store::test_support::{
    ACTUAL, AGENT, CrashAt, DECLARED, ENVELOPE, Fixture, G_AGENT, ProducerCounter, artifact,
    capture, count, dump, idem, invocation, ledger_usage, source,
};
use crate::store::{
    Begin, Boundary, Intent, Phase, RecoveryReport, SettleOutcome, Store, Transfer,
};

/// The state recovery must reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    /// No invocation and no reservation.
    Nothing,
    /// `Released(Abandoned)`, reservation returned.
    Abandoned,
    /// `UnknownEffect`, reservation charged, nothing visible.
    UnknownEffect,
    /// `Settled`, actual cost kept, artifact visible.
    Settled,
}

/// Runs one capture through every boundary, calling the stand-in producer
/// between B2 and B3, and stops at the first error.
fn drive(store: &Store, producer: &ProducerCounter) -> Result<(), Error> {
    let key = idem(1);
    let begin = store.begin(&Intent::new(
        invocation(1),
        capture(G_AGENT),
        &key,
        [0xd1; 32],
    ))?;
    assert!(matches!(begin, Begin::Persisted(_)), "{begin:?}");
    store.dispatch(invocation(1))?;
    producer.call();
    let transfer = Transfer::new(artifact(0x71), ENVELOPE, source(), ACTUAL);
    store.complete_transfer(invocation(1), &transfer)?;
    store.publish(invocation(1))?;
    store.settle(invocation(1), SettleOutcome::Success)?;
    Ok(())
}

/// Crashes at `boundary`/`phase`, recovers, and checks the result.
fn check(boundary: Boundary, phase: Phase, expected: Expected, calls: u32) {
    let fixture = Fixture::new();
    drop(fixture.seeded());
    let store = fixture.reopen_with(Arc::new(CrashAt { boundary, phase }));
    let producer = ProducerCounter::default();
    let error = drive(&store, &producer).expect_err("the failpoint fires");
    assert!(
        matches!(error, Error::InjectedCrash { boundary: b, phase: p, .. } if b == boundary && p == phase),
        "crash at {phase} {boundary}: {error:?}"
    );
    drop(store);
    assert_eq!(
        producer.calls(),
        calls,
        "calls before recovery at {phase} {boundary}"
    );

    let store = fixture.reopen();
    let report = store.recover().expect("recover");
    assert_eq!(producer.calls(), calls, "recovery never calls the producer");
    assert_eq!(
        report,
        expected_report(boundary, phase, expected),
        "report at {phase} {boundary}"
    );
    assert_state(&store, expected, &format!("{phase} {boundary}"));

    let settled = dump(&store);
    let again = store.recover().expect("second recovery");
    assert!(
        again.is_empty(),
        "a second recovery does nothing: {again:?}"
    );
    assert_eq!(dump(&store), settled, "a second recovery writes nothing");
    drop(store);
    let store = fixture.reopen();
    assert!(
        store.recover().expect("third").is_empty(),
        "idempotent across reopen"
    );
    assert_eq!(producer.calls(), calls, "the producer count never moves");
}

/// What recovery reports for the row: which roll-forward or terminal
/// step it took.
fn expected_report(boundary: Boundary, phase: Phase, expected: Expected) -> RecoveryReport {
    let mut report = RecoveryReport::default();
    match (expected, boundary, phase) {
        (Expected::Abandoned, ..) => report.released = 1,
        (Expected::UnknownEffect, ..) => report.unknown_effect = 1,
        (Expected::Settled, Boundary::CompleteTransfer, Phase::AfterCommit)
        | (Expected::Settled, Boundary::Publish, Phase::BeforeCommit) => report.published = 1,
        (Expected::Settled, Boundary::Publish, Phase::AfterCommit)
        | (Expected::Settled, Boundary::Terminal, Phase::BeforeCommit) => report.settled = 1,
        _ => {}
    }
    report
}

fn assert_state(store: &Store, expected: Expected, case: &str) {
    let status = store.invocation(invocation(1)).expect("read");
    let terminal_audits = store
        .audit_records(AGENT, None, 100)
        .expect("audit")
        .into_iter()
        .filter(|record| record.invocation == invocation(1))
        .count();
    let visible = store
        .read_artifact(artifact(0x71), 0, 4096)
        .expect("read")
        .map(|chunk| chunk.bytes);
    let blobs = count(&dump(store), "blobs");
    match expected {
        Expected::Nothing => {
            assert_eq!(status, None, "{case}: no invocation");
            assert_eq!(
                ledger_usage(store),
                vec![Cost::default(); 4],
                "{case}: no reservation"
            );
            assert_eq!(terminal_audits, 0, "{case}: nothing audited");
        }
        Expected::Abandoned => {
            let status = status.expect("recorded");
            assert_eq!(status.state, InvocationState::Released, "{case}: released");
            assert_eq!(
                status.release_reason,
                Some(ReleaseReason::Abandoned),
                "{case}: reason"
            );
            assert_eq!(
                ledger_usage(store),
                vec![Cost::default(); 4],
                "{case}: released once"
            );
            assert_eq!(terminal_audits, 1, "{case}: one terminal audit entry");
        }
        Expected::UnknownEffect => {
            let status = status.expect("recorded");
            assert_eq!(
                status.state,
                InvocationState::UnknownEffect,
                "{case}: unknown effect"
            );
            assert_eq!(
                status.debited,
                Some(DECLARED),
                "{case}: reservation charged"
            );
            assert_eq!(
                ledger_usage(store),
                vec![DECLARED; 4],
                "{case}: charged once"
            );
            assert_eq!(terminal_audits, 1, "{case}: one terminal audit entry");
            assert_eq!(blobs, 0, "{case}: an uncommitted blob is discarded");
        }
        Expected::Settled => {
            let status = status.expect("recorded");
            assert_eq!(status.state, InvocationState::Settled, "{case}: settled");
            assert_eq!(status.debited, Some(ACTUAL), "{case}: actual kept");
            assert_eq!(ledger_usage(store), vec![ACTUAL; 4], "{case}: settled once");
            assert_eq!(terminal_audits, 1, "{case}: one terminal audit entry");
        }
    }
    let expect_visible = expected == Expected::Settled;
    assert_eq!(
        visible.as_deref() == Some(ENVELOPE),
        expect_visible,
        "{case}: visibility"
    );
    assert_eq!(
        visible.is_some(),
        expect_visible,
        "{case}: nothing partial is visible"
    );
}

/// One test per row of the failure-injection table.
macro_rules! crash_row {
    ($($name:ident: $boundary:ident, $phase:ident => $expected:ident, calls $calls:literal;)+) => {
        $(#[test]
        fn $name() {
            check(Boundary::$boundary, Phase::$phase, Expected::$expected, $calls);
        })+
    };
}

crash_row! {
    crash_before_b1_leaves_nothing: PersistIntent, BeforeCommit => Nothing, calls 0;
    crash_after_b1_releases_abandoned: PersistIntent, AfterCommit => Abandoned, calls 0;
    crash_before_b2_releases_abandoned: Dispatch, BeforeCommit => Abandoned, calls 0;
    crash_after_b2_marks_unknown_effect: Dispatch, AfterCommit => UnknownEffect, calls 0;
    crash_before_b3_marks_unknown_effect: CompleteTransfer, BeforeCommit => UnknownEffect, calls 1;
    crash_after_b3_rolls_forward_to_settled: CompleteTransfer, AfterCommit => Settled, calls 1;
    crash_before_b4_rolls_forward_to_settled: Publish, BeforeCommit => Settled, calls 1;
    crash_after_b4_rolls_forward_to_settled: Publish, AfterCommit => Settled, calls 1;
    crash_before_b5_rolls_forward_to_settled: Terminal, BeforeCommit => Settled, calls 1;
    crash_after_b5_is_terminal: Terminal, AfterCommit => Settled, calls 1;
}

#[test]
fn boundary_names_match_the_contract() {
    let names: Vec<String> = Boundary::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(names, ["B1", "B2", "B3", "B4", "B5"], "boundary names");
    let phases: Vec<String> = Phase::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(
        phases,
        ["before commit of", "after commit of"],
        "phase names"
    );
}
