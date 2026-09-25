//! Terminal records: every release reason recorded as given, the replies
//! derived from them, the failures a B2 settlement accepts, the
//! idempotency binding, and store-assigned artifact ids.

use syntheke::{DenyCode, ExtractionClass, Failure, InvocationState, OutcomeKind, ReleaseReason};

use crate::Error;
use crate::store::test_support::{
    ACTUAL, AGENT, DECLARED, ENVELOPE, Fixture, G_AGENT, S_AGENT, artifact, capture, ceilings,
    dump, idem, invocation, issue_agent_grant, ledger_usage, source,
};
use crate::store::{
    Begin, Intent, InvocationStatus, RecoveryReport, SettleOutcome, Store, Terminal, Transfer,
    artifact_ref,
};

/// The caller digest every intent here carries.
const DIGEST: [u8; 32] = [0xd7; 32];

/// B1 for invocation `byte` under idempotency key `byte`.
fn begin(store: &Store, byte: u8) -> Begin {
    let key = idem(byte);
    store
        .begin(&Intent::new(
            invocation(byte),
            capture(G_AGENT),
            &key,
            DIGEST,
        ))
        .expect("begin")
}

/// B1, expecting a new invocation.
fn persist(store: &Store, byte: u8) {
    let begin = begin(store, byte);
    assert!(matches!(begin, Begin::Persisted(_)), "{begin:?}");
}

/// Drives invocation `byte` to B3.
fn transfer(store: &Store, byte: u8) {
    persist(store, byte);
    store.dispatch(invocation(byte)).expect("B2");
    store
        .complete_transfer(invocation(byte), &Transfer::new(ENVELOPE, source(), ACTUAL))
        .expect("B3");
}

/// The reply kind the contract gives each release reason, written out
/// independently of [`Terminal::outcome`].
const fn expected_reply(reason: ReleaseReason) -> OutcomeKind {
    match reason {
        ReleaseReason::Revoked => OutcomeKind::Denied,
        ReleaseReason::ProducerUnavailable => OutcomeKind::ProducerUnavailable,
        ReleaseReason::DeadlineExceeded => OutcomeKind::DeadlineExceeded,
        _ => OutcomeKind::Cancelled,
    }
}

/// Releases a fresh invocation `byte` for `reason` from B1 or B2 and checks
/// the invocation, its audit entry, its replay, and the ledgers.
fn check_release(reason: ReleaseReason, dispatched: bool, byte: u8) {
    let case = format!("{reason} from {}", if dispatched { "B2" } else { "B1" });
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, byte);
    if dispatched {
        store.dispatch(invocation(byte)).expect("B2");
    }
    let status = store.release(invocation(byte), reason).expect("release");
    let expected = Terminal::Released { reason };
    assert_eq!(status.state, InvocationState::Released, "{case}: state");
    assert_eq!(status.terminal, Some(expected), "{case}: terminal record");
    assert_eq!(status.release_reason(), Some(reason), "{case}: reason");
    assert_eq!(
        ledger_usage(&store),
        vec![syntheke::Cost::default(); 4],
        "{case}: the whole reservation returns"
    );

    let audits: Vec<_> = store
        .audit_records(AGENT, None, 100)
        .expect("audit")
        .into_iter()
        .filter(|event| event.record.invocation == invocation(byte))
        .collect();
    assert_eq!(audits.len(), 1, "{case}: one terminal audit entry");
    let audit = audits.first().expect("entry");
    assert_eq!(audit.release_reason, Some(reason), "{case}: audited reason");
    assert_eq!(
        audit.record.state,
        InvocationState::Released,
        "{case}: audited state"
    );
    assert_eq!(
        audit.record.outcome,
        expected_reply(reason),
        "{case}: audited reply kind"
    );

    let Begin::Replayed(replayed) = begin(&store, byte) else {
        panic!("{case}: expected a replay");
    };
    assert_eq!(
        replayed.terminal,
        Some(expected),
        "{case}: a replay reads the reason"
    );
}

#[test]
fn release_from_intent_records_each_reason_exactly() {
    for (byte, reason) in [
        (1, ReleaseReason::Abandoned),
        (2, ReleaseReason::Revoked),
        (3, ReleaseReason::Cancelled),
        (4, ReleaseReason::DeadlineExceeded),
    ] {
        check_release(reason, false, byte);
    }
}

#[test]
fn release_from_dispatch_records_each_reason_exactly() {
    for (byte, reason) in [
        (1, ReleaseReason::Revoked),
        (2, ReleaseReason::Cancelled),
        (3, ReleaseReason::DeadlineExceeded),
        (4, ReleaseReason::ProducerUnavailable),
    ] {
        check_release(reason, true, byte);
    }
}

#[test]
fn abandoned_and_cancelled_releases_stay_distinct() {
    let abandoned = Terminal::Released {
        reason: ReleaseReason::Abandoned,
    };
    let cancelled = Terminal::Released {
        reason: ReleaseReason::Cancelled,
    };
    assert_ne!(abandoned, cancelled, "the records differ");
    assert_eq!(
        abandoned.reply_failure(),
        Some(Failure::Cancelled),
        "an abandoned call replies as a call ended before any effect"
    );
    assert_eq!(
        Terminal::Released {
            reason: ReleaseReason::Revoked
        }
        .reply_failure(),
        Some(Failure::denied(DenyCode::GrantRevoked)),
        "revoked"
    );
    assert_eq!(
        Terminal::UnknownEffect.reply_failure(),
        Some(Failure::UnknownEffect),
        "unknown effect"
    );
    assert_eq!(
        Terminal::Settled { failure: None }.outcome(),
        OutcomeKind::Success,
        "success"
    );
    assert_eq!(
        Terminal::UnknownEffect.release_reason(),
        None,
        "only a release has a reason"
    );
}

#[test]
fn dispatched_settle_refuses_a_failure_no_started_producer_reports() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    store.dispatch(invocation(1)).expect("B2");
    let before = dump(&store);
    for failure in [
        Failure::UnknownEffect,
        Failure::denied(DenyCode::GrantRevoked),
        Failure::ProducerUnavailable,
        Failure::NotFoundOrDenied,
    ] {
        let error = store
            .settle(
                invocation(1),
                SettleOutcome::Failed {
                    failure,
                    actual: ACTUAL,
                },
            )
            .expect_err("not a started failure");
        assert!(
            matches!(
                error,
                Error::SettleMismatch {
                    state: InvocationState::Dispatched,
                    ..
                }
            ),
            "{failure:?}: {error:?}"
        );
    }
    assert_eq!(dump(&store), before, "a refused settlement writes nothing");
    let failure = Failure::ExtractionFailed {
        class: ExtractionClass::Malformed,
    };
    let status = store
        .settle(
            invocation(1),
            SettleOutcome::Failed {
                failure,
                actual: ACTUAL,
            },
        )
        .expect("an extraction failure settles");
    assert_eq!(
        status.terminal,
        Some(Terminal::Settled {
            failure: Some(failure)
        }),
        "recorded"
    );
}

#[test]
fn same_key_under_another_grant_conflicts_whatever_the_digest() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    let second = syntheke::GrantId::from_bytes([0xb2; 16]);
    issue_agent_grant(&store, second, ceilings(10, 524_288));
    let before = dump(&store);
    let key = idem(1);
    let under_second = store
        .begin(&Intent::new(invocation(2), capture(second), &key, DIGEST))
        .expect("begin");
    assert_eq!(
        under_second,
        Begin::Conflict,
        "the same caller digest under another grant"
    );
    let mut other_target = capture(G_AGENT);
    other_target.target = Some("https://example.com/another-page");
    let retargeted = store
        .begin(&Intent::new(invocation(2), other_target, &key, DIGEST))
        .expect("begin");
    assert_eq!(retargeted, Begin::Conflict, "another target");
    let mut bigger = capture(G_AGENT);
    bigger.declared.fetches = DECLARED.fetches.saturating_add(1);
    let costlier = store
        .begin(&Intent::new(invocation(2), bigger, &key, DIGEST))
        .expect("begin");
    assert_eq!(costlier, Begin::Conflict, "another declared cost");
    assert_eq!(dump(&store), before, "a conflict writes nothing");
}

#[test]
fn each_capture_publishes_under_its_invocation_id() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    for byte in [1, 2] {
        transfer(&store, byte);
        let status: InvocationStatus = store.publish(invocation(byte)).expect("B4");
        assert_eq!(
            status.artifact,
            Some(artifact_ref(invocation(byte))),
            "the artifact id is the invocation id"
        );
    }
    assert_ne!(artifact(1), artifact(2), "distinct ids");
    for byte in [1, 2] {
        let info = store
            .artifact(artifact(byte))
            .expect("read")
            .expect("published");
        assert_eq!(info.artifact, artifact(byte), "readable under its id");
    }
}

#[test]
fn recovery_publishes_every_pending_capture() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    for byte in [1, 2, 3] {
        transfer(&store, byte);
    }
    drop(store);
    let store = fixture.reopen();
    let report = store.recover().expect("recover");
    let expected = RecoveryReport {
        published: 3,
        ..RecoveryReport::default()
    };
    assert_eq!(report, expected, "three roll-forward publishes");
    for byte in [1, 2, 3] {
        let status = store
            .invocation(invocation(byte))
            .expect("read")
            .expect("recorded");
        assert_eq!(
            status.terminal,
            Some(Terminal::Settled { failure: None }),
            "settled"
        );
        assert!(
            store.artifact(artifact(byte)).expect("read").is_some(),
            "visible"
        );
    }
    let page = store
        .session_artifacts(S_AGENT, None, 10)
        .expect("query")
        .expect("session");
    assert_eq!(
        page.result_refs,
        [artifact(1), artifact(2), artifact(3)],
        "all indexed"
    );
}
