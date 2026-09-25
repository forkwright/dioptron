//! B1 through B5, idempotency, refusals, dry-run, reads, and concurrency.

use syntheke::{
    Capability, Cost, DenyCode, Dimension, Failure, InvocationState, OutcomeKind, ReleaseReason,
    TransferClass,
};

use crate::Error;
use crate::store::test_support::{
    ACTUAL, AGENT, DECLARED, ENVELOPE, Fixture, G_AGENT, OPERATOR, S_AGENT, artifact, capture,
    ceilings, count, dump, idem, invocation, issue_agent_grant, ledger_usage, source,
};
use crate::store::{Begin, Intent, InvocationStatus, SettleOutcome, Store, Terminal, Transfer};

/// A digest standing in for the request digest.
const DIGEST: [u8; 32] = [0xd1; 32];

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
fn persist(store: &Store, byte: u8) -> InvocationStatus {
    match begin(store, byte) {
        Begin::Persisted(status) => status,
        other => panic!("expected a persisted intent, got {other:?}"),
    }
}

/// The transfer every test capture reports.
fn transfer() -> Transfer<'static> {
    let mut transfer = Transfer::new(ENVELOPE, source(), ACTUAL);
    transfer.text_view = Some("PHYLAKE-CUSTODY-PLAINTEXT-7f3a".to_owned());
    transfer.output_bytes = 30;
    transfer
}

/// Drives invocation `byte` through B1 to B4.
fn publish(store: &Store, byte: u8) {
    persist(store, byte);
    store.dispatch(invocation(byte)).expect("B2");
    store
        .complete_transfer(invocation(byte), &transfer())
        .expect("B3");
    store.publish(invocation(byte)).expect("B4");
}

/// `cost` on every capture ledger.
fn all(cost: Cost) -> Vec<Cost> {
    vec![cost; 4]
}

#[test]
fn happy_path_runs_b1_through_b5() {
    let fixture = Fixture::new();
    let store = fixture.seeded();

    let status = persist(&store, 1);
    assert_eq!(status.state, InvocationState::IntentPersisted, "B1 state");
    assert_eq!(
        status.reserved, DECLARED,
        "B1 reserves the declared maximum"
    );
    assert_eq!(
        status.grant_chain,
        [G_AGENT, crate::store::test_support::G_ROOT],
        "chain"
    );
    assert_eq!(
        ledger_usage(&store),
        all(DECLARED),
        "every ledger is debited at B1"
    );

    let status = store.dispatch(invocation(1)).expect("B2");
    assert_eq!(status.state, InvocationState::Dispatched, "B2 state");
    let status = store
        .complete_transfer(invocation(1), &transfer())
        .expect("B3");
    assert_eq!(status.state, InvocationState::TransferComplete, "B3 state");
    let status = store.publish(invocation(1)).expect("B4");
    assert_eq!(status.state, InvocationState::Published, "B4 state");
    let status = store
        .settle(invocation(1), SettleOutcome::Success)
        .expect("B5");
    assert_eq!(status.state, InvocationState::Settled, "B5 state");
    assert_eq!(
        status.terminal,
        Some(Terminal::Settled { failure: None }),
        "a success"
    );
    assert_eq!(
        status.debited,
        Some(ACTUAL),
        "the actual consumption is kept"
    );
    assert_eq!(
        ledger_usage(&store),
        all(ACTUAL),
        "the remainder is released"
    );
    let terminal = store
        .audit_records(AGENT, None, 100)
        .expect("audit")
        .into_iter()
        .map(|event| event.record)
        .filter(|record| record.invocation == invocation(1))
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 1, "one audit entry, at the terminal state");
    assert_eq!(
        terminal.first().map(|r| r.state),
        Some(InvocationState::Settled),
        "state"
    );
}

#[test]
fn published_artifact_reads_whole_and_in_chunks() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    publish(&store, 1);
    let info = store
        .artifact(artifact(1))
        .expect("read")
        .expect("published");
    assert_eq!(info.owner, AGENT, "owner");
    assert_eq!(info.session, Some(S_AGENT), "session");
    assert_eq!(info.source, source(), "source reference");
    assert_eq!(
        usize::try_from(info.envelope_len).ok(),
        Some(ENVELOPE.len()),
        "envelope length"
    );
    let whole = store
        .read_artifact(artifact(1), 0, 4096)
        .expect("read")
        .expect("published");
    assert_eq!(whole.bytes, ENVELOPE, "the envelope is stored verbatim");
    let chunk = store
        .read_artifact(artifact(1), 12, 10)
        .expect("read")
        .expect("published");
    assert_eq!(chunk.bytes, b"PHYLAKE-CU", "a chunk is a slice");
    assert_eq!(
        usize::try_from(chunk.total_len).ok(),
        Some(ENVELOPE.len()),
        "chunks report the total"
    );
    let tail = store
        .read_artifact(artifact(1), 500, 10)
        .expect("read")
        .expect("published");
    assert!(tail.bytes.is_empty(), "a chunk past the end is empty");

    let page = store
        .session_artifacts(S_AGENT, None, 10)
        .expect("query")
        .expect("session exists");
    assert_eq!(
        page.result_refs,
        [artifact(1)],
        "the session index lists it"
    );
    assert!(!page.more, "one result");
}

#[test]
fn transfer_complete_blob_is_not_visible() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    store.dispatch(invocation(1)).expect("B2");
    store
        .complete_transfer(invocation(1), &transfer())
        .expect("B3");
    let blobs = count(&dump(&store), "blobs");
    assert_eq!(blobs, 1, "the blob is written at B3");
    assert_eq!(
        store.artifact(artifact(1)).expect("read"),
        None,
        "no side record read"
    );
    assert_eq!(
        store.read_artifact(artifact(1), 0, 16).expect("read"),
        None,
        "no envelope read"
    );
    let page = store
        .session_artifacts(S_AGENT, None, 10)
        .expect("query")
        .expect("session exists");
    assert!(page.result_refs.is_empty(), "no session index entry");
}

#[test]
fn settling_twice_is_refused_and_settles_once() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    publish(&store, 1);
    store
        .settle(invocation(1), SettleOutcome::Success)
        .expect("first settle");
    let before = dump(&store);
    let error = store
        .settle(invocation(1), SettleOutcome::Success)
        .expect_err("second settle");
    assert!(matches!(error, Error::Authz { .. }), "{error:?}");
    let error = store
        .release(invocation(1), ReleaseReason::Cancelled)
        .expect_err("release after settle");
    assert!(matches!(error, Error::Authz { .. }), "{error:?}");
    assert_eq!(dump(&store), before, "a refused step writes nothing");
    assert_eq!(ledger_usage(&store), all(ACTUAL), "settled exactly once");
}

#[test]
fn publish_before_transfer_is_refused() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    store.dispatch(invocation(1)).expect("B2");
    let error = store.publish(invocation(1)).expect_err("publish at B2");
    assert!(matches!(error, Error::Authz { .. }), "{error:?}");
    let error = store
        .settle(invocation(1), SettleOutcome::Success)
        .expect_err("success before publish");
    assert!(
        matches!(
            error,
            Error::SettleMismatch {
                state: InvocationState::Dispatched,
                ..
            }
        ),
        "{error:?}"
    );
    let error = store.dispatch(invocation(1)).expect_err("dispatch twice");
    assert!(matches!(error, Error::Authz { .. }), "{error:?}");
}

#[test]
fn failure_after_publish_is_a_mismatch() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    publish(&store, 1);
    let failed = SettleOutcome::Failed {
        failure: Failure::Cancelled,
        actual: ACTUAL,
    };
    let error = store
        .settle(invocation(1), failed)
        .expect_err("failure at B4");
    assert!(
        matches!(
            error,
            Error::SettleMismatch {
                state: InvocationState::Published,
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn dispatched_failure_settles_actual_cost() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    store.dispatch(invocation(1)).expect("B2");
    let failure = Failure::TransferFailed {
        class: TransferClass::Reset,
    };
    let status = store
        .settle(
            invocation(1),
            SettleOutcome::Failed {
                failure,
                actual: ACTUAL,
            },
        )
        .expect("B5");
    assert_eq!(status.state, InvocationState::Settled, "settled");
    assert_eq!(
        status.terminal,
        Some(Terminal::Settled {
            failure: Some(failure)
        }),
        "the failure is recorded"
    );
    assert_eq!(ledger_usage(&store), all(ACTUAL), "actual cost kept");
}

#[test]
fn overrun_is_clamped_to_the_reservation() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    store.dispatch(invocation(1)).expect("B2");
    let actual = Cost {
        fetches: 3,
        ..ACTUAL
    };
    let status = store
        .settle(
            invocation(1),
            SettleOutcome::Failed {
                failure: Failure::Cancelled,
                actual,
            },
        )
        .expect("B5");
    let kept = Cost {
        fetches: DECLARED.fetches,
        ..ACTUAL
    };
    assert_eq!(status.debited, Some(kept), "never more than reserved");
    assert_eq!(
        ledger_usage(&store),
        all(kept),
        "ledgers hold the clamped debit"
    );
}

#[test]
fn release_returns_the_whole_reservation() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    let status = store
        .release(invocation(1), ReleaseReason::Revoked)
        .expect("release");
    assert_eq!(status.state, InvocationState::Released, "released");
    assert_eq!(
        status.terminal,
        Some(Terminal::Released {
            reason: ReleaseReason::Revoked
        }),
        "the reason is the record"
    );
    assert_eq!(
        status.terminal.and_then(Terminal::reply_failure),
        Some(Failure::denied(DenyCode::GrantRevoked)),
        "a revoked release replies as a revoked grant"
    );
    assert_eq!(
        ledger_usage(&store),
        all(Cost::default()),
        "nothing is kept"
    );
}

#[test]
fn unknown_effect_charges_the_reservation() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    store.dispatch(invocation(1)).expect("B2");
    let status = store.mark_unknown_effect(invocation(1)).expect("B5");
    assert_eq!(status.state, InvocationState::UnknownEffect, "state");
    assert_eq!(status.debited, Some(DECLARED), "the reservation is charged");
    assert_eq!(ledger_usage(&store), all(DECLARED), "nothing is released");
}

#[test]
fn replay_returns_the_existing_invocation() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    store.dispatch(invocation(1)).expect("B2");
    let before = dump(&store);
    let key = idem(1);
    let replay = store
        .begin(&Intent::new(invocation(2), capture(G_AGENT), &key, DIGEST))
        .expect("replay");
    let Begin::Replayed(status) = replay else {
        panic!("expected a replay, got {replay:?}");
    };
    assert_eq!(status.id, invocation(1), "the original invocation");
    assert_eq!(
        status.state,
        InvocationState::Dispatched,
        "its current state"
    );
    assert_eq!(dump(&store), before, "a replay writes nothing");
    assert_eq!(
        ledger_usage(&store),
        all(DECLARED),
        "nothing reserved twice"
    );
}

#[test]
fn same_key_with_a_different_digest_conflicts() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    let before = dump(&store);
    let key = idem(1);
    let result = store
        .begin(&Intent::new(
            invocation(2),
            capture(G_AGENT),
            &key,
            [0xd2; 32],
        ))
        .expect("begin");
    assert_eq!(
        result,
        Begin::Conflict,
        "the key is bound to another request"
    );
    assert_eq!(dump(&store), before, "a conflict writes nothing");
}

#[test]
fn reused_invocation_id_is_a_conflict() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    persist(&store, 1);
    let key = idem(2);
    let error = store
        .begin(&Intent::new(invocation(1), capture(G_AGENT), &key, DIGEST))
        .expect_err("id taken");
    assert!(
        matches!(
            error,
            Error::Conflict {
                what: "invocation",
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn refused_call_writes_only_its_audit_entry() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let before = dump(&store);
    let key = idem(3);
    let mut request = capture(G_AGENT);
    request.capability = Capability::Ingest;
    let result = store
        .begin(&Intent::new(invocation(3), request, &key, DIGEST))
        .expect("begin");
    let Begin::Refused { failure, audit_seq } = result else {
        panic!("expected a refusal, got {result:?}");
    };
    assert_eq!(
        failure,
        Failure::denied(DenyCode::CapabilityNotGranted),
        "the agent grant does not confer Ingest"
    );
    let after = dump(&store);
    for (name, entries) in &after {
        let grew = entries.len() != count(&before, name);
        let audit = *name == "audit" || *name == "audit_stub";
        assert_eq!(
            grew, audit,
            "only the audit keyspaces change, {name} did not"
        );
    }
    let records = store.audit_records(AGENT, None, 100).expect("audit");
    let denied = records
        .iter()
        .map(|event| &event.record)
        .find(|record| record.invocation == invocation(3))
        .expect("the refusal is audited");
    assert_eq!(denied.seq, audit_seq, "sequence");
    assert_eq!(denied.state, InvocationState::Denied, "state");
    assert_eq!(denied.outcome, OutcomeKind::Denied, "outcome");
    assert_eq!(
        store.invocation(invocation(3)).expect("read"),
        None,
        "no invocation record"
    );
}

#[test]
fn budget_exceeded_on_an_own_ledger_names_the_dimension() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = idem(4);
    let mut request = capture(G_AGENT);
    request.declared.fetches = 11;
    let result = store
        .begin(&Intent::new(invocation(4), request, &key, DIGEST))
        .expect("begin");
    assert!(
        matches!(
            result,
            Begin::Refused {
                failure: Failure::BudgetExceeded {
                    dimension: Dimension::Fetches
                },
                ..
            }
        ),
        "{result:?}"
    );
}

#[test]
fn dry_run_writes_nothing() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let before = dump(&store);
    let allowed = store.plan(&capture(G_AGENT)).expect("plan");
    assert_eq!(allowed.refusal, None, "the plan would be allowed");
    assert_eq!(allowed.cost, DECLARED, "the plan carries the declared cost");
    let mut refused = capture(G_AGENT);
    refused.capability = Capability::Ingest;
    let refused = store.plan(&refused).expect("plan");
    assert!(refused.refusal.is_some(), "the plan reports the refusal");
    assert_eq!(
        dump(&store),
        before,
        "two dry-runs leave the store byte for byte unchanged"
    );
}

#[test]
fn unknown_invocation_is_missing() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let error = store.dispatch(invocation(9)).expect_err("missing");
    assert!(
        matches!(error, Error::InvocationMissing { .. }),
        "{error:?}"
    );
    assert_eq!(
        store.invocation(invocation(9)).expect("read"),
        None,
        "reads as absent"
    );
}

#[test]
fn unknown_tenant_cannot_begin() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = idem(5);
    let mut request = capture(G_AGENT);
    request.tenant = syntheke::TenantId::from_bytes([0x99; 16]);
    let error = store
        .begin(&Intent::new(invocation(5), request, &key, DIGEST))
        .expect_err("unknown tenant");
    assert!(matches!(error, Error::TenantMissing { .. }), "{error:?}");
}

#[test]
fn reads_of_missing_records_are_absent() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    assert_eq!(
        store.artifact(artifact(0x55)).expect("read"),
        None,
        "artifact"
    );
    assert_eq!(
        store.read_artifact(artifact(0x55), 0, 1).expect("read"),
        None,
        "chunk"
    );
    let missing = syntheke::SessionId::from_bytes([0x5e; 16]);
    assert_eq!(
        store.session_artifacts(missing, None, 1).expect("read"),
        None,
        "session"
    );
}

#[test]
fn session_query_pages_in_artifact_order() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    for byte in [3, 1, 2] {
        persist(&store, byte);
        store.dispatch(invocation(byte)).expect("B2");
        store
            .complete_transfer(invocation(byte), &transfer())
            .expect("B3");
        store.publish(invocation(byte)).expect("B4");
    }
    let first = store
        .session_artifacts(S_AGENT, None, 2)
        .expect("query")
        .expect("session");
    assert_eq!(first.result_refs, [artifact(1), artifact(2)], "first page");
    assert!(first.more, "a third result remains");
    let second = store
        .session_artifacts(S_AGENT, Some(artifact(2)), 2)
        .expect("query")
        .expect("session");
    assert_eq!(second.result_refs, [artifact(3)], "second page");
    assert!(!second.more, "no more");
    assert_eq!(
        count(&dump(&store), "blobs"),
        1,
        "identical envelopes share a blob"
    );
}

#[test]
fn concurrent_reservations_cannot_overspend() {
    // WHY eight racers on a ceiling of three, released together by a
    // barrier: the reservation reads and debits every ledger inside one
    // write transaction, so exactly three fit however the threads
    // interleave. A read outside the writing transaction would let
    // racers that read the same remaining budget all reserve.
    const RACERS: u8 = 8;
    const CEILING: u64 = 3;
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let tight = syntheke::GrantId::from_bytes([0xb1; 16]);
    issue_agent_grant(&store, tight, ceilings(CEILING, 524_288));
    let barrier = std::sync::Barrier::new(usize::from(RACERS));
    let results: Vec<Begin> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..RACERS)
            .map(|index| {
                let (store, barrier) = (&store, &barrier);
                scope.spawn(move || {
                    let byte = 0x10_u8.saturating_add(index);
                    let key = idem(byte);
                    let intent = Intent::new(invocation(byte), capture(tight), &key, DIGEST);
                    barrier.wait();
                    store.begin(&intent).expect("begin")
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect()
    });
    let persisted = results
        .iter()
        .filter(|result| matches!(result, Begin::Persisted(_)))
        .count();
    let refused = results
        .iter()
        .filter(|result| {
            matches!(
                result,
                Begin::Refused {
                    failure: Failure::BudgetExceeded {
                        dimension: Dimension::Fetches
                    },
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        (persisted, refused),
        (3, 5),
        "three fit, five are refused: {results:?}"
    );
    let snapshot = store.snapshot();
    for ledger in [
        epitrope::LedgerId::Grant(tight),
        epitrope::LedgerId::Grant(crate::store::test_support::G_ROOT),
        epitrope::LedgerId::Session(S_AGENT),
        epitrope::LedgerId::Tenant(AGENT),
    ] {
        let used = epitrope::LedgerView::used(&snapshot, ledger).expect("ledger");
        assert_eq!(
            used.fetches, CEILING,
            "{ledger:?} holds exactly the three reservations"
        );
    }
}

#[test]
fn operator_capture_in_an_agent_session_indexes_under_the_owner() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = idem(6);
    let request = epitrope::AuthzRequest {
        tenant: OPERATOR,
        grant: crate::store::test_support::G_ROOT,
        ..capture(G_AGENT)
    };
    let result = store
        .begin(&Intent::new(invocation(6), request, &key, DIGEST))
        .expect("begin");
    assert!(matches!(result, Begin::Persisted(_)), "{result:?}");
    store.dispatch(invocation(6)).expect("B2");
    store
        .complete_transfer(invocation(6), &transfer())
        .expect("B3");
    store.publish(invocation(6)).expect("B4");
    let page = store
        .session_artifacts(S_AGENT, None, 10)
        .expect("query")
        .expect("session");
    assert_eq!(
        page.result_refs,
        [artifact(6)],
        "indexed in the agent's session"
    );
    let info = store
        .artifact(artifact(6))
        .expect("read")
        .expect("published");
    assert_eq!(info.owner, OPERATOR, "owned by the capturing tenant");
}
