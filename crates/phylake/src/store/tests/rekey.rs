//! Tenant data-key rotation: every record re-sealed, reads during the
//! rotation, and a crash before and after each rekey commit.

use std::num::NonZeroUsize;

use crate::Error;
use crate::crypto::{KeyId, Keyspace};
use crate::store::record_key::store as keys;
use crate::store::test_support::{
    AGENT, CrashAtNth, Fixture, OTHER, SealedRecord, publish_capture, raw, reads, tenant_sealed,
};
use crate::store::{Boundary, Phase, RekeyStatus, Store};

const KEY_1: KeyId = KeyId::new(1);
const KEY_2: KeyId = KeyId::new(2);

/// One record per batch, so every rotation spans many batch commits.
const ONE: NonZeroUsize = NonZeroUsize::MIN;

/// Envelopes of the seeded captures.
const ENVELOPES: [&[u8]; 3] = [
    b"<p>REKEY-ENVELOPE-ONE example.com</p>",
    b"<p>REKEY-ENVELOPE-TWO example.com</p>",
    b"<p>REKEY-ENVELOPE-THREE example.com</p>",
];

/// A seeded store with three published captures by the agent.
fn populated(fixture: &Fixture) -> (Store, Vec<syntheke::ArtifactRef>) {
    let store = fixture.seeded();
    let artifacts = ENVELOPES
        .iter()
        .zip(1_u8..)
        .map(|(envelope, byte)| publish_capture(&store, byte, envelope))
        .collect();
    (store, artifacts)
}

/// The agent's tenant-sealed records, counted independently of the walk:
/// per capture an idempotency entry, a side record, a blob, and a session
/// index entry, plus one record per audit entry the agent reads back.
fn expected_agent_records(store: &Store) -> usize {
    let audit = store.audit_records(AGENT, None, 1000).expect("audit").len();
    ENVELOPES
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(audit))
        .expect("count")
}

fn ids(records: &[SealedRecord]) -> Vec<KeyId> {
    records.iter().map(|(_, _, id)| *id).collect()
}

#[test]
fn rekey_reseals_every_record_and_retires_the_old_key() {
    let fixture = Fixture::new();
    let (store, artifacts) = populated(&fixture);
    let before = reads(&store, &artifacts);
    let expected = expected_agent_records(&store);
    let agent_before = tenant_sealed(&store, AGENT);
    assert_eq!(agent_before.len(), expected, "every agent record opens");
    assert!(
        ids(&agent_before).iter().all(|id| *id == KEY_1),
        "all under key 1"
    );
    let other_before = tenant_sealed(&store, OTHER);

    let status = store.rekey_tenant(AGENT, ONE).expect("rekey");
    assert!(
        !store
            .tenant_keys
            .lock()
            .expect("cache")
            .contains_key(&AGENT),
        "the retire commit evicts the cached keyring"
    );
    assert_eq!(
        status,
        RekeyStatus {
            tenant: AGENT,
            from_key_id: KEY_1,
            to_key_id: KEY_2,
            keyspace: None,
            visited: status.visited,
            resealed: u64::try_from(expected).expect("count"),
            total: status.total,
            done: true,
        },
        "the rotation re-sealed exactly the agent's records"
    );
    assert!(status.visited >= status.resealed, "{status:?}");
    assert_eq!(status.visited, status.total, "no writes ran during it");

    let agent_after = tenant_sealed(&store, AGENT);
    assert_eq!(agent_after.len(), expected, "no agent record lost");
    assert!(
        ids(&agent_after).iter().all(|id| *id == KEY_2),
        "all under key 2"
    );
    let keys_before: Vec<_> = agent_before.iter().map(|(ks, key, _)| (*ks, key)).collect();
    let keys_after: Vec<_> = agent_after.iter().map(|(ks, key, _)| (*ks, key)).collect();
    assert_eq!(
        keys_before, keys_after,
        "record keys and blob keys stay put"
    );
    assert_eq!(
        tenant_sealed(&store, OTHER),
        other_before,
        "another tenant is untouched"
    );
    assert_eq!(reads(&store, &artifacts), before, "reads are unchanged");

    let old = keys::data_key(store.keys.index(), AGENT, KEY_1).expect("key");
    assert!(
        raw(&store, Keyspace::Keys, &old).is_none(),
        "the old wrapped key is deleted"
    );
    drop(store);
    let store = fixture.reopen();
    assert_eq!(reads(&store, &artifacts), before, "reads after reopen");
    assert_eq!(store.rekey_status(AGENT).expect("status"), Some(status));
}

#[test]
fn second_rotation_keeps_the_addressing_subkeys() {
    let fixture = Fixture::new();
    let (store, artifacts) = populated(&fixture);
    let before = reads(&store, &artifacts);
    let first = store.rekey_tenant(AGENT, ONE).expect("first");
    let second = store
        .rekey_tenant(AGENT, NonZeroUsize::MAX)
        .expect("second");
    assert_eq!(
        (first.to_key_id, second.from_key_id, second.to_key_id),
        (KEY_2, KEY_2, KeyId::new(3)),
        "each rotation starts from the active key"
    );
    assert_eq!(second.resealed, first.resealed, "the same records again");
    assert_eq!(
        reads(&store, &artifacts),
        before,
        "reads survive two rotations"
    );
    let later = publish_capture(&store, 9, b"<p>REKEY-AFTER example.com</p>");
    assert!(
        store.artifact(later).expect("read").is_some(),
        "writes keep working"
    );
}

#[test]
fn reads_and_writes_work_mid_rotation() {
    let fixture = Fixture::new();
    let (store, artifacts) = populated(&fixture);
    let before = reads(&store, &artifacts);
    store.begin_rekey(AGENT).expect("begin");
    for _ in 0..4 {
        store.rekey_batch(AGENT, ONE).expect("batch");
    }
    let mixed = ids(&tenant_sealed(&store, AGENT));
    assert!(
        mixed.contains(&KEY_1) && mixed.contains(&KEY_2),
        "both key ids are live mid-rotation: {mixed:?}"
    );
    assert_eq!(
        reads(&store, &artifacts),
        before,
        "reads accept both key ids"
    );

    let during = publish_capture(&store, 9, b"<p>REKEY-DURING example.com</p>");
    let status = store.rekey_tenant(AGENT, ONE).expect("finish");
    assert_eq!(
        status.to_key_id, KEY_2,
        "the rotation resumed, not restarted"
    );
    let after = ids(&tenant_sealed(&store, AGENT));
    assert!(after.iter().all(|id| *id == KEY_2), "{after:?}");
    assert!(
        store.artifact(during).expect("read").is_some(),
        "mid-rotation capture"
    );
    let mut all = artifacts;
    all.push(during);
    assert_eq!(reads(&store, &all).artifacts.len(), 4, "four captures");
}

#[test]
fn begin_while_rotating_is_refused_and_batch_without_rotation_is_refused() {
    let fixture = Fixture::new();
    let (store, _) = populated(&fixture);
    let error = store.rekey_batch(AGENT, ONE).expect_err("nothing to run");
    assert!(
        matches!(error, Error::RekeyNotInProgress { tenant, .. } if tenant == AGENT),
        "{error:?}"
    );
    store.begin_rekey(AGENT).expect("begin");
    let error = store.begin_rekey(AGENT).expect_err("already rotating");
    assert!(
        matches!(error, Error::RekeyInProgress { tenant, .. } if tenant == AGENT),
        "{error:?}"
    );
    store.rekey_tenant(AGENT, ONE).expect("finish");
    let error = store.rekey_batch(AGENT, ONE).expect_err("finished");
    assert!(
        matches!(error, Error::RekeyNotInProgress { .. }),
        "{error:?}"
    );
    assert!(
        store.rekeys_in_progress().expect("list").is_empty(),
        "none open"
    );
}

#[test]
fn rekey_of_an_unknown_tenant_is_missing() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let stranger = syntheke::TenantId::from_bytes(*b"TENANT-STRANGER1");
    let error = store.begin_rekey(stranger).expect_err("unknown");
    assert!(matches!(error, Error::TenantMissing { .. }), "{error:?}");
    assert_eq!(
        store.rekey_status(stranger).expect("status"),
        None,
        "no record"
    );
}

/// Crashes the `nth` time the rotation reaches `boundary`/`phase`,
/// reopens, checks that no record was lost, resumes, and checks the end
/// state.
fn crash_and_resume(boundary: Boundary, phase: Phase, nth: u32) {
    let case = format!("{phase} {boundary} #{nth}");
    let fixture = Fixture::new();
    let (store, artifacts) = populated(&fixture);
    let before = reads(&store, &artifacts);
    let expected = expected_agent_records(&store);
    drop(store);

    let store = fixture.reopen_with(CrashAtNth::new(boundary, phase, nth));
    let error = store
        .rekey_tenant(AGENT, ONE)
        .expect_err("the failpoint fires");
    assert!(
        matches!(error, Error::InjectedCrash { boundary: b, phase: p, .. } if b == boundary && p == phase),
        "{case}: {error:?}"
    );
    drop(store);

    let store = fixture.reopen();
    let sealed = tenant_sealed(&store, AGENT);
    assert_eq!(sealed.len(), expected, "{case}: every record still opens");
    assert!(
        ids(&sealed).iter().all(|id| *id == KEY_1 || *id == KEY_2),
        "{case}: each record is under one of the two keys"
    );
    assert_eq!(
        reads(&store, &artifacts),
        before,
        "{case}: reads after the crash"
    );
    let began = !(boundary == Boundary::RekeyBegin && phase == Phase::BeforeCommit);
    let open = store.rekeys_in_progress().expect("list");
    let retired = boundary == Boundary::RekeyRetire && phase == Phase::AfterCommit;
    assert_eq!(
        open.len(),
        usize::from(began && !retired),
        "{case}: {open:?}"
    );

    let status = if retired {
        store.rekey_status(AGENT).expect("status").expect("record")
    } else {
        store.rekey_tenant(AGENT, ONE).expect("resume")
    };
    assert_eq!(
        (status.from_key_id, status.to_key_id, status.done),
        (KEY_1, KEY_2, true),
        "{case}: resumed the same rotation"
    );
    let after = tenant_sealed(&store, AGENT);
    assert_eq!(after.len(), expected, "{case}: nothing lost");
    assert!(
        ids(&after).iter().all(|id| *id == KEY_2),
        "{case}: all re-sealed"
    );
    let old = keys::data_key(store.keys.index(), AGENT, KEY_1).expect("key");
    assert!(
        raw(&store, Keyspace::Keys, &old).is_none(),
        "{case}: old key retired"
    );
    assert_eq!(
        reads(&store, &artifacts),
        before,
        "{case}: reads at the end"
    );
}

#[test]
fn crash_at_every_rekey_commit_resumes_without_loss() {
    for phase in Phase::ALL {
        crash_and_resume(Boundary::RekeyBegin, phase, 1);
        for nth in [1, 5, 11] {
            crash_and_resume(Boundary::RekeyBatch, phase, nth);
        }
        crash_and_resume(Boundary::RekeyRetire, phase, 1);
    }
}
