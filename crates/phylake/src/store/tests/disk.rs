//! What reaches the disk: a raw scan of every file for plaintext, and the
//! keyed record keys' tenant separation.

use sha2::{Digest as _, Sha256};
use syntheke::{Capability, IdempotencyKey};

use crate::Error;
use crate::store::codec::StoredRecord as _;
use crate::store::record_key;
use crate::store::records::InvocationRecord;
use crate::store::test_support::{
    ACTUAL, AGENT, ENVELOPE, Fixture, G_AGENT, OPERATOR, OTHER, S_AGENT, TARGET, artifact, capture,
    invocation, occurrences, read_tree, source,
};
use crate::store::{Begin, Intent, SettleOutcome, Transfer, slot};

/// The idempotency key the scanned capture uses.
const IDEM_MARKER: &[u8] = b"IDEMPOTENCY-MARKER-7f3a-0001";

/// The text view the scanned capture stores.
const TEXT_MARKER: &str = "TEXT-VIEW-MARKER-7f3a derived from the envelope";

#[test]
fn raw_disk_holds_no_plaintext_ids_or_digests() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = IdempotencyKey::from_slice(IDEM_MARKER).expect("key");
    let begin = store
        .begin(&Intent::new(
            invocation(1),
            capture(G_AGENT),
            &key,
            [0xd1; 32],
        ))
        .expect("B1");
    assert!(matches!(begin, Begin::Persisted(_)), "{begin:?}");
    store.dispatch(invocation(1)).expect("B2");
    let mut transfer = Transfer::new(ENVELOPE, source(), ACTUAL);
    transfer.text_view = Some(TEXT_MARKER.to_owned());
    store
        .complete_transfer(invocation(1), &transfer)
        .expect("B3");
    store.publish(invocation(1)).expect("B4");
    store
        .settle(invocation(1), SettleOutcome::Success)
        .expect("B5");
    drop(store);

    let digest: [u8; 32] = Sha256::digest(ENVELOPE).into();
    let tenant_texts: Vec<String> = [OPERATOR, AGENT, OTHER]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut needles: Vec<(String, Vec<u8>)> = vec![
        (
            "envelope marker".to_owned(),
            b"PHYLAKE-CUSTODY-PLAINTEXT-7f3a".to_vec(),
        ),
        ("target url".to_owned(), TARGET.as_bytes().to_vec()),
        ("target host".to_owned(), b"example.com".to_vec()),
        ("text view".to_owned(), TEXT_MARKER.as_bytes().to_vec()),
        ("idempotency key".to_owned(), IDEM_MARKER.to_vec()),
        ("envelope sha-256".to_owned(), digest.to_vec()),
        ("session id".to_owned(), S_AGENT.to_bytes().to_vec()),
        ("schema id".to_owned(), b"zetesis.evidence.v1".to_vec()),
    ];
    for tenant in [OPERATOR, AGENT, OTHER] {
        needles.push((format!("tenant bytes {tenant}"), tenant.to_bytes().to_vec()));
    }
    for text in tenant_texts {
        needles.push((format!("tenant text {text}"), text.into_bytes()));
    }

    let files = read_tree(&fixture.path);
    let total: usize = files.iter().map(|(_, bytes)| bytes.len()).sum();
    assert!(total > 0, "the store wrote files");
    for (path, bytes) in &files {
        for (name, needle) in &needles {
            assert_eq!(
                occurrences(bytes, needle),
                0,
                "{name} found in {}",
                path.display()
            );
        }
    }
    // WHY a positive control: the plaintext format tag lives in `meta`, so
    // the scan does read the bytes the store wrote.
    let format_hits: usize = files
        .iter()
        .map(|(_, bytes)| occurrences(bytes, b"dioptron-custody/fjall3"))
        .sum();
    assert!(
        format_hits > 0,
        "the scan sees plaintext that is meant to be there"
    );
    assert_eq!(
        occurrences(ENVELOPE, TARGET.as_bytes()),
        1,
        "the envelope held the url"
    );
}

#[test]
fn identical_inputs_key_differently_per_tenant() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let snapshot = store.db.read_tx();
    let agent = store.tenant_keys(&snapshot, AGENT).expect("agent keys");
    let other = store.tenant_keys(&snapshot, OTHER).expect("other keys");
    let key = IdempotencyKey::from_slice(IDEM_MARKER).expect("key");

    let idem_a =
        record_key::tenant::idem(agent.index(), AGENT, Capability::Capture, &key).expect("idem a");
    let idem_b =
        record_key::tenant::idem(other.index(), OTHER, Capability::Capture, &key).expect("idem b");
    assert_ne!(idem_a, idem_b, "idempotency keys");

    let address_a = agent.blob_address(ENVELOPE).expect("address a");
    let address_b = other.blob_address(ENVELOPE).expect("address b");
    assert_ne!(address_a, address_b, "blob addresses");
    let blob_a = record_key::tenant::blob(agent.index(), AGENT, &address_a).expect("blob a");
    let blob_b = record_key::tenant::blob(other.index(), OTHER, &address_b).expect("blob b");
    assert_ne!(blob_a, blob_b, "blob keys");

    let audit_a = record_key::tenant::audit(agent.index(), AGENT).expect("audit a");
    let audit_b = record_key::tenant::audit(other.index(), OTHER).expect("audit b");
    assert_ne!(audit_a, audit_b, "audit prefixes");

    let session_a =
        record_key::tenant::session_index(agent.index(), AGENT, S_AGENT).expect("index a");
    let session_b =
        record_key::tenant::session_index(other.index(), OTHER, S_AGENT).expect("index b");
    assert_ne!(session_a, session_b, "session index prefixes");

    let artifact_a =
        record_key::tenant::artifact(agent.index(), AGENT, artifact(1)).expect("artifact a");
    let artifact_b =
        record_key::tenant::artifact(other.index(), OTHER, artifact(1)).expect("artifact b");
    assert_ne!(artifact_a, artifact_b, "artifact side record keys");

    // WHY: the tenant id is an input, not only the tenant's key, so the
    // same index key with another tenant id also keys differently.
    let crossed =
        record_key::tenant::idem(agent.index(), OTHER, Capability::Capture, &key).expect("crossed");
    assert_ne!(idem_a, crossed, "the tenant id is hashed in");
    let capability = record_key::tenant::idem(agent.index(), AGENT, Capability::Ingest, &key)
        .expect("capability");
    assert_ne!(idem_a, capability, "the capability is hashed in");
}

#[test]
fn invalid_archive_is_a_decode_error() {
    let error = InvocationRecord::decode(b"not an archive", "invocations").expect_err("garbage");
    assert!(
        matches!(
            error,
            Error::Decode {
                keyspace: "invocations",
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn publish_without_its_pending_record_is_inconsistent() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let key = IdempotencyKey::from_slice(IDEM_MARKER).expect("key");
    store
        .begin(&Intent::new(
            invocation(1),
            capture(G_AGENT),
            &key,
            [0xd1; 32],
        ))
        .expect("B1");
    store.dispatch(invocation(1)).expect("B2");
    let transfer = Transfer::new(ENVELOPE, source(), ACTUAL);
    store
        .complete_transfer(invocation(1), &transfer)
        .expect("B3");

    let pending_key = {
        let snapshot = store.db.read_tx();
        let keys = store.tenant_keys(&snapshot, AGENT).expect("keys");
        record_key::tenant::pending(keys.index(), AGENT, invocation(1)).expect("pending key")
    };
    let mut tx = store.write_tx();
    tx.remove(
        store
            .ks
            .get(slot::PENDING_ARTIFACT.keyspace)
            .expect("keyspace"),
        pending_key,
    );
    tx.commit().expect("remove pending");

    let error = store.publish(invocation(1)).expect_err("pending gone");
    assert!(matches!(error, Error::Inconsistent { .. }), "{error:?}");
    let status = store
        .invocation(invocation(1))
        .expect("read")
        .expect("recorded");
    assert_eq!(
        status.state,
        syntheke::InvocationState::TransferComplete,
        "a failed publish changes nothing"
    );
}

#[test]
fn a_record_moved_to_another_key_does_not_open() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let snapshot = store.db.read_tx();
    let index = store.keys.index();
    let from = record_key::store::grant(index, G_AGENT).expect("key");
    let to = record_key::store::grant(index, crate::store::test_support::G_ROOT).expect("key");
    let grants = store.ks.get(slot::GRANT.keyspace).expect("keyspace");
    let sealed = fjall::Readable::get(&snapshot, grants, from)
        .expect("read")
        .expect("present");
    drop(snapshot);
    let mut tx = store.write_tx();
    tx.insert(grants, to, sealed);
    tx.commit().expect("swap");
    let error = store
        .plan(&capture(G_AGENT))
        .expect_err("the moved grant fails authentication");
    assert!(matches!(error, Error::Authz { .. }), "{error:?}");
}
