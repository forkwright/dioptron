#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use std::io::Write as _;

use sha2::{Digest, Sha256};

use super::*;
use crate::Error;
use crate::crypto::test_support::{FailingEntropy, FixedNonce, unhex};
use crate::crypto::test_support::{store_keys, tenant_key};

const SCHEMA: SchemaVersion = SchemaVersion::new(1);
const KIND: RecordKind = RecordKind::new(3);
const RECORD_KEY: &[u8] = b"record-key-0001";

fn ctx(record_key: &[u8]) -> SealContext<'_> {
    SealContext::new(SCHEMA, Keyspace::Artifacts, KIND, record_key)
}

/// A tenant meta key and a value sealed under it at `ctx(RECORD_KEY)`.
fn fixture() -> (crate::crypto::TenantKeys, Vec<u8>) {
    let keys = tenant_key(5, 0x3c).derive().expect("derive");
    let sealed = seal(keys.meta(), &ctx(RECORD_KEY), b"fixture plaintext").expect("seal");
    (keys, sealed)
}

// draft-irtf-cfrg-xchacha-03, Appendix A.3.1 (AEAD_XChaCha20_Poly1305).
#[test]
fn encrypt_matches_xchacha_draft_a31() {
    let key: [u8; 32] = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        .try_into()
        .expect("32-byte key");
    let nonce: [u8; NONCE_LEN] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into()
        .expect("24-byte nonce");
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer \
        you only one tip for the future, sunscreen would be it.";
    let expected = unhex(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13b52e",
        "c0875924c1c7987947deafd8780acf49",
    ));
    let key = SubKey::from_bytes(key);
    let got = encrypt(&key, &nonce, &aad, plaintext).expect("encrypt");
    assert_eq!(got, expected, "ciphertext and tag match draft A.3.1");
}

// WHY: expected bytes computed outside this crate with a pure-Python
// HChaCha20 + ChaCha20-Poly1305 (RFC 8439) checked against RFC 8439
// 2.8.2 and draft-irtf-cfrg-xchacha-03 2.2.1 and A.3.1, over the
// documented header and additional-data layout. A change to field
// order, widths, endianness, or the label fails here.
#[test]
fn seal_matches_known_answer_for_documented_layout() {
    let store = store_keys();
    let sealed = seal_with(
        store.meta(),
        &ctx(RECORD_KEY),
        b"fixture plaintext",
        &mut FixedNonce,
    )
    .expect("seal");
    let expected = unhex(concat!(
        "0100",
        "01000000",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7",
        "ea263ed10cb5011ca0b871d745803e48ee",
        "3877ac1baa09c7bd08d22a6a3f945781",
    ));
    assert_eq!(sealed, expected, "sealed bytes match the reference");
}

#[test]
fn seal_open_round_trips() {
    let store = store_keys();
    let plaintext = b"{\"url\":\"https://example.com/\"}";
    let sealed = seal(store.meta(), &ctx(RECORD_KEY), plaintext).expect("seal");
    assert_eq!(
        sealed.len(),
        MIN_SEALED_LEN + plaintext.len(),
        "header + ciphertext + tag"
    );
    let opened = open(&[store.meta()], &ctx(RECORD_KEY), &sealed).expect("open");
    assert_eq!(opened.as_slice(), plaintext, "round trip");
}

#[test]
fn seal_open_round_trips_empty_plaintext() {
    let store = store_keys();
    let sealed = seal(store.meta(), &ctx(RECORD_KEY), b"").expect("seal");
    assert_eq!(
        sealed.len(),
        MIN_SEALED_LEN,
        "empty plaintext is header + tag"
    );
    let opened = open(&[store.meta()], &ctx(RECORD_KEY), &sealed).expect("open");
    assert!(opened.is_empty(), "empty round trip");
}

#[test]
fn header_carries_version_and_key_id() {
    let tenant = tenant_key(0x0102_0304, 0x3c).derive().expect("derive");
    let sealed = seal(tenant.blob(), &ctx(RECORD_KEY), b"x").expect("seal");
    assert_eq!(sealed.get(..2), Some(&[1_u8, 0][..]), "rec_ver 1 LE");
    assert_eq!(sealed.get(2..6), Some(&[4_u8, 3, 2, 1][..]), "key id LE");
}

#[test]
fn nonces_differ_between_seals_of_same_value() {
    let store = store_keys();
    let a = seal(store.meta(), &ctx(RECORD_KEY), b"same").expect("a");
    let b = seal(store.meta(), &ctx(RECORD_KEY), b"same").expect("b");
    assert_ne!(a.get(6..30), b.get(6..30), "fresh nonce per seal");
    assert_ne!(a, b, "distinct ciphertexts");
}

#[test]
fn tampering_nonce_ciphertext_or_tag_fails() {
    let (keys, sealed) = fixture();
    let regions = [
        ("nonce start", 6),
        ("nonce end", SEALED_HEADER_LEN - 1),
        ("ciphertext", SEALED_HEADER_LEN),
        ("tag start", sealed.len() - TAG_LEN),
        ("tag end", sealed.len() - 1),
    ];
    for (name, index) in regions {
        let mut tampered = sealed.clone();
        if let Some(b) = tampered.get_mut(index) {
            *b ^= 0x01;
        }
        let err = open(&[keys.meta()], &ctx(RECORD_KEY), &tampered).expect_err(name);
        assert!(matches!(err, Error::Open { .. }), "{name}: {err:?}");
    }
}

#[test]
fn tampering_header_fails() {
    let (keys, sealed) = fixture();
    let mut version = sealed.clone();
    if let Some(b) = version.get_mut(0) {
        *b = 2;
    }
    let err = open(&[keys.meta()], &ctx(RECORD_KEY), &version).expect_err("version");
    assert!(
        matches!(err, Error::UnsupportedRecordVersion { found: 2, .. }),
        "{err:?}"
    );

    let mut key_id = sealed;
    if let Some(b) = key_id.get_mut(2) {
        *b ^= 0x01;
    }
    let err = open(&[keys.meta()], &ctx(RECORD_KEY), &key_id).expect_err("key id");
    assert!(matches!(err, Error::UnknownKeyId { .. }), "{err:?}");
}

#[test]
fn rewritten_key_id_fails_even_when_that_id_is_present() {
    // Tenant keys 5 and 4 hold the same data-key bytes, so only the key
    // id in the additional data distinguishes them.
    let (keys, mut sealed) = fixture();
    let impostor = tenant_key(4, 0x3c).derive().expect("derive");
    if let Some(b) = sealed.get_mut(2) {
        *b = 4;
    }
    let err =
        open(&[keys.meta(), impostor.meta()], &ctx(RECORD_KEY), &sealed).expect_err("aad key id");
    assert!(matches!(err, Error::Open { .. }), "{err:?}");
}

#[test]
fn truncated_value_is_malformed() {
    let (keys, sealed) = fixture();
    for len in [0, 1, SEALED_HEADER_LEN, MIN_SEALED_LEN - 1] {
        let short = sealed.get(..len).expect("prefix");
        let err = open(&[keys.meta()], &ctx(RECORD_KEY), short).expect_err("short");
        assert!(matches!(err, Error::Malformed { .. }), "len {len}: {err:?}");
    }
    let cut = sealed.get(..MIN_SEALED_LEN).expect("prefix");
    let err = open(&[keys.meta()], &ctx(RECORD_KEY), cut).expect_err("cut ciphertext");
    assert!(
        matches!(err, Error::Open { .. }),
        "cut body fails auth: {err:?}"
    );
}

#[test]
fn aad_mismatch_on_each_component_fails() {
    let (keys, sealed) = fixture();
    let ks = Keyspace::Artifacts;
    let variants = [
        (
            "schema version",
            SealContext::new(SchemaVersion::new(2), ks, KIND, RECORD_KEY),
        ),
        (
            "record kind",
            SealContext::new(SCHEMA, ks, RecordKind::new(4), RECORD_KEY),
        ),
        (
            "keyspace",
            SealContext::new(SCHEMA, Keyspace::Blobs, KIND, RECORD_KEY),
        ),
        (
            "record key",
            SealContext::new(SCHEMA, ks, KIND, b"record-key-0002"),
        ),
    ];
    for (name, other) in variants {
        let err = open(&[keys.meta()], &other, &sealed).expect_err(name);
        assert!(matches!(err, Error::Open { .. }), "{name}: {err:?}");
    }
    // NOTE: the key id component is covered by
    // `rewritten_key_id_fails_even_when_that_id_is_present`.
}

#[test]
fn length_prefix_separates_keyspace_and_record_key() {
    // WHY: an unprefixed encoding would make these two contexts collide
    // ("audit" ‖ "_stubX" == "audit_stub" ‖ "X").
    let store = store_keys();
    let a = SealContext::new(SCHEMA, Keyspace::Audit, KIND, b"_stubX");
    let b = SealContext::new(SCHEMA, Keyspace::AuditStub, KIND, b"X");
    let sealed = seal(store.meta(), &a, b"audit row").expect("seal");
    let err = open(&[store.meta()], &b, &sealed).expect_err("collision refused");
    assert!(matches!(err, Error::Open { .. }), "{err:?}");
    let aad_a = a.aad(KeyId::new(1)).expect("a");
    let aad_b = b.aad(KeyId::new(1)).expect("b");
    assert_ne!(aad_a, aad_b, "encodings differ");
}

#[test]
fn swapping_values_between_record_keys_fails() {
    let store = store_keys();
    let v1 = seal(store.meta(), &ctx(b"record-1"), b"value one").expect("v1");
    let v2 = seal(store.meta(), &ctx(b"record-2"), b"value two").expect("v2");
    let err = open(&[store.meta()], &ctx(b"record-1"), &v2).expect_err("v2 at k1");
    assert!(matches!(err, Error::Open { .. }), "{err:?}");
    let err = open(&[store.meta()], &ctx(b"record-2"), &v1).expect_err("v1 at k2");
    assert!(matches!(err, Error::Open { .. }), "{err:?}");
}

#[test]
fn wrong_key_with_same_id_fails() {
    let store = store_keys();
    let sealed = seal(store.meta(), &ctx(RECORD_KEY), b"meta row").expect("seal");
    // Same root key id, different subkey (audit instead of meta).
    let err = open(&[store.audit()], &ctx(RECORD_KEY), &sealed).expect_err("wrong key");
    assert!(matches!(err, Error::Open { .. }), "{err:?}");
    let other_tenant = tenant_key(1, 0x99).derive().expect("derive");
    let err = open(&[other_tenant.meta()], &ctx(RECORD_KEY), &sealed).expect_err("tenant");
    assert!(matches!(err, Error::Open { .. }), "{err:?}");
}

#[test]
fn open_selects_key_by_header_id_during_rotation() {
    let old = tenant_key(1, 0x01).derive().expect("old");
    let new = tenant_key(2, 0x02).derive().expect("new");
    let sealed_old = seal(old.meta(), &ctx(RECORD_KEY), b"old").expect("old");
    let sealed_new = seal(new.meta(), &ctx(RECORD_KEY), b"new").expect("new");
    let both = [old.meta(), new.meta()];
    let got_old = open(&both, &ctx(RECORD_KEY), &sealed_old).expect("old opens");
    let got_new = open(&both, &ctx(RECORD_KEY), &sealed_new).expect("new opens");
    assert_eq!(got_old.as_slice(), b"old", "old key id");
    assert_eq!(got_new.as_slice(), b"new", "new key id");
    let err = open(&[new.meta()], &ctx(RECORD_KEY), &sealed_old).expect_err("retired");
    assert!(
        matches!(err, Error::UnknownKeyId { found, .. } if found == KeyId::new(1)),
        "{err:?}"
    );
}

#[test]
fn oversized_plaintext_and_record_key_are_refused() {
    let err = check_plaintext_len(MAX_PLAINTEXT_LEN + 1).expect_err("too large");
    assert!(matches!(err, Error::PlaintextTooLarge { .. }), "{err:?}");
    assert!(
        check_plaintext_len(MAX_PLAINTEXT_LEN).is_ok(),
        "bound is inclusive"
    );

    let store = store_keys();
    let long_key = vec![b'k'; usize::from(u16::MAX) + 1];
    let err = seal(store.meta(), &ctx(&long_key), b"x").expect_err("long record key");
    assert!(
        matches!(
            err,
            Error::AadComponentTooLong {
                component: "record key",
                ..
            }
        ),
        "{err:?}"
    );
    let max_key = vec![b'k'; usize::from(u16::MAX)];
    let sealed = seal(store.meta(), &ctx(&max_key), b"x").expect("65535-byte key seals");
    assert!(
        open(&[store.meta()], &ctx(&max_key), &sealed).is_ok(),
        "and opens"
    );
}

#[test]
fn seal_surfaces_entropy_failure() {
    let store = store_keys();
    let err = seal_with(store.meta(), &ctx(RECORD_KEY), b"x", &mut FailingEntropy);
    assert!(
        matches!(err, Err(Error::Entropy { .. })),
        "entropy failure surfaces"
    );
}

#[test]
fn open_failure_display_carries_no_plaintext_or_key() {
    let (keys, mut sealed) = fixture();
    if let Some(b) = sealed.last_mut() {
        *b ^= 1;
    }
    let err = open(&[keys.meta()], &ctx(RECORD_KEY), &sealed).expect_err("tampered");
    let shown = format!("{err} {err:?}");
    assert!(
        !shown.contains("fixture plaintext"),
        "no plaintext: {shown}"
    );
    let key = keys.meta().subkey().expose();
    let hex = crate::crypto::test_support::hex(key);
    assert!(!shown.contains(&hex), "no key hex: {shown}");
}

fn count_hits(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[test]
fn sealed_bytes_on_disk_contain_no_plaintext_markers() {
    const PLAINTEXT_MARKER: &[u8] = b"PHYLAKE-FIXTURE-PLAINTEXT-7f3a";
    const URL_MARKER: &[u8] = b"https://example.com/phylake-marker/7f3a";
    const TENANT_ID: [u8; 16] = *b"tenant-marker-7f";
    let body = [
        b"<html><body>".as_slice(),
        PLAINTEXT_MARKER,
        b" fetched from ",
        URL_MARKER,
        b" for ",
        &TENANT_ID,
        b"</body></html>",
    ]
    .concat();
    let digest: [u8; 32] = Sha256::digest(&body).into();

    let store = store_keys();
    let data_key = tenant_key(8, 0x6d);
    let tenant = data_key.derive().expect("derive");
    let address = tenant.blob_address(&body).expect("address");
    let blob_ctx = SealContext::new(SCHEMA, Keyspace::Blobs, KIND, address.as_bytes());
    let blob = seal(tenant.blob(), &blob_ctx, &body).expect("seal blob");
    let side = [
        URL_MARKER,
        &TENANT_ID,
        crate::crypto::provenance_digest(&body).as_bytes(),
        address.as_bytes(),
    ]
    .concat();
    let side_ctx = SealContext::new(SCHEMA, Keyspace::Artifacts, KIND, b"artifact-01");
    let record = seal(tenant.meta(), &side_ctx, &side).expect("seal side record");
    let wrapped = store.wrap_tenant_key(&TENANT_ID, &data_key).expect("wrap");
    let check = store.key_check().expect("check");

    let dir = tempfile::tempdir().expect("tempdir");
    let mut file = std::fs::File::create(dir.path().join("store.bin")).expect("create");
    for chunk in [
        blob.as_slice(),
        &record,
        &wrapped,
        address.as_bytes(),
        check.as_bytes(),
    ] {
        file.write_all(chunk).expect("write");
    }
    file.sync_all().expect("sync");
    drop(file);

    let mut scanned = 0_usize;
    for entry in std::fs::read_dir(dir.path()).expect("read_dir") {
        let raw = std::fs::read(entry.expect("entry").path()).expect("read");
        scanned += 1;
        for (name, needle) in [
            ("plaintext marker", PLAINTEXT_MARKER),
            ("url marker", URL_MARKER),
            ("tenant id", &TENANT_ID[..]),
            ("plaintext sha-256", &digest[..]),
            ("tenant data key", &data_key.expose()[..]),
            ("html prefix", b"<html>"),
        ] {
            assert_eq!(count_hits(&raw, needle), 0, "{name} found on disk");
        }
    }
    assert_eq!(scanned, 1, "scanned the store file");
    // WHY: the markers are present in the plaintext, so zero hits above
    // means sealing hid them, not that the fixture lacked them.
    assert_eq!(
        count_hits(&body, PLAINTEXT_MARKER),
        1,
        "marker in plaintext"
    );
    assert_eq!(
        count_hits(&side, &digest),
        1,
        "digest in sealed side record"
    );
}
