#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use super::*;
use crate::Error;
use crate::crypto::test_support::{FailingEntropy, ROOT_BYTES, ROOT_ID, store_keys, tenant_key};

fn all_store_subkeys(keys: &StoreKeys) -> Vec<[u8; 32]> {
    vec![
        *keys.blob.key.expose(),
        *keys.meta.key.expose(),
        *keys.audit.key.expose(),
        *keys.index.expose(),
        *keys.kek.expose(),
        *keys.check.expose(),
    ]
}

#[test]
fn store_subkeys_are_pairwise_distinct_and_differ_from_root() {
    let keys = store_keys();
    let subkeys = all_store_subkeys(&keys);
    let unique: std::collections::HashSet<_> = subkeys.iter().collect();
    assert_eq!(unique.len(), 6, "six distinct subkeys");
    assert!(
        !subkeys.contains(&ROOT_BYTES),
        "no subkey equals the root key"
    );
}

// WHY: expected values computed outside this crate with Python's
// `hmac`/`hashlib` (HKDF per RFC 5869 over the documented labels), so
// the test checks label, salt, and message wiring, not the code against
// itself.
const KAT_BLOB_SUBKEY: &str = "d3e5b2d5529c88ead9447f5944c9e16c4b14c22f32798af461127b57b98db2b0";
const KAT_KEY_CHECK: &str = "d958239cb0a00284e9f9668ee7b517775c68440f96ea9fc6aa2fc6fc451c1c42";
const KAT_BLOB_ADDRESS_ABC: &str =
    "8f363b9c1ee46a604a4666c77b8fec5704a82a63290fbcd2f3acab14a13aede2";

#[test]
fn store_blob_subkey_matches_known_answer() {
    let hex = crate::crypto::test_support::hex(store_keys().blob.key.expose());
    assert_eq!(
        hex, KAT_BLOB_SUBKEY,
        "HKDF(salt, root, \"dioptron/v1/blob\")"
    );
}

#[test]
fn key_check_matches_known_answer() {
    let check = store_keys().key_check().expect("check");
    let hex = crate::crypto::test_support::hex(check.as_bytes());
    assert_eq!(hex, KAT_KEY_CHECK, "HMAC(k_check, \"dioptron-key-check\")");
}

#[test]
fn blob_address_matches_known_answer() {
    let tenant = tenant_key(1, 0xa1).derive().expect("derive");
    let address = tenant.blob_address(b"abc").expect("address");
    let hex = crate::crypto::test_support::hex(address.as_bytes());
    assert_eq!(hex, KAT_BLOB_ADDRESS_ABC, "HMAC(k_blob_addr, \"abc\")");
}

#[test]
fn derive_is_deterministic_and_salt_sensitive() {
    let root = RootKey::from_bytes(ROOT_BYTES);
    let a = StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([1; 32])).expect("a");
    let b = StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([1; 32])).expect("b");
    let c = StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([2; 32])).expect("c");
    assert_eq!(all_store_subkeys(&a), all_store_subkeys(&b), "same inputs");
    assert_ne!(
        all_store_subkeys(&a),
        all_store_subkeys(&c),
        "salt changes keys"
    );
}

#[test]
fn unlock_accepts_matching_key_check() {
    let root = RootKey::from_bytes(ROOT_BYTES);
    let salt = StoreSalt::from_bytes([3; 32]);
    let check = StoreKeys::derive(&root, ROOT_ID, &salt)
        .and_then(|k| k.key_check())
        .expect("check");
    let keys = StoreKeys::unlock(&root, ROOT_ID, &salt, check.as_bytes()).expect("unlock");
    assert_eq!(keys.root_key_id(), ROOT_ID, "unlocked under the root id");
}

#[test]
fn unlock_with_wrong_root_key_is_locked() {
    let salt = StoreSalt::from_bytes([3; 32]);
    let check = StoreKeys::derive(&RootKey::from_bytes(ROOT_BYTES), ROOT_ID, &salt)
        .and_then(|k| k.key_check())
        .expect("check");
    let wrong = RootKey::from_bytes([0x12; 32]);
    let err = StoreKeys::unlock(&wrong, ROOT_ID, &salt, check.as_bytes()).expect_err("locked");
    assert!(matches!(err, Error::StoreLocked { .. }), "got {err:?}");
    let shown = err.to_string();
    assert!(
        !shown.contains("18") && !shown.contains("0x12"),
        "no key bytes: {shown}"
    );
}

#[test]
fn unlock_with_wrong_salt_or_short_check_is_locked() {
    let root = RootKey::from_bytes(ROOT_BYTES);
    let check = StoreKeys::derive(&root, ROOT_ID, &StoreSalt::from_bytes([3; 32]))
        .and_then(|k| k.key_check())
        .expect("check");
    let other_salt = StoreSalt::from_bytes([4; 32]);
    let err = StoreKeys::unlock(&root, ROOT_ID, &other_salt, check.as_bytes());
    assert!(
        matches!(err, Err(Error::StoreLocked { .. })),
        "salt mismatch"
    );
    let salt = StoreSalt::from_bytes([3; 32]);
    let short = check.as_bytes().get(..16).expect("prefix");
    let err = StoreKeys::unlock(&root, ROOT_ID, &salt, short);
    assert!(matches!(err, Err(Error::StoreLocked { .. })), "short check");
    let err = StoreKeys::unlock(&root, ROOT_ID, &salt, &[]);
    assert!(matches!(err, Err(Error::StoreLocked { .. })), "empty check");
}

#[test]
fn tenant_subkeys_are_distinct_and_key_specific() {
    let a = tenant_key(7, 0xa1).derive().expect("a");
    let b = tenant_key(7, 0xb2).derive().expect("b");
    let a_keys = [
        *a.blob.key.expose(),
        *a.blob_addr.expose(),
        *a.meta.key.expose(),
        *a.audit.key.expose(),
        *a.index.expose(),
    ];
    let unique: std::collections::HashSet<_> = a_keys.iter().collect();
    assert_eq!(unique.len(), 5, "five distinct tenant subkeys");
    assert_ne!(a.blob.key.expose(), b.blob.key.expose(), "per-tenant");
    assert_eq!(a.key_id(), KeyId::new(7), "key id carried");
    assert_eq!(
        a.blob().id(),
        KeyId::new(7),
        "sealing key id is the data key id"
    );
}

#[test]
fn blob_address_is_tenant_scoped_and_stable() {
    let a = tenant_key(1, 0xa1).derive().expect("a");
    let b = tenant_key(1, 0xb2).derive().expect("b");
    let body = b"<html>identical capture from https://example.com/</html>";
    let a1 = a.blob_address(body).expect("a1");
    let a2 = a.blob_address(body).expect("a2");
    let b1 = b.blob_address(body).expect("b1");
    assert_eq!(a1, a2, "stable within a tenant");
    assert_ne!(a1, b1, "differs across tenants");
    assert_ne!(
        a1.as_bytes(),
        crate::crypto::provenance_digest(body).as_bytes(),
        "address is not the plain digest"
    );
}

#[test]
fn generate_draws_distinct_keys_and_surfaces_entropy_failure() {
    let a = TenantDataKey::generate(KeyId::new(1)).expect("a");
    let b = TenantDataKey::generate(KeyId::new(1)).expect("b");
    assert_ne!(a.expose(), b.expose(), "independent draws");
    let s1 = StoreSalt::generate().expect("salt");
    let s2 = StoreSalt::generate().expect("salt");
    assert_ne!(s1, s2, "independent salts");
    let err = TenantDataKey::generate_with(KeyId::new(1), &mut FailingEntropy);
    assert!(
        matches!(err, Err(Error::Entropy { .. })),
        "data key entropy"
    );
    let err = StoreSalt::generate_with(&mut FailingEntropy);
    assert!(matches!(err, Err(Error::Entropy { .. })), "salt entropy");
}

fn assert_no_key_bytes(shown: &str, key: &[u8; 32]) {
    let hex = crate::crypto::test_support::hex(key);
    let decimal = format!("{key:?}");
    let decimal_inner = decimal.trim_start_matches('[').trim_end_matches(']');
    assert!(!shown.contains(&hex), "hex key bytes leaked: {shown}");
    assert!(
        !shown.contains(decimal_inner),
        "decimal key bytes leaked: {shown}"
    );
}

#[test]
fn debug_output_contains_no_key_bytes() {
    let store = store_keys();
    let shown = format!("{store:?}");
    assert!(shown.contains("[REDACTED]"), "redaction marker present");
    for key in all_store_subkeys(&store) {
        assert_no_key_bytes(&shown, &key);
    }
    assert_no_key_bytes(&shown, &ROOT_BYTES);

    let data = tenant_key(9, 0xc3);
    let shown = format!("{data:?}");
    assert_no_key_bytes(&shown, data.expose());
    assert!(!shown.contains("195"), "no decimal 0xc3 byte: {shown}");

    let tenant = data.derive().expect("derive");
    let shown = format!("{tenant:?}");
    for key in [
        tenant.blob.key.expose(),
        tenant.blob_addr.expose(),
        tenant.meta.key.expose(),
        tenant.audit.key.expose(),
        tenant.index.expose(),
    ] {
        assert_no_key_bytes(&shown, key);
    }
}

#[test]
fn keyed_hash_is_key_specific() {
    let store = store_keys();
    let tenant = tenant_key(1, 0xa1).derive().expect("derive");
    let s = store.index().keyed_hash(b"tenant-id").expect("store index");
    let t = tenant
        .index()
        .keyed_hash(b"tenant-id")
        .expect("tenant index");
    assert_ne!(s, t, "different index keys give different tags");
}
