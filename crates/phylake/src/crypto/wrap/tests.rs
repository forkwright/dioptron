#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use super::*;
use crate::Error;
use crate::crypto::test_support::{FailingEntropy, FixedNonce};
use crate::crypto::test_support::{ROOT_BYTES, store_keys, tenant_key};
use crate::crypto::{StoreSalt, TenantDataKey};
use crate::keyfile::RootKey;

const TENANT_A: [u8; TENANT_ID_LEN] = *b"tenant-marker-A1";
const TENANT_B: [u8; TENANT_ID_LEN] = *b"tenant-marker-B2";

#[test]
fn wrap_unwrap_round_trips() {
    let store = store_keys();
    let key = tenant_key(42, 0x7e);
    let wrapped = store.wrap_tenant_key(&TENANT_A, &key).expect("wrap");
    assert_eq!(wrapped.len(), WRAPPED_KEY_LEN, "fixed wrapped length");
    let back = store
        .unwrap_tenant_key(&TENANT_A, &wrapped)
        .expect("unwrap");
    assert_eq!(back.id(), KeyId::new(42), "key id preserved");
    assert_eq!(back.expose(), key.expose(), "key bytes preserved");
    assert!(
        !wrapped.windows(KEY_LEN).any(|w| w == key.expose()),
        "plaintext data key absent from wrapped bytes"
    );
}

// WHY: expected bytes computed outside this crate with the same
// independent Python reference as the seal known answer (see
// `seal::tests::seal_matches_known_answer_for_documented_layout`), over
// the documented wrapped layout and additional data.
#[test]
fn wrap_matches_known_answer_for_documented_layout() {
    let store = store_keys();
    let wrapped = store
        .wrap_tenant_key_with(&TENANT_A, &tenant_key(42, 0x7e), &mut FixedNonce)
        .expect("wrap");
    let expected = concat!(
        "0100",
        "01000000",
        "2a000000",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7",
        "5e7c059a7b24e29675bf1ab6a3c6a6f33aee4b2f9fedf1322923ff9017dba74e",
        "c287d1ff0fc9b9d69ddcc13a50464652",
    );
    assert_eq!(
        crate::crypto::test_support::hex(&wrapped),
        expected,
        "wrapped bytes match the reference"
    );
}

#[test]
fn unwrap_under_wrong_tenant_fails() {
    let store = store_keys();
    let wrapped = store
        .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
        .expect("wrap");
    let err = store
        .unwrap_tenant_key(&TENANT_B, &wrapped)
        .expect_err("wrong tenant");
    assert!(matches!(err, Error::TenantKeyUnwrap { .. }), "got {err:?}");
}

#[test]
fn unwrap_with_rewritten_data_key_id_fails() {
    let store = store_keys();
    let mut wrapped = store
        .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
        .expect("wrap");
    if let Some(b) = wrapped.get_mut(6) {
        *b ^= 1;
    }
    let err = store
        .unwrap_tenant_key(&TENANT_A, &wrapped)
        .expect_err("id rewritten");
    assert!(matches!(err, Error::TenantKeyUnwrap { .. }), "got {err:?}");
}

#[test]
fn unwrap_with_other_root_key_fails() {
    let store = store_keys();
    let wrapped = store
        .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
        .expect("wrap");
    let mut other = ROOT_BYTES;
    other[0] ^= 1;
    let other = StoreKeys::derive(
        &RootKey::from_bytes(other),
        store.root_key_id(),
        &StoreSalt::from_bytes([0x22; 32]),
    )
    .expect("derive");
    let err = other
        .unwrap_tenant_key(&TENANT_A, &wrapped)
        .expect_err("other root");
    assert!(matches!(err, Error::TenantKeyUnwrap { .. }), "got {err:?}");
}

#[test]
fn unwrap_rejects_unknown_kek_id_version_and_length() {
    let store = store_keys();
    let wrapped = store
        .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
        .expect("wrap");

    let mut other_kek = wrapped.clone();
    if let Some(b) = other_kek.get_mut(2) {
        *b ^= 1;
    }
    let err = store
        .unwrap_tenant_key(&TENANT_A, &other_kek)
        .expect_err("kek id");
    assert!(matches!(err, Error::UnknownKeyId { .. }), "got {err:?}");

    let mut other_version = wrapped.clone();
    if let Some(b) = other_version.get_mut(0) {
        *b = 9;
    }
    let err = store
        .unwrap_tenant_key(&TENANT_A, &other_version)
        .expect_err("version");
    assert!(
        matches!(err, Error::UnsupportedRecordVersion { found: 9, .. }),
        "got {err:?}"
    );

    let short = wrapped.get(..WRAPPED_KEY_LEN - 1).expect("prefix");
    let err = store
        .unwrap_tenant_key(&TENANT_A, short)
        .expect_err("short");
    assert!(matches!(err, Error::Malformed { .. }), "got {err:?}");
}

#[test]
fn unwrap_rejects_tampered_nonce_ciphertext_and_tag() {
    let store = store_keys();
    let wrapped = store
        .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
        .expect("wrap");
    for index in [10, 10 + NONCE_LEN, WRAPPED_KEY_LEN - 1] {
        let mut tampered = wrapped.clone();
        if let Some(b) = tampered.get_mut(index) {
            *b ^= 0x80;
        }
        let err = store
            .unwrap_tenant_key(&TENANT_A, &tampered)
            .expect_err("tampered");
        assert!(
            matches!(err, Error::TenantKeyUnwrap { .. }),
            "byte {index}: {err:?}"
        );
    }
}

#[test]
fn wrap_surfaces_entropy_failure() {
    let store = store_keys();
    let err = store.wrap_tenant_key_with(&TENANT_A, &tenant_key(1, 0x7e), &mut FailingEntropy);
    assert!(
        matches!(err, Err(Error::Entropy { .. })),
        "entropy failure surfaces"
    );
}

/// Addressing subkeys of a fixed tenant data key, and a wrapping of them.
fn wrapped_address() -> (crate::crypto::AddressKeys, Vec<u8>) {
    let (_, address) = tenant_key(1, 0x7e).derive().expect("derive").split();
    let wrapped = store_keys()
        .wrap_address_keys_with(&TENANT_A, &address, &mut OsEntropy)
        .expect("wrap");
    (address, wrapped)
}

#[test]
fn address_keys_round_trip_and_hide_the_subkeys() {
    let (address, wrapped) = wrapped_address();
    assert_eq!(wrapped.len(), WRAPPED_ADDRESS_LEN, "fixed wrapped length");
    let back = store_keys()
        .unwrap_address_keys(&TENANT_A, &wrapped)
        .expect("unwrap");
    assert_eq!(
        back.index().expose(),
        address.index().expose(),
        "index subkey"
    );
    assert_eq!(
        back.blob_addr().expose(),
        address.blob_addr().expose(),
        "blob-address subkey"
    );
    for subkey in [address.index().expose(), address.blob_addr().expose()] {
        assert!(
            !wrapped.windows(KEY_LEN).any(|w| w == subkey),
            "plaintext subkey absent from wrapped bytes"
        );
    }
}

#[test]
fn address_keys_bind_tenant_and_key_id_and_check_shape() {
    let (_, wrapped) = wrapped_address();
    let store = store_keys();
    let err = store
        .unwrap_address_keys(&TENANT_B, &wrapped)
        .expect_err("another tenant");
    assert!(matches!(err, Error::TenantKeyUnwrap { .. }), "{err:?}");

    let other_root = StoreKeys::derive(
        &RootKey::from_bytes(ROOT_BYTES),
        KeyId::new(2),
        &StoreSalt::from_bytes([0x22; 32]),
    )
    .expect("derive");
    let err = other_root
        .unwrap_address_keys(&TENANT_A, &wrapped)
        .expect_err("another root key id");
    assert!(matches!(err, Error::UnknownKeyId { .. }), "{err:?}");

    let err = store
        .unwrap_address_keys(&TENANT_A, wrapped.get(1..).expect("tail"))
        .expect_err("short");
    assert!(matches!(err, Error::Malformed { .. }), "{err:?}");

    let mut versioned = wrapped;
    *versioned.first_mut().expect("version byte") = 9;
    let err = store
        .unwrap_address_keys(&TENANT_A, &versioned)
        .expect_err("version");
    assert!(
        matches!(err, Error::UnsupportedRecordVersion { found: 9, .. }),
        "{err:?}"
    );

    let data_key = store
        .wrap_tenant_key(&TENANT_A, &tenant_key(1, 0x7e))
        .expect("wrap");
    let err = store
        .unwrap_address_keys(&TENANT_A, &data_key)
        .expect_err("a wrapped data key is not addressing subkeys");
    assert!(matches!(err, Error::Malformed { .. }), "{err:?}");
}

#[test]
fn address_wrap_surfaces_entropy_failure() {
    let (address, _) = wrapped_address();
    let err = store_keys().wrap_address_keys_with(&TENANT_A, &address, &mut FailingEntropy);
    assert!(matches!(err, Err(Error::Entropy { .. })), "{err:?}");
}

#[test]
fn unwrapped_key_derives_same_subkeys() {
    let store = store_keys();
    let key = TenantDataKey::generate(KeyId::new(3)).expect("generate");
    let wrapped = store.wrap_tenant_key(&TENANT_A, &key).expect("wrap");
    let back = store
        .unwrap_tenant_key(&TENANT_A, &wrapped)
        .expect("unwrap");
    let body = b"same body";
    assert_eq!(
        key.derive()
            .and_then(|k| k.blob_address(body))
            .expect("orig"),
        back.derive()
            .and_then(|k| k.blob_address(body))
            .expect("back"),
        "unwrapped key is the same key"
    );
}
