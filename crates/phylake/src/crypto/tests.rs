#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use super::*;
use crate::Error;

use test_support::{FailingEntropy, ShortEntropy, unhex};

// RFC 5869 Appendix A, Test Case 1 (basic SHA-256).
#[test]
fn hkdf_matches_rfc5869_case_1() {
    let ikm = [0x0b_u8; 22];
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let expected = unhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
    let hk = hkdf_extract(Some(&salt), &ikm);
    let mut okm = [0_u8; 42];
    hkdf_expand(&hk, &info, &mut okm).expect("expand");
    assert_eq!(okm.to_vec(), expected, "RFC 5869 A.1 OKM");
}

// RFC 5869 Appendix A, Test Case 3 (zero-length salt and info).
#[test]
fn hkdf_matches_rfc5869_case_3() {
    let ikm = [0x0b_u8; 22];
    let expected = unhex(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
    let hk = hkdf_extract(Some(&[]), &ikm);
    let mut okm = [0_u8; 42];
    hkdf_expand(&hk, &[], &mut okm).expect("expand");
    assert_eq!(okm.to_vec(), expected, "RFC 5869 A.3 OKM");
}

#[test]
fn hkdf_expand_rejects_oversized_output() {
    let hk = hkdf_extract(None, &[1_u8; 32]);
    let mut okm = vec![0_u8; 255 * 32 + 1];
    let err = hkdf_expand(&hk, b"x", &mut okm).expect_err("over 255 blocks refused");
    assert!(matches!(err, Error::KeyMaterial { .. }), "got {err:?}");
}

// RFC 4231 Section 4.2, Test Case 1.
#[test]
fn hmac_matches_rfc4231_case_1() {
    let key = [0x0b_u8; 20];
    let expected = unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    let tag = hmac_sha256(&key, &[b"Hi There"]).expect("hmac");
    assert_eq!(tag.to_vec(), expected, "RFC 4231 4.2 HMAC-SHA-256");
}

// RFC 4231 Section 4.3, Test Case 2, with the message split across parts.
#[test]
fn hmac_matches_rfc4231_case_2_across_parts() {
    let expected = unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    let tag = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]).expect("hmac");
    assert_eq!(tag.to_vec(), expected, "RFC 4231 4.3 HMAC-SHA-256");
}

#[test]
fn hmac_verify_accepts_match_and_rejects_mismatch() {
    let key = [0x0b_u8; 20];
    let good = unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert!(
        hmac_sha256_verify(&key, b"Hi There", &good).expect("verify"),
        "match"
    );
    let mut bad = good.clone();
    if let Some(last) = bad.last_mut() {
        *last ^= 1;
    }
    assert!(
        !hmac_sha256_verify(&key, b"Hi There", &bad).expect("verify"),
        "flip"
    );
    assert!(
        !hmac_sha256_verify(&key, b"Hi There", good.get(..31).expect("prefix")).expect("verify"),
        "truncated tag rejected"
    );
}

// FIPS 180-2 Appendix B.1 ("abc").
#[test]
fn provenance_digest_is_plain_sha256() {
    let expected = unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        provenance_digest(b"abc").as_bytes().to_vec(),
        expected,
        "SHA-256(abc)"
    );
}

#[test]
fn provenance_digest_debug_is_redacted() {
    let shown = format!("{:?}", provenance_digest(b"abc"));
    assert_eq!(shown, "ProvenanceDigest([REDACTED])", "redacted");
}

#[test]
fn keyspace_names_are_distinct() {
    let all = [
        Keyspace::Meta,
        Keyspace::Keys,
        Keyspace::Tenants,
        Keyspace::Grants,
        Keyspace::Revocations,
        Keyspace::Sessions,
        Keyspace::Invocations,
        Keyspace::Idem,
        Keyspace::Ledgers,
        Keyspace::Artifacts,
        Keyspace::Blobs,
        Keyspace::SessionIndex,
        Keyspace::Audit,
        Keyspace::AuditStub,
        Keyspace::Rekey,
    ];
    let names: std::collections::HashSet<_> = all.iter().map(|k| k.name()).collect();
    assert_eq!(names.len(), all.len(), "every keyspace name is unique");
}

#[test]
fn os_entropy_fills_buffer() {
    let a: [u8; 32] = random_array(&mut OsEntropy).expect("draw");
    let b: [u8; 32] = random_array(&mut OsEntropy).expect("draw");
    assert_ne!(a, b, "two 256-bit draws differ");
}

#[test]
fn random_array_surfaces_entropy_failure() {
    let err = random_array::<24>(&mut FailingEntropy);
    assert!(matches!(err, Err(Error::Entropy { .. })), "got {err:?}");
}

#[test]
fn random_array_rejects_short_fill() {
    let err = random_array::<24>(&mut ShortEntropy);
    assert!(
        matches!(
            err,
            Err(Error::Malformed {
                what: "entropy draw",
                len: 1,
                ..
            })
        ),
        "got {err:?}"
    );
}
