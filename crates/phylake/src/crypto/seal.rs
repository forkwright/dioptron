//! Sealed value format.
//!
//! A sealed value is:
//!
//! ```text
//! rec_ver u16 LE ‖ key_id u32 LE ‖ nonce [24] ‖ ciphertext ‖ tag [16]
//! ```
//!
//! sealed with XChaCha20-Poly1305 over this additional data:
//!
//! ```text
//! "dioptron/v1" ‖ schema_version u32 LE ‖ record_kind u8 ‖ key_id u32 LE
//!   ‖ len u16 LE ‖ keyspace name ‖ len u16 LE ‖ record key
//! ```
//!
//! The protocol label names record version 1; a later record version uses a
//! new label, so the header's `rec_ver` is bound through the label it
//! selects. The two variable-length fields carry length prefixes so the
//! encoding is injective: without them, keyspace `"ab"` with record key
//! `"c"` and keyspace `"a"` with record key `"bc"` would produce the same
//! bytes, and a value could be replayed at the second location.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use snafu::{OptionExt, ensure};
use zeroize::Zeroizing;

use super::keys::{SealingKey, SubKey};
use super::{Entropy, KeyId, Keyspace, NONCE_LEN, OsEntropy, RecordKind, SchemaVersion, TAG_LEN};
use crate::Result;
use crate::error::{
    AadComponentTooLongSnafu, KeyMaterialSnafu, MalformedSnafu, OpenSnafu, PlaintextTooLargeSnafu,
    UnknownKeyIdSnafu, UnsupportedRecordVersionSnafu,
};

/// Record version written into every sealed header.
pub const SEALED_RECORD_VERSION: u16 = 1;

/// Length of the sealed header: record version, key id, and nonce.
pub const SEALED_HEADER_LEN: usize = 2 + 4 + NONCE_LEN;

/// Shortest well-formed sealed value (empty plaintext).
pub const MIN_SEALED_LEN: usize = SEALED_HEADER_LEN + TAG_LEN;

/// Largest plaintext one sealed value may carry.
///
/// WHY: XChaCha20-Poly1305 itself permits 256 GiB per message. The store
/// holds records and producer envelopes that the contract bounds at a few
/// MiB (4 MiB wire maximum), so a value this large is a caller bug, surfaced
/// as an error instead of a multi-gigabyte allocation.
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;

const AAD_LABEL: &[u8] = b"dioptron/v1";

/// Where a sealed value lives. Every field is bound into the additional
/// data, so a value opens only at the exact location it was sealed for.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SealContext<'a> {
    /// Store schema version at the time of sealing.
    pub schema_version: SchemaVersion,
    /// Keyspace the value is stored in.
    pub keyspace: Keyspace,
    /// Kind of record within the keyspace.
    pub kind: RecordKind,
    /// The record's key within the keyspace.
    pub record_key: &'a [u8],
}

impl<'a> SealContext<'a> {
    /// Build a sealing context.
    #[must_use]
    pub const fn new(
        schema_version: SchemaVersion,
        keyspace: Keyspace,
        kind: RecordKind,
        record_key: &'a [u8],
    ) -> Self {
        Self {
            schema_version,
            keyspace,
            kind,
            record_key,
        }
    }

    fn aad(&self, key_id: KeyId) -> Result<Vec<u8>> {
        let keyspace = self.keyspace.name().as_bytes();
        let mut aad = Vec::with_capacity(
            AAD_LABEL
                .len()
                .saturating_add(4 + 1 + 4 + 2 + 2)
                .saturating_add(keyspace.len())
                .saturating_add(self.record_key.len()),
        );
        aad.extend_from_slice(AAD_LABEL);
        aad.extend_from_slice(&self.schema_version.get().to_le_bytes());
        aad.push(self.kind.get());
        aad.extend_from_slice(&key_id.get().to_le_bytes());
        push_prefixed(&mut aad, "keyspace name", keyspace)?;
        push_prefixed(&mut aad, "record key", self.record_key)?;
        Ok(aad)
    }
}

fn push_prefixed(out: &mut Vec<u8>, component: &'static str, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len())
        .ok()
        .context(AadComponentTooLongSnafu {
            component,
            len: bytes.len(),
        })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Seal `plaintext` for storage at `ctx` under `key`.
///
/// # Errors
///
/// - [`crate::Error::PlaintextTooLarge`] above [`MAX_PLAINTEXT_LEN`].
/// - [`crate::Error::AadComponentTooLong`] when the record key exceeds 65535 bytes.
/// - [`crate::Error::Entropy`] when the nonce cannot be drawn.
/// - [`crate::Error::KeyMaterial`] if the cipher rejects its input.
pub fn seal(key: &SealingKey, ctx: &SealContext<'_>, plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_with(key, ctx, plaintext, &mut OsEntropy)
}

pub(crate) fn seal_with(
    key: &SealingKey,
    ctx: &SealContext<'_>,
    plaintext: &[u8],
    entropy: &mut impl Entropy,
) -> Result<Vec<u8>> {
    check_plaintext_len(plaintext.len())?;
    let aad = ctx.aad(key.id())?;
    let nonce = random_nonce(entropy)?;
    let ct = encrypt(key.subkey(), &nonce, &aad, plaintext)?;
    let mut out = Vec::with_capacity(SEALED_HEADER_LEN.saturating_add(ct.len()));
    out.extend_from_slice(&SEALED_RECORD_VERSION.to_le_bytes());
    out.extend_from_slice(&key.id().get().to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed value read from `ctx`, choosing the key named in its
/// header from `keys`. Passing both the old and new key during a rotation
/// lets reads succeed under either key id.
///
/// # Errors
///
/// - [`crate::Error::Malformed`] when the value is shorter than [`MIN_SEALED_LEN`].
/// - [`crate::Error::UnsupportedRecordVersion`] for an unknown record version.
/// - [`crate::Error::UnknownKeyId`] when no key in `keys` has the header's id.
/// - [`crate::Error::Open`] when authentication fails: wrong key, a context
///   that differs from the one sealed, or tampered bytes.
/// - [`crate::Error::AadComponentTooLong`] when the record key exceeds 65535 bytes.
pub fn open(
    keys: &[&SealingKey],
    ctx: &SealContext<'_>,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let malformed = || MalformedSnafu {
        what: "sealed value",
        len: sealed.len(),
    };
    ensure!(sealed.len() >= MIN_SEALED_LEN, malformed());
    let (version, rest) = sealed.split_first_chunk::<2>().with_context(malformed)?;
    let (key_id, rest) = rest.split_first_chunk::<4>().with_context(malformed)?;
    let (nonce, ct) = rest
        .split_first_chunk::<NONCE_LEN>()
        .with_context(malformed)?;
    let version = u16::from_le_bytes(*version);
    ensure!(
        version == SEALED_RECORD_VERSION,
        UnsupportedRecordVersionSnafu { found: version }
    );
    let key_id = KeyId::new(u32::from_le_bytes(*key_id));
    let key = keys
        .iter()
        .find(|k| k.id() == key_id)
        .context(UnknownKeyIdSnafu { found: key_id })?;
    let aad = ctx.aad(key_id)?;
    let plain = cipher(key.subkey())?
        .decrypt(xnonce(nonce), Payload { msg: ct, aad: &aad })
        .ok()
        .context(OpenSnafu {
            keyspace: ctx.keyspace.name(),
        })?;
    Ok(Zeroizing::new(plain))
}

fn check_plaintext_len(len: usize) -> Result<()> {
    ensure!(
        len <= MAX_PLAINTEXT_LEN,
        PlaintextTooLargeSnafu {
            len,
            max: MAX_PLAINTEXT_LEN,
        }
    );
    Ok(())
}

/// Build the AEAD for `key`. The cipher copies the key into its own state,
/// which zeroes on drop (the `zeroize` feature of `chacha20poly1305`).
pub(super) fn cipher(key: &SubKey) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key.expose())
        .ok()
        .context(KeyMaterialSnafu {
            purpose: "xchacha20poly1305 key",
        })
}

/// Draw a fresh nonce.
///
/// WHY random: the 192-bit `XChaCha20` nonce makes independently random nonces
/// safe; after 2^48 values under one key, the chance of any repeat is about
/// 2^-97. Random nonces need no counter state, so a crash, a restored backup,
/// or two writers can never replay a nonce the way a persisted counter could.
pub(super) fn random_nonce(entropy: &mut impl Entropy) -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0_u8; NONCE_LEN];
    entropy.fill(&mut nonce)?;
    Ok(nonce)
}

pub(super) fn xnonce(nonce: &[u8; NONCE_LEN]) -> &XNonce {
    nonce.into()
}

/// Encrypt `plaintext` under `key`, returning `ciphertext ‖ tag`.
pub(super) fn encrypt(
    key: &SubKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    cipher(key)?
        .encrypt(
            xnonce(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .ok()
        .context(KeyMaterialSnafu {
            purpose: "xchacha20poly1305 encrypt",
        })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

    use std::io::Write as _;

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::Error;
    use crate::crypto::keys::tests::{store_keys, tenant_key};
    use crate::crypto::test_support::FailingEntropy;

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
        let err = open(&[keys.meta(), impostor.meta()], &ctx(RECORD_KEY), &sealed)
            .expect_err("aad key id");
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
}
