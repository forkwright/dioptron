//! Encryption at rest for the custody store.
//!
//! Implements the "Encryption at rest" section of
//! `docs/design/custody-store.md`:
//!
//! - [`StoreKeys`]: HKDF-SHA256 subkeys (blob, meta, audit, index, kek, check)
//!   from the root key and a per-store salt, gated by a key-check value.
//! - [`TenantDataKey`]: a random per-tenant key, wrapped by the kek subkey
//!   with XChaCha20-Poly1305 and derived into [`TenantKeys`] (blob,
//!   blob-address, meta, audit, index).
//! - [`seal`] and [`open`]: the sealed value format with additional data that
//!   binds each record to its schema version, record kind, key id, keyspace,
//!   and record key.
//! - [`TenantKeys::blob_address`] and [`provenance_digest`]: tenant-keyed blob
//!   addressing and the plain digest that is stored only inside sealed
//!   metadata.
//!
//! Every key type zeroes on drop and prints `[REDACTED]` under `Debug`.

mod keys;
mod seal;
mod wrap;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use snafu::{OptionExt, ResultExt};

use crate::Result;
use crate::error::{EntropySnafu, KeyMaterialSnafu};

pub use keys::{SealingKey, StoreKeys, StoreSalt, SubKey, TenantDataKey, TenantKeys};
pub use seal::{
    MAX_PLAINTEXT_LEN, MIN_SEALED_LEN, SEALED_HEADER_LEN, SEALED_RECORD_VERSION, SealContext, open,
    seal,
};
pub use wrap::{WRAPPED_KEY_LEN, WRAPPED_KEY_VERSION};

/// Length of every symmetric key and subkey in bytes.
pub const KEY_LEN: usize = 32;

/// Length of a tenant id in bytes (a 16-byte ULID).
pub const TENANT_ID_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 24;

/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Identifies which key sealed a value: the root key id for store-level
/// records, a tenant data-key id for tenant records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(u32);

impl KeyId {
    /// Wrap a raw key id.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The raw key id.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The store schema version bound into every sealed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    /// Wrap a raw schema version.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The raw schema version.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The kind of record within a keyspace, bound into every sealed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKind(u8);

impl RecordKind {
    /// Wrap a raw record kind.
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// The raw record kind.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// The store keyspaces named in `docs/design/custody-store.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Keyspace {
    /// Plaintext non-sensitive store metadata.
    Meta,
    /// Wrapped per-tenant data keys.
    Keys,
    /// Tenant records.
    Tenants,
    /// Grant records.
    Grants,
    /// Revocation records.
    Revocations,
    /// Session records.
    Sessions,
    /// Invocation intent and lifecycle state.
    Invocations,
    /// Idempotency index.
    Idem,
    /// Budget ledgers.
    Ledgers,
    /// Artifact side records.
    Artifacts,
    /// Verbatim producer envelopes.
    Blobs,
    /// Per-session artifact index.
    SessionIndex,
    /// Per-tenant sequenced audit records.
    Audit,
    /// Global minimal audit records.
    AuditStub,
    /// In-progress rekey cursors.
    Rekey,
}

impl Keyspace {
    /// The keyspace's on-disk name, bound into additional data.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Keys => "keys",
            Self::Tenants => "tenants",
            Self::Grants => "grants",
            Self::Revocations => "revocations",
            Self::Sessions => "sessions",
            Self::Invocations => "invocations",
            Self::Idem => "idem",
            Self::Ledgers => "ledgers",
            Self::Artifacts => "artifacts",
            Self::Blobs => "blobs",
            Self::SessionIndex => "session_index",
            Self::Audit => "audit",
            Self::AuditStub => "audit_stub",
            Self::Rekey => "rekey",
        }
    }
}

/// A tenant-scoped blob address: HMAC-SHA256 of the plaintext under the
/// tenant's blob-address key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlobAddress([u8; 32]);

impl BlobAddress {
    /// The address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A plain SHA-256 digest of acquired content.
///
/// It identifies plaintext to anyone holding the same bytes, so it is stored
/// only inside sealed metadata and never as a key or address. `Debug`
/// redacts it to keep it out of logs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProvenanceDigest([u8; 32]);

impl ProvenanceDigest {
    /// The digest bytes, for sealing into a metadata record.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ProvenanceDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProvenanceDigest([REDACTED])")
    }
}

/// The key-check value stored in plaintext in `meta`:
/// HMAC-SHA256(check subkey, "dioptron-key-check").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyCheck([u8; 32]);

impl KeyCheck {
    /// The key-check bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// SHA-256 of `plaintext`, for provenance inside sealed metadata only.
#[must_use]
pub fn provenance_digest(plaintext: &[u8]) -> ProvenanceDigest {
    ProvenanceDigest(Sha256::digest(plaintext).into())
}

/// Source of cryptographic randomness. The operating system source is the
/// only production implementation; tests inject a failing source to cover
/// [`crate::Error::Entropy`].
pub(crate) trait Entropy {
    /// Fill `dest` with random bytes.
    fn fill(&mut self, dest: &mut [u8]) -> Result<()>;
}

/// The operating system random source via `getrandom`.
pub(crate) struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest).context(EntropySnafu)
    }
}

/// HMAC-SHA256 over the concatenation of `parts` under `key`.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .ok()
        .context(KeyMaterialSnafu {
            purpose: "hmac-sha256",
        })?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

/// Constant-time check that `tag` is HMAC-SHA256(`key`, `msg`).
///
/// Returns `Ok(false)` on mismatch, including a tag of the wrong length.
fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<bool> {
    let mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .ok()
        .context(KeyMaterialSnafu {
            purpose: "hmac-sha256",
        })?;
    // WHY: `verify_slice` compares with `ctutils::CtEq`, so the comparison
    // time does not depend on how many leading bytes match.
    Ok(mac.chain_update(msg).verify_slice(tag).is_ok())
}

/// HKDF-SHA256 extract step.
fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> Hkdf<Sha256> {
    Hkdf::<Sha256>::new(salt, ikm)
}

/// HKDF-SHA256 expand step into `okm`.
fn hkdf_expand(hk: &Hkdf<Sha256>, info: &[u8], okm: &mut [u8]) -> Result<()> {
    hk.expand(info, okm).ok().context(KeyMaterialSnafu {
        purpose: "hkdf-sha256 expand",
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::Entropy;
    use crate::Result;
    use crate::error::EntropySnafu;
    use snafu::IntoError;

    /// An entropy source that always fails.
    pub(crate) struct FailingEntropy;

    impl Entropy for FailingEntropy {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<()> {
            Err(EntropySnafu.into_error(getrandom::Error::UNSUPPORTED))
        }
    }

    /// Lowercase hex of `bytes`, for asserting key bytes are absent from text.
    pub(crate) fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

    use super::*;
    use crate::Error;

    fn unhex(s: &str) -> Vec<u8> {
        let clean: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
        clean
            .chunks(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).expect("ascii");
                u8::from_str_radix(pair, 16).expect("hex")
            })
            .collect()
    }

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
            !hmac_sha256_verify(&key, b"Hi There", good.get(..31).expect("prefix"))
                .expect("verify"),
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
        let mut a = [0_u8; 32];
        let mut b = [0_u8; 32];
        OsEntropy.fill(&mut a).expect("fill");
        OsEntropy.fill(&mut b).expect("fill");
        assert_ne!(a, b, "two 256-bit draws differ");
    }
}
