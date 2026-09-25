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
use zeroize::Zeroize;

use crate::Result;
use crate::error::{EntropySnafu, KeyMaterialSnafu};

pub use keys::{SealingKey, StoreKeys, StoreSalt, SubKey, TenantDataKey, TenantKeys};
pub use seal::{
    MAX_PLAINTEXT_LEN, MIN_SEALED_LEN, SEALED_HEADER_LEN, SEALED_RECORD_VERSION, SealContext, open,
    seal,
};
pub use wrap::{WRAPPED_KEY_LEN, WRAPPED_KEY_VERSION};

pub(crate) use seal::seal_with;

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
    /// An address read back from a sealed record.
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

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

// WARNING: accepted residual, stack copies of key material left by the
// RustCrypto primitives (checked against hmac 0.13.0, hkdf 0.13.0, and
// digest 0.11.3 sources). The `zeroize` features enabled in the workspace
// wipe the HMAC and SHA-256 states, the block buffers, the AEAD key, and the
// ChaCha20 state on drop. They do not reach these locals:
// - `hmac::block_api::HmacCore::new_from_slice` builds the zero-padded key
//   block, XORs it with ipad and then opad in place, and returns without
//   wiping it: 64 bytes equal to `key ⊕ opad` stay in a dead stack slot. The
//   key is recoverable from it (opad is a constant). This applies to every
//   HMAC key here: the salt and PRK inside HKDF, the check, index, and
//   blob-address subkeys.
// - `HmacCore::finalize_fixed_core` leaves the inner hash `H(key ⊕ ipad ‖
//   msg)` unwiped; it does not reveal the key.
// - `hkdf::GenericHkdf::expand_multi_info` leaves each output block T(i) in
//   its `output` and `prev` locals; for our 32-byte outputs T(1) is the
//   derived subkey itself.
// - Poly1305's one-time key (r, s) is not wiped: `chacha20poly1305`'s
//   `zeroize` feature does not enable `poly1305/zeroize`. That key is per
//   nonce and reveals nothing about the XChaCha20 key.
// hmac 0.13 has no feature that wipes these, and no safe API reaches them.
// The residue lives only in this process's stack until the frames are
// reused; reading it requires memory access to the daemon, which already
// exposes the live root key. `hkdf_extract` below wipes the one copy that is
// returned to this crate (the PRK). Revisit when hmac wipes its padded key
// block or the store moves key handling into a dedicated process.

/// HKDF-SHA256 extract step.
fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> Hkdf<Sha256> {
    // WHY `extract` over `new`: `Hkdf::new` discards the PRK by value without
    // wiping it; taking it here lets the returned copy be zeroed.
    let (mut prk, hk) = Hkdf::<Sha256>::extract(salt, ikm);
    prk.as_mut_slice().zeroize();
    hk
}

/// HKDF-SHA256 expand step into `okm`.
fn hkdf_expand(hk: &Hkdf<Sha256>, info: &[u8], okm: &mut [u8]) -> Result<()> {
    hk.expand(info, okm).ok().context(KeyMaterialSnafu {
        purpose: "hkdf-sha256 expand",
    })
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
