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
use super::{
    Entropy, KeyId, Keyspace, NONCE_LEN, OsEntropy, RecordKind, SchemaVersion, TAG_LEN,
    random_array,
};
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
/// WHY: XChaCha20-Poly1305 itself permits 256 GiB per message, but one
/// sealed value is encrypted and decrypted as a single in-memory buffer and
/// stored as a single keyspace value, so its size is a per-operation memory
/// bound. The wire frame limit (4 MiB hard maximum) does not bound stored
/// values, because reads are chunked; the transfer budget of a grant does.
/// 64 MiB is a ceiling well above any record and above the envelope sizes
/// Phase 01 acquires; a larger envelope needs chunked blob storage, which
/// must land before any producer may exceed this bound. Until then an
/// oversized value is refused with an error, not a multi-gigabyte allocation.
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

/// The key id in a sealed value's header, or `None` when the value is
/// too short to hold a header. Reads the header only; nothing is
/// authenticated.
pub(crate) fn sealed_key_id(sealed: &[u8]) -> Option<KeyId> {
    let (_version, rest) = sealed.split_first_chunk::<2>()?;
    let (key_id, _) = rest.split_first_chunk::<4>()?;
    Some(KeyId::new(u32::from_le_bytes(*key_id)))
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
    random_array(entropy)
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
mod tests;
