//! Identifiers, sequence numbers, timestamps, and idempotency keys.
//!
//! Every identifier is 16 opaque bytes whose text form is a 26-character
//! ULID in Crockford base32. This crate parses and displays identifiers but
//! never generates them: generation needs a clock and randomness, which the
//! daemon owns.

use core::fmt::{self, Write as _};
use core::str::FromStr;

use snafu::{OptionExt as _, ensure};

use crate::error::{
    Error, IdempotencyKeyLengthSnafu, UlidCharacterSnafu, UlidLengthSnafu, UlidOverflowSnafu,
};

/// Length of the ULID text form in characters.
const ULID_LEN: usize = 26;

/// Crockford base32 alphabet, which omits I, L, O, and U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The largest leading digit that keeps a 26-digit value within 128 bits.
const MAX_LEADING_DIGIT: u8 = 7;

/// Writes 16 bytes as an uppercase 26-character ULID.
fn write_ulid(bytes: [u8; 16], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut value = u128::from_be_bytes(bytes);
    let mut out = [0_u8; ULID_LEN];
    for slot in out.iter_mut().rev() {
        let [low, ..] = (value & 0x1f).to_le_bytes();
        // INVARIANT: low < 32 after the mask, so the lookup always hits.
        *slot = ALPHABET.get(usize::from(low)).copied().unwrap_or(b'0');
        value >>= 5;
    }
    out.iter()
        .try_for_each(|&byte| f.write_char(char::from(byte)))
}

/// Parses a 26-character ULID, accepting either letter case.
///
/// WHY strict: the Crockford aliases (I and L for 1, O for 0) are rejected so
/// that each identifier has exactly one accepted spelling per case.
fn parse_ulid(text: &str) -> Result<[u8; 16], Error> {
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() == ULID_LEN,
        UlidLengthSnafu { len: bytes.len() }
    );
    let mut value: u128 = 0;
    for (position, &byte) in bytes.iter().enumerate() {
        let upper = byte.to_ascii_uppercase();
        let digit = ALPHABET
            .iter()
            .position(|&symbol| symbol == upper)
            .and_then(|index| u8::try_from(index).ok())
            .context(UlidCharacterSnafu { position })?;
        ensure!(
            position != 0 || digit <= MAX_LEADING_DIGIT,
            UlidOverflowSnafu
        );
        value = (value << 5) | u128::from(digit);
    }
    Ok(value.to_be_bytes())
}

/// Declares a 16-byte identifier newtype with ULID text form.
macro_rules! ulid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord,
            rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
        )]
        pub struct $name([u8; 16]);

        impl $name {
            /// Wraps 16 raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// The raw 16 bytes.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; 16] {
                self.0
            }
        }

        impl fmt::Display for $name {
            /// Writes the canonical uppercase ULID form.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_ulid(self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "("))?;
                write_ulid(self.0, f)?;
                f.write_char(')')
            }
        }

        impl FromStr for $name {
            type Err = Error;

            /// Parses a 26-character ULID in either letter case.
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                parse_ulid(text).map(Self)
            }
        }
    };
}

ulid_id! {
    /// Identifies a tenant: the operator, an agent, or a sub-agent.
    ///
    /// # Examples
    ///
    /// ```
    /// use syntheke::TenantId;
    ///
    /// let id: TenantId = "01j8k7r3v9zq4n5m6p7s8tnt0b".parse()?;
    /// assert_eq!(id.to_string(), "01J8K7R3V9ZQ4N5M6P7S8TNT0B");
    /// # Ok::<(), syntheke::Error>(())
    /// ```
    TenantId
}

ulid_id! {
    /// Identifies a grant.
    GrantId
}

ulid_id! {
    /// Identifies a session.
    SessionId
}

ulid_id! {
    /// Identifies one capability invocation.
    InvocationId
}

ulid_id! {
    /// Identifies a stored artifact (a capture's side record and envelope).
    ArtifactRef
}

ulid_id! {
    /// Identifies a budget reservation.
    ReservationId
}

/// Position of a record in the audit sequence. Revocation records carry the
/// sequence at which they took effect, which is the revocation epoch.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct AuditSeq(u64);

impl AuditSeq {
    /// Wraps a sequence number.
    #[must_use]
    pub const fn new(seq: u64) -> Self {
        Self(seq)
    }

    /// The sequence number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Wall time as milliseconds since the Unix epoch, UTC.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Wraps milliseconds since the Unix epoch.
    #[must_use]
    pub const fn from_unix_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn unix_millis(self) -> i64 {
        self.0
    }
}

/// A caller-supplied idempotency key of 16 to 64 bytes.
///
/// WHY no bare trust in the derive: a value decoded from the wire bypasses
/// [`IdempotencyKey::new`], so [`crate::decode`] re-runs
/// [`IdempotencyKey::check`] through [`crate::Message::check`] before
/// returning it.
///
/// # Examples
///
/// ```
/// use syntheke::IdempotencyKey;
///
/// let key = IdempotencyKey::from_slice(b"tool-call-000000000001")?;
/// assert_eq!(key.as_bytes(), b"tool-call-000000000001");
/// assert!(IdempotencyKey::from_slice(b"short").is_err());
/// # Ok::<(), syntheke::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct IdempotencyKey(Vec<u8>);

impl IdempotencyKey {
    /// Shortest accepted key, in bytes.
    pub const MIN_LEN: usize = 16;
    /// Longest accepted key, in bytes.
    pub const MAX_LEN: usize = 64;

    /// Wraps `bytes` as a key.
    ///
    /// # Errors
    ///
    /// [`Error::IdempotencyKeyLength`] when `bytes` is shorter than
    /// [`Self::MIN_LEN`] or longer than [`Self::MAX_LEN`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        let key = Self(bytes);
        key.check()?;
        Ok(key)
    }

    /// Copies `bytes` into a key.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        ensure!(
            (Self::MIN_LEN..=Self::MAX_LEN).contains(&bytes.len()),
            IdempotencyKeyLengthSnafu { len: bytes.len() }
        );
        Ok(Self(bytes.to_vec()))
    }

    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Builds a key without the length check, so tests can put an invalid
    /// key on the wire.
    #[cfg(test)]
    pub(crate) fn unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Re-checks the length bound, for values that did not come through a
    /// constructor.
    ///
    /// # Errors
    ///
    /// [`Error::IdempotencyKeyLength`] when the bound does not hold.
    pub fn check(&self) -> Result<(), Error> {
        ensure!(
            (Self::MIN_LEN..=Self::MAX_LEN).contains(&self.0.len()),
            IdempotencyKeyLengthSnafu { len: self.0.len() }
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
