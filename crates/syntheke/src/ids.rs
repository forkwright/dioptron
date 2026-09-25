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
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn display_parse_round_trips_boundary_values() -> TestResult {
        for bytes in [[0_u8; 16], [0xff_u8; 16], *b"0123456789abcdef"] {
            let id = SessionId::from_bytes(bytes);
            let parsed: SessionId = id.to_string().parse()?;
            assert_eq!(parsed, id, "display then parse must be the identity");
        }
        Ok(())
    }

    #[test]
    fn display_matches_known_ulid_values() {
        assert_eq!(
            TenantId::from_bytes([0; 16]).to_string(),
            "00000000000000000000000000",
            "all-zero bytes are all-zero digits"
        );
        assert_eq!(
            TenantId::from_bytes([0xff; 16]).to_string(),
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "the 128-bit maximum is the largest ULID"
        );
        assert_eq!(
            GrantId::from_bytes(1_u128.to_be_bytes()).to_string(),
            "00000000000000000000000001",
            "the least significant digit carries the low five bits"
        );
    }

    #[test]
    fn parse_accepts_lowercase_and_uppercase_alike() -> TestResult {
        let lower: ArtifactRef = "01j8k7r3v9zq4n5m6p7s8art0a".parse()?;
        let upper: ArtifactRef = "01J8K7R3V9ZQ4N5M6P7S8ART0A".parse()?;
        assert_eq!(lower, upper, "ULID parsing is case-insensitive");
        assert_eq!(
            lower.to_string(),
            "01J8K7R3V9ZQ4N5M6P7S8ART0A",
            "display is uppercase"
        );
        Ok(())
    }

    #[test]
    fn debug_names_the_type_and_ulid() {
        let id = InvocationId::from_bytes([0; 16]);
        assert_eq!(
            format!("{id:?}"),
            "InvocationId(00000000000000000000000000)",
            "debug output names the type"
        );
    }

    #[test]
    fn parse_rejects_wrong_length() {
        for text in [
            "",
            "0000000000000000000000000",
            "000000000000000000000000000",
        ] {
            let result = text.parse::<ReservationId>();
            assert!(
                matches!(result, Err(Error::UlidLength { len, .. }) if len == text.len()),
                "length {} must be rejected, got {result:?}",
                text.len()
            );
        }
    }

    #[test]
    fn parse_rejects_characters_outside_crockford() {
        for (text, bad) in [
            ("0000000000000000000000000I", 25),
            ("000000000000L0000000000000", 12),
            ("0O000000000000000000000000", 1),
            ("0000000000000000000000000U", 25),
            ("00000000000000000000000-00", 23),
            // 24 digits plus a two-byte character: 26 bytes, bad at byte 24.
            ("000000000000000000000000\u{e9}", 24),
        ] {
            let result = text.parse::<TenantId>();
            assert!(
                matches!(result, Err(Error::UlidCharacter { position, .. }) if position == bad),
                "{text:?} must be rejected at {bad}, got {result:?}"
            );
        }
    }

    #[test]
    fn parse_rejects_values_above_128_bits() {
        let result = "80000000000000000000000000".parse::<TenantId>();
        assert!(
            matches!(result, Err(Error::UlidOverflow { .. })),
            "a leading digit above 7 overflows 128 bits, got {result:?}"
        );
    }

    #[test]
    fn idempotency_key_accepts_bounds_inclusive() -> TestResult {
        for len in [IdempotencyKey::MIN_LEN, 32, IdempotencyKey::MAX_LEN] {
            let key = IdempotencyKey::new(vec![0xa5; len])?;
            assert_eq!(key.as_bytes().len(), len, "key keeps its bytes");
            key.check()?;
        }
        Ok(())
    }

    #[test]
    fn idempotency_key_rejects_out_of_bounds_lengths() {
        for len in [0, IdempotencyKey::MIN_LEN - 1, IdempotencyKey::MAX_LEN + 1] {
            let owned = IdempotencyKey::new(vec![1; len]);
            let borrowed = IdempotencyKey::from_slice(&vec![1; len]);
            for result in [owned, borrowed] {
                assert!(
                    matches!(result, Err(Error::IdempotencyKeyLength { len: got, .. }) if got == len),
                    "length {len} must be rejected, got {result:?}"
                );
            }
        }
    }

    #[test]
    fn scalar_wrappers_round_trip_their_values() {
        assert_eq!(AuditSeq::new(42).get(), 42, "sequence is preserved");
        assert_eq!(
            Timestamp::from_unix_millis(-1).unix_millis(),
            -1,
            "timestamps before the epoch are preserved"
        );
    }
}
