//! The crate error type.

use snafu::Snafu;

use crate::outcome::OutcomeKind;
use crate::vocab::Capability;
use crate::wire::FrameKind;

/// Errors raised while parsing identifiers, checking contract invariants,
/// and encoding or decoding wire frames.
///
/// These are local failures of this crate. The outcome a caller observes on
/// the wire is a [`crate::Failure`]; a daemon maps any decode error here to
/// [`crate::Failure::ProtocolError`].
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum Error {
    /// A ULID text form was not 26 bytes long.
    #[snafu(display("ULID text must be 26 characters, got {len} bytes"))]
    UlidLength {
        /// Byte length of the rejected text.
        len: usize,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A ULID text form held a byte outside the Crockford base32 alphabet.
    #[snafu(display("ULID text has a non-Crockford byte at position {position}"))]
    UlidCharacter {
        /// Byte offset of the first rejected byte.
        position: usize,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A ULID text form encoded a value above 128 bits.
    #[snafu(display("ULID text encodes a value above 128 bits"))]
    UlidOverflow {
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// An idempotency key was outside 16 to 64 bytes.
    #[snafu(display("idempotency key must be 16 to 64 bytes, got {len}"))]
    IdempotencyKeyLength {
        /// Byte length of the rejected key.
        len: usize,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A frame header did not start with the `DPT1` magic.
    #[snafu(display("frame magic mismatch, got {found:02x?}"))]
    BadMagic {
        /// The four bytes found in place of the magic.
        found: [u8; 4],
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A frame header named a kind this wire version does not define.
    #[snafu(display("unknown frame kind {kind}"))]
    UnknownFrameKind {
        /// The rejected kind byte.
        kind: u8,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A frame header set flag bits this wire version does not define.
    #[snafu(display("unknown frame flag bits {flags:#04x}"))]
    UnknownFlags {
        /// The rejected flags byte.
        flags: u8,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A frame header's reserved field was not zero.
    #[snafu(display("reserved header field must be zero, got {reserved:#06x}"))]
    NonzeroReserved {
        /// The rejected reserved value.
        reserved: u16,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A frame body length exceeded the bound in force.
    #[snafu(display("frame body of {len} bytes exceeds the {cap}-byte bound"))]
    FrameTooLarge {
        /// Declared or actual body length.
        len: u64,
        /// The bound in force, already clamped to the hard maximum.
        cap: u32,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A body's length disagreed with the length its header declared.
    #[snafu(display("frame header declares {declared} body bytes, got {actual}"))]
    BodyLengthMismatch {
        /// Length the header declared.
        declared: u32,
        /// Length of the body supplied.
        actual: u64,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A frame's kind was not the kind the caller expected to decode.
    #[snafu(display("expected a {expected:?} frame, got {found:?}"))]
    UnexpectedFrameKind {
        /// Kind of the message type being decoded.
        expected: FrameKind,
        /// Kind named by the frame header.
        found: FrameKind,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A body failed archive validation (corrupt, truncated, or not the
    /// expected type).
    #[snafu(display("frame body failed archive validation"))]
    InvalidArchive {
        /// The validator's error.
        source: rkyv::rancor::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A message could not be serialized.
    #[snafu(display("message serialization failed"))]
    Encode {
        /// The serializer's error.
        source: rkyv::rancor::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A client hello's version range was inverted.
    #[snafu(display("version range {min}..={max} is empty"))]
    InvalidVersionRange {
        /// Lowest version offered.
        min: u16,
        /// Highest version offered.
        max: u16,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A server hello advertised a maximum frame outside the contract bounds.
    #[snafu(display("negotiated maximum frame {max_frame} is outside 4096..=4194304"))]
    MaxFrameOutOfRange {
        /// The advertised maximum body length.
        max_frame: u32,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// An executed state-changing request carried no idempotency key.
    #[snafu(display("an executed {capability} request must carry an idempotency key"))]
    MissingIdempotencyKey {
        /// Capability of the rejected request.
        capability: Capability,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A fault frame carried a failure that is not connection-level.
    #[snafu(display("a fault frame carries only ProtocolError or AuthFailed, got {kind}"))]
    FaultNotConnectionLevel {
        /// Kind of the rejected failure.
        kind: OutcomeKind,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },
}
