//! The crate error type.

use std::io;
use std::path::PathBuf;

use snafu::Snafu;
use syntheke::{Failure, FrameKind};

/// Errors raised while connecting, framing, handshaking, and exchanging
/// requests with a Dioptron daemon.
///
/// The frame-header variants are this crate's own checks, not syntheke's:
/// the client parses headers itself so that it tests the daemon's framing
/// from outside.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum Error {
    /// The socket path could not be connected.
    #[snafu(display("connecting to {}", path.display()))]
    Connect {
        /// The socket path.
        path: PathBuf,
        /// The connect error.
        source: io::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A socket operation failed for a reason other than a timeout or an
    /// orderly close by the peer.
    #[snafu(display("socket I/O failed"))]
    Io {
        /// The I/O error.
        source: io::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The deadline for the current handshake or frame elapsed.
    #[snafu(display("timed out"))]
    Timeout {
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The peer closed the connection at a frame boundary.
    #[snafu(display("connection closed by peer"))]
    Closed {
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The peer closed the connection partway through a frame.
    #[snafu(display("connection closed after {received} of {expected} bytes"))]
    Truncated {
        /// Bytes the frame part needed.
        expected: usize,
        /// Bytes received before the close.
        received: usize,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Bytes arrived where the connection was expected to be closed.
    #[snafu(display("expected the peer to close, but data arrived"))]
    NotClosed {
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A received frame header did not start with `DPT1`.
    #[snafu(display("frame magic mismatch, got {found:02x?}"))]
    BadMagic {
        /// The four bytes found in place of the magic.
        found: [u8; 4],
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A received frame header named a kind wire version 1 does not define.
    #[snafu(display("unknown frame kind {kind}"))]
    UnknownFrameKind {
        /// The rejected kind byte.
        kind: u8,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A received frame header set flag bits wire version 1 does not define.
    #[snafu(display("unknown frame flag bits {flags:#04x}"))]
    UnknownFlags {
        /// The rejected flags byte.
        flags: u8,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A received frame header's reserved field was not zero.
    #[snafu(display("reserved header field must be zero, got {reserved:#06x}"))]
    NonzeroReserved {
        /// The rejected reserved value.
        reserved: u16,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A frame body, received or about to be sent, exceeds the bound in
    /// force. A received header is refused before any body buffer exists.
    #[snafu(display("frame body of {len} bytes exceeds the {cap}-byte bound"))]
    FrameTooLarge {
        /// Declared or actual body length.
        len: u64,
        /// The bound in force.
        cap: u32,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A message body failed to encode, validate, or pass its contract
    /// check.
    #[snafu(display("message body rejected by the contract codec"))]
    Contract {
        /// The contract crate's error.
        source: syntheke::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A well-formed frame arrived whose kind is not valid at this point of
    /// the protocol.
    #[snafu(display("expected a {expected:?} frame, got {found:?}"))]
    UnexpectedFrame {
        /// The kind the protocol required here.
        expected: FrameKind,
        /// The kind received.
        found: FrameKind,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The server shares no wire version with the client's range.
    #[snafu(display("server supports no wire version in {min}..={max}"))]
    Incompatible {
        /// Lowest version the client offered.
        min: u16,
        /// Highest version the client offered.
        max: u16,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The server chose a version outside the range the client offered.
    #[snafu(display("server chose version {chosen}, outside {min}..={max}"))]
    VersionOutOfRange {
        /// The version the server chose.
        chosen: u16,
        /// Lowest version the client offered.
        min: u16,
        /// Highest version the client offered.
        max: u16,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The server refused authentication. The contract gives one answer for
    /// every cause.
    #[snafu(display("authentication failed"))]
    AuthFailed {
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The server sent a connection-level `Fault` other than `AuthFailed`.
    #[snafu(display("server fault: {failure:?}"))]
    Fault {
        /// The failure the server reported.
        failure: Failure,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The OS random source could not produce a handshake nonce.
    #[snafu(display("OS random source failed"))]
    Random {
        /// The random source's error.
        source: getrandom::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A response answered a different request than the one awaited.
    #[snafu(display("awaited response to request {expected}, got {found}"))]
    UnexpectedResponse {
        /// The awaited request id.
        expected: u64,
        /// The request id the response named.
        found: u64,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// An earlier failure left the connection in an unknown framing state;
    /// the client refuses further use.
    #[snafu(display("connection unusable after an earlier failure"))]
    Broken {
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },
}
