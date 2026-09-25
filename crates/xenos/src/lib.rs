//! Independent client for the Dioptron wire protocol.
//!
//! `xenos` drives process-level acceptance tests against the daemon binary
//! from outside. It links `syntheke` only for message types, protocol
//! constants, and the authentication transcript bytes. Framing (header
//! emit and parse, length bounds), timeouts, and the handshake sequence are
//! written here again from `docs/design/capability-contract.md` § Wire
//! protocol, over a blocking [`std::os::unix::net::UnixStream`], so a defect
//! in the daemon's framing cannot hide behind a shared implementation.
//!
//! - [`Client`] runs the handshake (`ClientHello`, `ServerHello`, `Auth`,
//!   `Admitted`) and then exchanges requests, responses, and cancels.
//! - [`RawConn`] sends arbitrary bytes and reads one checked frame at a
//!   time, for tests that put malformed or out-of-sequence frames on the
//!   wire.
#![deny(missing_docs)]

mod client;
mod error;
mod frame;
#[cfg(test)]
mod peer;
mod raw;

pub use client::{Client, Timeouts, supported_versions};
pub use error::Error;
pub use frame::{Frame, WireMessage, header_bytes, parse_header};
pub use raw::RawConn;
